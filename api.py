#!/usr/bin/env python3
import os
import re
from pathlib import Path

os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")

import chromadb
from chromadb.utils import embedding_functions
from fastapi import FastAPI, HTTPException, Query
from sentence_transformers import CrossEncoder

CHROMA_HOST  = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT  = int(os.getenv("CHROMA_PORT", "8888"))
OUTPUT_DIR   = Path(os.getenv("OUTPUT_DIR", "output")).resolve()
EMBED_MODEL  = "BAAI/bge-large-en-v1.5"
RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
COLLECTIONS  = ["hmas_cve_writeups", "hmas_bugbounty_writeups", "hmas_ctf_writeups"]

# How many candidates to pull from each collection before re-ranking.
# More candidates = higher recall; re-ranker handles precision.
CANDIDATE_MULTIPLIER = 6

CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)

app = FastAPI(title="H-MAS Knowledge API")

_settings = chromadb.Settings(anonymized_telemetry=False)
try:
    _client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT, settings=_settings)
    _client.heartbeat()
except Exception:
    _client = chromadb.PersistentClient(path="./chroma_hmas", settings=_settings)

_embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
_reranker = CrossEncoder(RERANK_MODEL)


def _collect_hits(col, query_text: str, n_candidates: int, where: dict | None) -> list[dict]:
    kwargs = dict(
        query_embeddings=_embed_fn([query_text]),
        n_results=n_candidates,
        include=["documents", "metadatas", "distances"],
    )
    if where:
        kwargs["where"] = where
    try:
        res = col.query(**kwargs)
    except Exception:
        return []

    hits = []
    for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
        category = meta.get("category", "")
        filename = meta.get("file", "")
        hits.append({
            "title":       meta.get("title", ""),
            "source":      meta.get("source", ""),
            "url":         meta.get("url", ""),
            "category":    category,
            "bi_score":    round(1 - dist, 4),   # raw vector score kept for blending
            "chunk_index": meta.get("chunk_index", 0),
            "total_chunks": meta.get("total_chunks", 1),
            "snippet":     doc[:400],
            "file_path":   f"output/{category}/{filename}" if category and filename else None,
            "quality":     meta.get("quality"),
        })
    return hits


@app.get("/query")
def query(q: str = Query(..., description="Search query"), n: int = 5):
    n_candidates = max(n * CANDIDATE_MULTIPLIER, 30)
    cve_ids = [m.upper() for m in CVE_RE.findall(q)]

    all_hits: list[dict] = []

    for col_name in COLLECTIONS:
        try:
            col = _client.get_collection(name=col_name)
        except Exception:
            continue

        # Pass 1 — semantic search over quality-filtered documents
        all_hits += _collect_hits(col, q, n_candidates, where={"quality": {"$gte": 0.6}})

        # Pass 2 — exact CVE ID match inside document text (bypasses quality filter so
        # we don't miss lower-quality writeups that happen to have the exact CVE)
        for cve_id in cve_ids:
            try:
                res = col.query(
                    query_embeddings=_embed_fn([q]),
                    n_results=min(10, n_candidates),
                    include=["documents", "metadatas", "distances"],
                    where_document={"$contains": cve_id},
                )
                for doc, meta, dist in zip(
                    res["documents"][0], res["metadatas"][0], res["distances"][0]
                ):
                    category = meta.get("category", "")
                    filename = meta.get("file", "")
                    all_hits.append({
                        "title":        meta.get("title", ""),
                        "source":       meta.get("source", ""),
                        "url":          meta.get("url", ""),
                        "category":     category,
                        "bi_score":     round(1 - dist, 4),
                        "chunk_index":  meta.get("chunk_index", 0),
                        "total_chunks": meta.get("total_chunks", 1),
                        "snippet":      doc[:400],
                        "file_path":    f"output/{category}/{filename}" if category and filename else None,
                        "quality":      meta.get("quality"),
                        "_exact_cve":   True,   # will get a score boost below
                    })
            except Exception:
                pass

    # Deduplicate by file_path, keeping the entry with the best bi_score
    seen: dict[str, dict] = {}
    for h in all_hits:
        key = h["file_path"] or h["title"]
        if key not in seen or h["bi_score"] > seen[key]["bi_score"]:
            seen[key] = h
    candidates = list(seen.values())

    if not candidates:
        return {"query": q, "results": []}

    # Cross-encoder re-ranking: score each (query, title + snippet) pair
    pairs = [(q, f"{c['title']}\n{c['snippet']}") for c in candidates]
    ce_scores = _reranker.predict(pairs).tolist()

    # Normalise CE scores to [0, 1] across this candidate set
    ce_min = min(ce_scores)
    ce_max = max(ce_scores)
    ce_range = ce_max - ce_min if ce_max != ce_min else 1.0

    for c, raw_ce in zip(candidates, ce_scores):
        ce_norm = (raw_ce - ce_min) / ce_range
        # Blend: 65% cross-encoder (precision), 35% bi-encoder (recall coverage)
        score = 0.65 * ce_norm + 0.35 * c["bi_score"]
        # Exact CVE match in document text → bonus
        if c.pop("_exact_cve", False):
            score = min(score + 0.15, 1.0)
        c["score"] = round(score, 4)

    candidates.sort(key=lambda x: x["score"], reverse=True)
    top = candidates[:n]

    # Clean internal fields before returning
    for c in top:
        c.pop("bi_score", None)

    return {"query": q, "results": top}


@app.get("/file")
def read_file(path: str = Query(..., description="Relative path from /query, e.g. output/cve/foo.txt")):
    target = (Path(".") / path).resolve()
    if not str(target).startswith(str(OUTPUT_DIR)):
        raise HTTPException(status_code=403, detail="Access denied")
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return {"path": path, "content": target.read_text(encoding="utf-8", errors="ignore")}
