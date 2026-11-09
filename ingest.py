#!/usr/bin/env python3
"""
H-MAS Knowledge Ingestor
Reads scraped TXT files → chunks → embeds → stores in ChromaDB

Uses the same ChromaDB instance your H-MAS dual-memory system uses.
Collection names match H-MAS conventions:
  - hmas_cve_writeups
  - hmas_bugbounty_writeups
  - hmas_ctf_writeups

Usage:
  pip install chromadb sentence-transformers
  python ingest.py                        # ingest all
  python ingest.py --only cve             # ingest one category
  python ingest.py --chunk-size 800       # tune chunk size
  python ingest.py --collection hmas_kb   # single merged collection
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

# Must be set before chromadb is imported to suppress PostHog telemetry errors
os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

console = Console()

COLLECTION_MAP = {
    "cve": "hmas_cve_writeups",
    "bugbounty": "hmas_bugbounty_writeups",
    "ctf": "hmas_ctf_writeups",
}


def parse_header(text: str) -> tuple[dict, str]:
    """Split metadata header from document content."""
    lines = text.split("\n")
    meta = {}
    content_start = 0

    for i, line in enumerate(lines):
        if line.startswith("====="):
            if i > 0:
                content_start = i + 1
            continue
        if ":" in line and i < 20:
            key, _, value = line.partition(":")
            meta[key.strip().lower()] = value.strip()
        if line == "" and i > 5:
            content_start = i + 1
            break

    content = "\n".join(lines[content_start:]).strip()
    return meta, content


def chunk_text(text: str, chunk_size: int = 800, overlap: int = 100) -> list[str]:
    """Split text into overlapping chunks for better RAG retrieval."""
    if len(text) <= chunk_size:
        return [text]

    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        # Try to break at a paragraph boundary
        if end < len(text):
            break_at = text.rfind("\n\n", start, end)
            if break_at > start + chunk_size // 2:
                end = break_at
        chunks.append(text[start:end].strip())
        start = end - overlap

    return [c for c in chunks if len(c) > 100]


def ingest(
    output_dir: Path = Path("output"),
    chunk_size: int = 800,
    only: str | None = None,
    single_collection: str | None = None,
    chroma_host: str = "localhost",
    chroma_port: int = 8888,
    model_name: str = "BAAI/bge-large-en-v1.5",
):
    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except ImportError:
        print("Install: pip install chromadb sentence-transformers")
        sys.exit(1)

    settings = chromadb.Settings(anonymized_telemetry=False)

    # Connect to ChromaDB (adjust to your H-MAS config)
    try:
        client = chromadb.HttpClient(host=chroma_host, port=chroma_port, settings=settings)
        client.heartbeat()
        console.print(f"[green]Connected to ChromaDB at {chroma_host}:{chroma_port}[/green]")
    except Exception:
        console.print("[yellow]ChromaDB not reachable via HTTP, using local persistent client[/yellow]")
        client = chromadb.PersistentClient(path="./chroma_hmas", settings=settings)

    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=model_name
    )

    categories = [only] if only else ["cve", "bugbounty", "ctf"]
    totals: dict[str, dict] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        for cat in categories:
            cat_dir = output_dir / cat
            if not cat_dir.exists():
                console.print(f"[yellow]  No output/{cat}/ directory, skipping[/yellow]")
                continue

            files = list(cat_dir.glob("*.txt"))
            col_name = single_collection or COLLECTION_MAP[cat]
            collection = client.get_or_create_collection(
                name=col_name,
                embedding_function=embed_fn,
            )

            added = 0
            skipped = 0
            task = progress.add_task(f"{cat.upper():10s}", total=len(files))

            for txt_file in files:
                progress.update(task, description=f"{cat.upper():10s} [dim]{txt_file.stem[:35]}[/dim] [green]{added}c[/green]")
                text = txt_file.read_text(encoding="utf-8", errors="ignore")
                meta, content = parse_header(text)

                if not content:
                    skipped += 1
                    progress.advance(task)
                    continue

                chunks = chunk_text(content, chunk_size=chunk_size)

                if len(chunks) > 1500:
                    skipped += 1
                    progress.advance(task)
                    continue

                # Check if this file is already fully ingested by probing chunk 0's ID.
                first_id = hashlib.md5(f"{txt_file.name}_0".encode()).hexdigest()
                if collection.get(ids=[first_id], include=[])["ids"]:
                    skipped += 1
                    progress.advance(task)
                    continue

                # Build all chunks for this file then upsert in one batch
                # so the embedding model processes them together instead of
                # making N serial inference calls.
                ids, documents, metadatas = [], [], []
                base_meta = {
                    "source": meta.get("source", "unknown"),
                    "url": meta.get("url", ""),
                    "category": cat,
                    "title": meta.get("title", txt_file.stem),
                    "date": meta.get("date", ""),
                    "quality": float(meta.get("quality", "0.5") or "0.5"),
                    "total_chunks": len(chunks),
                    "file": txt_file.name,
                }
                for field in ["cve_id", "cvss", "bounty", "tags"]:
                    if meta.get(field):
                        base_meta[field] = meta[field]

                for i, chunk in enumerate(chunks):
                    ids.append(hashlib.md5(f"{txt_file.name}_{i}".encode()).hexdigest())
                    documents.append(chunk)
                    metadatas.append({**base_meta, "chunk_index": i})

                # Pre-compute embeddings in small batches so the progress bar
                # stays live. Passing embeddings= to upsert skips the blocking
                # inline encode call and makes the upsert itself a fast network call.
                embed_batch = 32
                embeddings: list = []
                for b in range(0, len(documents), embed_batch):
                    batch = documents[b: b + embed_batch]
                    progress.update(task, description=(
                        f"{cat.upper():10s} [dim]{txt_file.stem[:28]}[/dim] "
                        f"[yellow]embed {b}/{len(documents)}[/yellow]"
                    ))
                    embeddings.extend(embed_fn(batch))

                progress.update(task, description=(
                    f"{cat.upper():10s} [dim]{txt_file.stem[:28]}[/dim] "
                    f"[cyan]upsert {len(ids)}c[/cyan]"
                ))
                max_batch = 5000
                for b in range(0, len(ids), max_batch):
                    collection.upsert(
                        ids=ids[b: b + max_batch],
                        documents=documents[b: b + max_batch],
                        embeddings=embeddings[b: b + max_batch],
                        metadatas=metadatas[b: b + max_batch],
                    )
                added += len(ids)
                progress.advance(task)

            totals[cat] = {"added": added, "skipped": skipped, "total": collection.count(), "col": col_name}

    # Summary table
    table = Table(title="Ingest Results")
    table.add_column("Category", style="cyan")
    table.add_column("Collection", style="dim")
    table.add_column("Chunks added", style="green", justify="right")
    table.add_column("Files skipped", style="yellow", justify="right")
    table.add_column("Collection total", style="bold", justify="right")
    for cat, s in totals.items():
        table.add_row(cat, s["col"], str(s["added"]), str(s["skipped"]), str(s["total"]))
    console.print(table)


def query_example(chroma_host: str = "localhost", chroma_port: int = 8888):
    """Example: query the knowledge base like H-MAS would."""
    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except ImportError:
        return

    settings = chromadb.Settings(anonymized_telemetry=False)
    try:
        client = chromadb.HttpClient(host=chroma_host, port=chroma_port, settings=settings)
    except Exception:
        client = chromadb.PersistentClient(path="./chroma_hmas", settings=settings)

    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="BAAI/bge-large-en-v1.5"
    )

    collection = client.get_or_create_collection(
        name="hmas_cve_writeups",
        embedding_function=embed_fn,
    )


    # Example query — what H-MAS StealthOrchestrator would ask
    results = collection.query(
        query_texts=["Apache path traversal RCE exploitation steps"],
        n_results=3,
        where={"quality": {"$gte": 0.7}},  # Quality gate at retrieval time
    )

    print("\n--- Example RAG Query ---")
    print("Query: 'Apache path traversal RCE exploitation steps'")
    for i, (doc, meta) in enumerate(zip(results["documents"][0], results["metadatas"][0])):
        print(f"\n[{i+1}] {meta.get('title')} ({meta.get('source')})")
        print(f"     CVE: {meta.get('cve_id', 'N/A')} | Quality: {meta.get('quality', 'N/A')}")
        print(f"     {doc[:300]}...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-MAS Knowledge Ingestor")
    parser.add_argument("--output-dir", default="output", help="Scraped TXT directory")
    parser.add_argument("--chunk-size", type=int, default=800)
    parser.add_argument("--only", choices=["cve", "bugbounty", "ctf"])
    parser.add_argument("--collection", help="Single collection name instead of per-category")
    parser.add_argument("--chroma-host", default="localhost")
    parser.add_argument("--chroma-port", type=int, default=8888)
    parser.add_argument(
        "--model", default="BAAI/bge-large-en-v1.5",
        help="Sentence-transformers model name (default: BAAI/bge-large-en-v1.5). "
             "Use all-MiniLM-L6-v2 for faster but lower-quality embeddings.",
    )
    parser.add_argument("--query-example", action="store_true", help="Run an example query after ingest")
    args = parser.parse_args()
    if args.query_example:
        query_example(args.chroma_host, args.chroma_port)
        exit()
    ingest(
        output_dir=Path(args.output_dir),
        chunk_size=args.chunk_size,
        only=args.only,
        single_collection=args.collection,
        chroma_host=args.chroma_host,
        chroma_port=args.chroma_port,
        model_name=args.model,
    )

    