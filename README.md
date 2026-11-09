# H-MAS Writeup Scraper

Collects CVE writeups, bug bounty reports, and CTF writeups into clean TXT
files for vectorization into ChromaDB (H-MAS dual-memory system).

## Setup

```bash
pip install trafilatura requests rich feedparser markdownify chromadb sentence-transformers
```

## Quick Start

```bash
# 1. Scrape everything (starts with free sources, no keys needed)
python scraper.py

# 2. Scrape only CVEs (good starting point for H-MAS)
python scraper.py --only cve

# 3. Higher quality gate
python scraper.py --min-stars 50 --min-cvss 8.0

# 4. With API keys (higher rate limits)
export GITHUB_TOKEN=ghp_xxxxx       # 5000 req/hr instead of 60
export NVD_API_KEY=xxxxx            # 50 req/30s instead of 5
python scraper.py

# 5. Ingest into ChromaDB
python ingest.py

# 6. Ingest + test a query
python ingest.py --query-example
```

## Sources

| Source | Category | Free? | Quality Gate |
|--------|----------|-------|--------------|
| CTFtime.org API | CTF | ✅ | Event weight |
| GitHub (ctf-writeup repos) | CTF | ✅ (token recommended) | ⭐ Stars |
| HackerOne Hacktivity | Bug Bounty | ✅ | Severity |
| pentester.land | Bug Bounty | ✅ | Curated |
| Medium infosec-writeups | All | ✅ | RSS |
| NVD NIST API | CVE | ✅ (key recommended) | CVSS ≥ 7.0 |
| exploit-db (git clone) | CVE | ✅ | All verified |
| Vulhub (Docker PoCs) | CVE | ✅ | All reproducible |

## Output Structure

```
output/
  cve/
    cve-2021-41773-a1b2c3d4.txt       # CVE-2021-41773 (Apache RCE)
    log4shell-rce-exploit-...txt
  bugbounty/
    ssrf-in-metadata-endpoint-...txt
    stored-xss-via-file-upload-...txt
  ctf/
    picoctf-web-exploitation-...txt
```

Each file:
```
======================================================================
TITLE:    CVE-2021-41773
SOURCE:   vulhub.org
URL:      https://github.com/vulhub/vulhub/tree/master/apache/CVE-2021-41773
DATE:     2024-01-15
CATEGORY: cve
QUALITY:  0.95
CVE_ID:   CVE-2021-41773
TAGS:     vulhub, cve, apache, reproducible-poc
======================================================================

[clean article text here]
```

## ChromaDB Integration

The ingestor creates three collections matching H-MAS conventions:
- `hmas_cve_writeups`
- `hmas_bugbounty_writeups`
- `hmas_ctf_writeups`

Query from H-MAS:
```python
results = collection.query(
    query_texts=["Apache path traversal exploitation"],
    n_results=5,
    where={"quality": {"$gte": 0.7}},  # Quality gate at retrieval
)
```

## Tips

- Start with `--only cve` — most directly useful for H-MAS pentest agent
- exploit-db + Vulhub are the highest signal sources for your use case
- HackerOne reports are the richest bug bounty content (verified, real CVEs)
- Set GITHUB_TOKEN or you'll hit the 60 req/hr anonymous rate limit fast
- NVD API key is free at nvd.nist.gov/developers/request-an-api-key
- Run scraper on your VPS (same machine as H-MAS) to avoid re-downloading