#!/usr/bin/env python3
"""
H-MAS Writeup Scraper
Collects CVE writeups, bug bounty reports, and CTF writeups
into clean TXT files ready for vectorization.

Sources:
  - CTFtime.org API      (CTF, quality-scored by event rating)
  - GitHub API           (CTF + bug bounty repos, quality-scored by stars)
  - HackerOne Hacktivity (bug bounty, all verified disclosed)
  - pentester.land       (bug bounty, curated JSON endpoint)
  - NVD NIST API         (CVE descriptions + references)
  - exploit-db git       (CVE POCs, pre-verified)
  - Medium RSS           (infosec-writeups publication)
  - Vulhub               (Docker-reproducible CVE PoCs)

Output: output/{category}/{slug}.txt
Each file has a metadata header followed by clean text.

Usage:
  python scraper.py                    # run all scrapers
  python scraper.py --only ctf
  python scraper.py --only bugbounty
  python scraper.py --only cve
  python scraper.py --min-stars 50
  python scraper.py --limit 500
"""

import argparse
import hashlib
import os
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
import trafilatura
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

console = Console()

# ── Config ────────────────────────────────────────────────────────────────────

OUTPUT_DIR = Path("output")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

RATE_LIMITS = {
    "ctftime.org": 1.5,
    "api.github.com": 0.5,
    "hackerone.com": 2.0,
    "pentester.land": 1.0,
    "nvd.nist.gov": 0.6,
    "medium.com": 1.0,
    "default": 1.0,
}

_last_request: dict[str, float] = {}

# Domains known to be dead, paywalled, or that redirect through Google CAPTCHA
SKIP_REF_DOMAINS = [
    # "blogs.adobe.com", "blogs.mcafee.com", "blog.mcafee.com",
    # "community.websense.com", "erpscan.io", "blog.vulnhunt.com",
    # "blog.sat0ri.com", "hi.baidu.com",
    # "blogspot.com",  # redirects through Google CAPTCHA
    # "fireeye.com", "community.rapid7.com",
]

_MEDIUM_HOSTS = {"medium.com", "infosecwriteups.com"}


def _medium_rss_url(url: str) -> str:
    """Return the RSS feed URL for a Medium article URL, or '' if not Medium."""
    parsed = urlparse(url)
    host = parsed.netloc.lower().lstrip("www.")
    path = parsed.path
    if host == "medium.com":
        m = re.match(r'^/@([^/]+)/', path)
        return f"https://medium.com/@{m.group(1)}/feed" if m else ""
    if host.endswith(".medium.com"):
        username = host[: -len(".medium.com")]
        return f"https://{username}.medium.com/feed"
    if host == "infosecwriteups.com":
        return "https://infosecwriteups.com/feed"
    return ""


def fetch_medium_via_rss(url: str) -> str:
    """
    Fetch a Medium article's text via the author/publication RSS feed.
    Avoids the 403 that Medium returns on direct GET requests.
    Matches the article by its slug (last URL path segment).
    """
    try:
        import feedparser
    except ImportError:
        return ""

    rss_url = _medium_rss_url(url)
    if not rss_url:
        return ""

    article_id = urlparse(url).path.rstrip("/").split("/")[-1]
    feed = feedparser.parse(rss_url)

    for entry in feed.entries:
        entry_link = str(entry.get("link") or "")
        if article_id not in entry_link:
            continue
        content_html = ""
        content_list = entry.get("content") or []
        if content_list:
            content_html = str(content_list[0].get("value") or "")
        elif entry.get("summary"):
            content_html = str(entry.get("summary") or "")
        if content_html:
            return html_to_text(content_html, url)

    return ""


def fetch_writeup(url: str) -> str:
    """
    Fetch writeup text from any URL.
    Medium and infosecwriteups.com URLs are fetched via RSS to avoid 403s;
    everything else uses a plain GET + trafilatura.
    """
    host = urlparse(url).netloc.lower().lstrip("www.")
    if host == "medium.com" or host.endswith(".medium.com") or host in _MEDIUM_HOSTS:
        return fetch_medium_via_rss(url)
    r = get(url)
    return html_to_text(r.text, url) if r else ""


def rate_limit(url: str):
    domain = urlparse(url).netloc
    wait = RATE_LIMITS.get(domain, RATE_LIMITS["default"])
    last = _last_request.get(domain, 0)
    elapsed = time.time() - last
    if elapsed < wait:
        time.sleep(wait - elapsed)
    _last_request[domain] = time.time()


def get(url: str, **kwargs) -> requests.Response | None:
    rate_limit(url)
    try:
        r = requests.get(url, headers=HEADERS, timeout=15, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        console.print(f"[dim red]  ✗ {url[:80]}: {e}[/dim red]")
        return None


def post(url: str, **kwargs) -> requests.Response | None:
    """POST with header merging — avoids duplicate keyword argument error."""
    rate_limit(url)
    try:
        extra_headers = kwargs.pop("headers", {})
        merged = {**HEADERS, **extra_headers}
        r = requests.post(url, headers=merged, timeout=20, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        console.print(f"[dim red]  ✗ POST {url[:80]}: {e}[/dim red]")
        return None


# ── Text extraction ────────────────────────────────────────────────────────────

def html_to_text(html: str, url: str = "") -> str:
    text = trafilatura.extract(
        html,
        url=url,
        include_comments=False,
        include_tables=True,
        no_fallback=False,
        favor_recall=True,
    )
    if not text:
        return ""
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def markdown_to_text(md: str) -> str:
    md = re.sub(r'<[^>]+>', '', md)
    md = re.sub(r'^#+\s+', '', md, flags=re.MULTILINE)
    md = re.sub(r'!\[([^\]]*)\]\([^\)]*\)', r'[image: \1]', md)
    md = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', md)
    md = re.sub(r'[*_]{1,3}([^*_]+)[*_]{1,3}', r'\1', md)
    md = re.sub(r'```[^\n]*\n', '\n[CODE]\n', md)
    md = re.sub(r'```', '\n[/CODE]\n', md)
    md = re.sub(r'\n{3,}', '\n\n', md)
    return md.strip()


# ── File output ───────────────────────────────────────────────────────────────

def make_slug(text: str) -> str:
    slug = re.sub(r'[^\w\s-]', '', text.lower())
    slug = re.sub(r'[\s_-]+', '-', slug)
    return slug[:80].strip('-')


def save_doc(category: str, metadata: dict, content: str, min_length: int = 300) -> bool:
    if len(content.strip()) < min_length:
        return False

    category_dir = OUTPUT_DIR / category
    category_dir.mkdir(parents=True, exist_ok=True)

    content_hash = hashlib.md5(content.encode()).hexdigest()[:8]
    slug = make_slug(metadata.get("title", "untitled"))
    filename = f"{slug}-{content_hash}.txt"
    filepath = category_dir / filename

    if filepath.exists():
        return False

    header_lines = [
        "=" * 70,
        f"TITLE:    {metadata.get('title', 'Unknown')}",
        f"SOURCE:   {metadata.get('source', 'Unknown')}",
        f"URL:      {metadata.get('url', '')}",
        f"DATE:     {metadata.get('date', 'Unknown')}",
        f"CATEGORY: {category}",
    ]
    if metadata.get("quality_score") is not None:
        header_lines.append(f"QUALITY:  {metadata['quality_score']:.2f}")
    if metadata.get("tags"):
        header_lines.append(f"TAGS:     {', '.join(t for t in metadata['tags'] if t)}")
    if metadata.get("cve_id"):
        header_lines.append(f"CVE_ID:   {metadata['cve_id']}")
    if metadata.get("cvss"):
        header_lines.append(f"CVSS:     {metadata['cvss']}")
    if metadata.get("bounty"):
        header_lines.append(f"BOUNTY:   {metadata['bounty']}")
    header_lines.append("=" * 70)

    filepath.write_text("\n".join(header_lines) + "\n\n" + content, encoding="utf-8")
    return True


# ── Stats ─────────────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.saved = {"ctf": 0, "bugbounty": 0, "cve": 0}
        self.skipped = 0

    def add(self, category: str, saved: bool):
        if saved:
            self.saved[category] = self.saved.get(category, 0) + 1
        else:
            self.skipped += 1

    def show(self):
        table = Table(title="H-MAS Scraper Results")
        table.add_column("Category", style="cyan")
        table.add_column("Saved", style="green", justify="right")
        for cat, count in self.saved.items():
            table.add_row(cat, str(count))
        table.add_row("Skipped/Short", str(self.skipped), style="dim")
        console.print(table)


stats = Stats()


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 1: CTFtime.org
# ══════════════════════════════════════════════════════════════════════════════

def scrape_ctftime(limit: int = 500, min_rating: float = 0.0):
    console.print("\n[bold cyan]━━ CTFtime.org[/bold cyan]")
    saved = 0

    now = int(time.time())
    three_years_ago = now - (3 * 365 * 24 * 3600)

    writeup_urls = []
    for start in [three_years_ago, three_years_ago + 365*24*3600, now - 365*24*3600]:
        end = start + 365 * 24 * 3600
        r = get(f"https://ctftime.org/api/v1/events/?limit=100&start={start}&finish={end}")
        if not r:
            continue
        for event in r.json():
            event_weight = event.get("weight", 0)
            if event_weight < min_rating:
                continue
            event_id = event.get("id")
            event_title = event.get("title", "CTF")
            event_date = event.get("start", "")[:10]
            wr = get(f"https://ctftime.org/api/v1/events/{event_id}/")
            if not wr:
                continue
            for writeup_link in wr.json().get("public_votable_writeup_list", []):
                url = writeup_link.get("url")
                if url:
                    writeup_urls.append({
                        "url": url, "event": event_title,
                        "date": event_date, "weight": event_weight,
                    })

    console.print(f"  Found [green]{len(writeup_urls)}[/green] writeup links")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Scraping CTF writeups...", total=min(len(writeup_urls), limit))
        for item in writeup_urls[:limit]:
            progress.advance(task)
            r = get(item["url"])
            if not r:
                continue
            text = html_to_text(r.text, item["url"])
            if not text:
                continue
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', r.text, re.I)
            title = title_match.group(1).strip() if title_match else item["event"]
            quality = min(item["weight"] / 100.0, 1.0)
            ok = save_doc("ctf", {
                "title": title, "source": "ctftime.org",
                "url": item["url"], "date": item["date"],
                "quality_score": quality, "tags": ["ctf", item["event"].lower()],
            }, text)
            stats.add("ctf", ok)
            if ok:
                saved += 1

    console.print(f"  [green]Saved {saved} CTF writeups[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 2: GitHub
# ══════════════════════════════════════════════════════════════════════════════

def scrape_github(token: str | None, min_stars: int = 10, limit: int = 500):
    console.print("\n[bold cyan]━━ GitHub[/bold cyan]")

    gh_headers = dict(HEADERS)
    if token:
        gh_headers["Authorization"] = f"token {token}"

    searches = [
        ("ctf", "ctf writeup"),
        ("ctf", "ctf-writeups language:markdown"),
        ("bugbounty", "bug bounty writeup"),
        ("bugbounty", "bug-bounty-writeups hackerone"),
        ("cve", "CVE exploit writeup"),
    ]

    all_repos = []
    for cat, query in searches:
        r = requests.get(
            "https://api.github.com/search/repositories",
            headers=gh_headers,
            params={"q": query, "sort": "stars", "order": "desc", "per_page": 50},
            timeout=15,
        )
        if r.status_code == 403:
            console.print("  [yellow]GitHub rate limit. Set GITHUB_TOKEN for 5000 req/hr[/yellow]")
            break
        if r.status_code != 200:
            continue
        for repo in r.json().get("items", []):
            if repo.get("stargazers_count", 0) >= min_stars:
                all_repos.append((cat, repo))
        time.sleep(0.5)

    seen_repos = set()
    unique_repos = []
    for cat, repo in all_repos:
        if repo["full_name"] not in seen_repos:
            seen_repos.add(repo["full_name"])
            unique_repos.append((cat, repo))

    console.print(f"  Found [green]{len(unique_repos)}[/green] repos (≥{min_stars} stars)")

    saved = 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Extracting GitHub writeups...", total=min(len(unique_repos), 100))
        for cat, repo in unique_repos[:100]:
            progress.advance(task)
            quality = min(repo["stargazers_count"] / 1000.0, 1.0)

            r = requests.get(
                f"https://api.github.com/repos/{repo['full_name']}/git/trees/HEAD",
                headers=gh_headers,
                params={"recursive": "1"},
                timeout=15,
            )
            time.sleep(0.5)
            if r.status_code != 200:
                continue

            md_files = [
                f for f in r.json().get("tree", [])
                if f.get("type") == "blob"
                and f.get("path", "").lower().endswith((".md", ".txt"))
                and f.get("size", 0) > 500
                and "readme" not in f.get("path", "").lower()
            ]

            for file_info in md_files[:20]:
                raw_url = f"https://raw.githubusercontent.com/{repo['full_name']}/HEAD/{file_info['path']}"
                r2 = get(raw_url)
                if not r2:
                    continue
                content = markdown_to_text(r2.text)
                if len(content) < 300:
                    continue
                title = Path(file_info["path"]).stem.replace("-", " ").replace("_", " ")
                ok = save_doc(cat, {
                    "title": f"{repo['name']} - {title}",
                    "source": "github.com",
                    "url": f"https://github.com/{repo['full_name']}/blob/HEAD/{file_info['path']}",
                    "date": repo.get("updated_at", "")[:10],
                    "quality_score": quality,
                    "tags": [cat, repo["full_name"]],
                }, content)
                stats.add(cat, ok)
                if ok:
                    saved += 1
                if saved >= limit:
                    break
            if saved >= limit:
                break

    console.print(f"  [green]Saved {saved} GitHub writeups[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 3: HackerOne (offline sources)
# ══════════════════════════════════════════════════════════════════════════════

_H1_SEV_SCORES = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}


def _scrape_h1_huggingface(limit: int) -> int:
    """
    HuggingFace dataset: Hacker0x01/hackerone_disclosed_reports
    Columns used: id, title, created_at, disclosed_at, substate,
                  vulnerability_information, reporter{username}, team{handle},
                  weakness{name}, structured_scope{severity}, vote_count, has_bounty?
    """
    console.print("  [dim]Source 1: HuggingFace (Hacker0x01/hackerone_disclosed_reports)[/dim]")
    try:
        from datasets import load_dataset
    except ImportError:
        console.print("  [yellow]datasets not installed — run: pip install datasets[/yellow]")
        return 0

    try:
        ds = load_dataset("Hacker0x01/hackerone_disclosed_reports", split="train")
    except Exception as e:
        console.print(f"  [red]Failed to load HuggingFace dataset: {e}[/red]")
        return 0

    console.print(f"  [dim]Dataset loaded: {len(ds)} rows[/dim]")
    saved = 0

    # Pre-compute max vote_count for quality normalisation fallback
    try:
        max_votes = max((r.get("vote_count") or 0) for r in ds) or 1
    except Exception:
        max_votes = 1

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Loading HuggingFace H1 dataset...", total=min(len(ds), limit))
        for row in ds:
            if saved >= limit:
                break
            progress.advance(task)

            content = row.get("vulnerability_information") or ""
            if not content or len(content.strip()) < 300:
                stats.add("bugbounty", False)
                continue

            # severity: may be inside structured_scope dict
            severity = ""
            scope = row.get("structured_scope")
            if isinstance(scope, dict):
                severity = str(scope.get("severity") or scope.get("severity_rating") or "")
            if not severity:
                # fall back to weakness name as category tag
                wk = row.get("weakness")
                severity = (wk.get("name") or "") if isinstance(wk, dict) else ""

            team_obj = row.get("team")
            team_handle = (team_obj.get("handle") or team_obj.get("name") or "") if isinstance(team_obj, dict) else str(team_obj or "")

            weakness_obj = row.get("weakness")
            weakness_name = (weakness_obj.get("name") or "") if isinstance(weakness_obj, dict) else ""

            vote_count = row.get("vote_count") or 0
            quality = _H1_SEV_SCORES.get(severity.lower(), min(vote_count / max_votes, 1.0))

            report_id = row.get("id") or ""
            title = row.get("title") or "H1 Report"
            date = str(row.get("disclosed_at") or row.get("created_at") or "")[:10]
            has_bounty = row.get("has_bounty?") or False

            ok = save_doc("bugbounty", {
                "title": title,
                "source": "hackerone.com",
                "url": f"https://hackerone.com/reports/{report_id}",
                "date": date,
                "quality_score": quality,
                "tags": ["bugbounty", "hackerone", severity, weakness_name, team_handle],
                "bounty": "yes" if has_bounty else None,
            }, markdown_to_text(content))
            stats.add("bugbounty", ok)
            if ok:
                saved += 1

    console.print(f"  [dim]HuggingFace source: saved {saved}[/dim]")
    return saved


def _scrape_h1_csv(limit: int) -> int:
    """
    GitHub repo reddelexc/hackerone-reports — fetches data.csv, then
    fetches each `link` URL and extracts text with trafilatura.
    CSV columns: program, title, link, upvotes, bounty, vuln_type
    Quality score = upvotes / max_upvotes.
    """
    import csv as _csv
    import io as _io

    console.print("  [dim]Source 2: reddelexc/hackerone-reports (data.csv)[/dim]")
    csv_url = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"
    r = get(csv_url)
    if not r:
        console.print("  [yellow]Could not fetch reddelexc/hackerone-reports data.csv[/yellow]")
        return 0

    try:
        rows = list(_csv.DictReader(_io.StringIO(r.text)))
    except Exception as e:
        console.print(f"  [red]CSV parse error: {e}[/red]")
        return 0

    if not rows:
        console.print("  [yellow]CSV is empty[/yellow]")
        return 0

    console.print(f"  [dim]{len(rows)} rows loaded[/dim]")

    # Compute max upvotes for quality normalisation
    max_upvotes = 1
    for row in rows:
        try:
            v = int(row.get("upvotes") or 0)
            if v > max_upvotes:
                max_upvotes = v
        except (ValueError, TypeError):
            pass

    saved = 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Fetching H1 CSV reports...", total=min(len(rows), limit * 3))
        for row in rows:
            if saved >= limit:
                break
            progress.advance(task)

            report_url = str(row.get("link") or "").strip()
            if not report_url.startswith("http"):
                continue

            text = fetch_writeup(report_url)
            if not text or len(text) < 300:
                stats.add("bugbounty", False)
                continue

            try:
                upvotes = int(row.get("upvotes") or 0)
            except (ValueError, TypeError):
                upvotes = 0
            quality = min(upvotes / max_upvotes, 1.0)

            bounty = str(row.get("bounty") or "").strip()
            vuln_type = str(row.get("vuln_type") or "").strip()
            program = str(row.get("program") or "").strip()
            title = str(row.get("title") or "H1 Report").strip()

            ok = save_doc("bugbounty", {
                "title": title,
                "source": "hackerone.com",
                "url": report_url,
                "date": datetime.now().strftime("%Y-%m-%d"),
                "quality_score": quality,
                "tags": ["bugbounty", "hackerone", vuln_type, program],
                "bounty": bounty if bounty and bounty != "0" else None,
            }, text)
            stats.add("bugbounty", ok)
            if ok:
                saved += 1

    console.print(f"  [dim]CSV source: saved {saved}[/dim]")
    return saved


def scrape_hackerone(limit: int = 500):
    """
    HackerOne disclosed reports from two offline sources:
      1. HuggingFace dataset Hacker0x01/hackerone_disclosed_reports
      2. reddelexc/hackerone-reports data.csv (fetches each Report Link URL)
    """
    console.print("\n[bold cyan]━━ HackerOne (Offline Sources)[/bold cyan]")

    saved = _scrape_h1_huggingface(limit)

    remaining = limit - saved
    if remaining > 0:
        saved += _scrape_h1_csv(remaining)

    console.print(f"  [green]Saved {saved} HackerOne reports total[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 4: pentester.land (JSON endpoint)
# ══════════════════════════════════════════════════════════════════════════════

def scrape_pentesterland(limit: int = 300):
    """
    Uses pentester.land/writeups.json — the official machine-readable endpoint.
    Fetches each writeup URL for full content.
    """
    console.print("\n[bold cyan]━━ pentester.land[/bold cyan]")

    r = get("https://pentester.land/writeups.json")
    if not r:
        console.print("  [yellow]Could not reach pentester.land/writeups.json[/yellow]")
        return

    try:
        data = r.json()
    except Exception as e:
        console.print(f"  [red]Could not parse writeups.json: {e}[/red]")
        console.print(f"  [dim]Response snippet: {r.text[:300]}[/dim]")
        return

    # Handle both list and dict response shapes
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = (
            data.get("writeups") or data.get("data") or
            data.get("items") or data.get("results") or
            (list(data.values())[0] if data else [])
        )
    else:
        entries = []

    console.print(f"  Found [green]{len(entries)}[/green] entries in writeups.json")

    # Debug: show first entry structure so we know the field names
    if entries:
        import json as _json
        console.print(f"  [dim]First entry sample: {_json.dumps(entries[0], default=str)[:400]}[/dim]")

    saved = 0
    _first_entry_printed = False
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Scraping pentester.land writeups...", total=min(len(entries), limit))

        for entry in entries[:limit]:
            progress.advance(task)

            # Flexible field extraction — covers all known pentester.land JSON shapes
            if isinstance(entry, str):
                url = entry
                title, date, tags = url, "", []
            elif isinstance(entry, dict):
                # Print keys of first entry for diagnosis
                if not _first_entry_printed:
                    console.print(f"  [dim]First entry keys: {list(entry.keys())}[/dim]")
                    _first_entry_printed = True

                # pentester.land structure: Links is a list of {Title, Link} dicts
                url = ""
                title = ""
                links_field = entry.get("Links") or entry.get("links") or []
                if isinstance(links_field, list) and links_field:
                    first_link = links_field[0]
                    if isinstance(first_link, dict):
                        url = str(first_link.get("Link") or first_link.get("link") or first_link.get("url") or "").strip()
                        title = str(first_link.get("Title") or first_link.get("title") or "").strip()

                # Fall back to flat field names if Links didn't yield a URL
                if not url:
                    url = (
                        entry.get("url") or entry.get("link") or entry.get("href") or
                        entry.get("writeup_url") or entry.get("writeup") or
                        entry.get("source") or entry.get("article_url") or
                        entry.get("post_url") or entry.get("reference") or
                        entry.get("URL") or entry.get("Link") or entry.get("Url") or ""
                    )

                if not title:
                    title = (
                        entry.get("title") or entry.get("name") or
                        entry.get("headline") or url
                    )

                date = str(
                    entry.get("PublicationDate") or entry.get("AddedDate") or
                    entry.get("date") or entry.get("published_at") or
                    entry.get("created_at") or entry.get("pubdate") or ""
                )[:10]

                # Bugs → vuln type tags; Programs → program tags
                bugs = entry.get("Bugs") or entry.get("bugs") or []
                programs = entry.get("Programs") or entry.get("programs") or []
                tags = bugs + programs
                if isinstance(tags, str):
                    tags = [tags]
            else:
                continue

            if not url or not url.startswith("http"):
                import json as _json
                console.print(f"  [dim yellow]No URL found — entry: {_json.dumps(entry, default=str)[:300]}[/dim yellow]")
                continue

            text = fetch_writeup(url)
            if not text or len(text) < 400:
                continue

            ok = save_doc("bugbounty", {
                "title": title,
                "source": "pentester.land",
                "url": url,
                "date": date or datetime.now().strftime("%Y-%m-%d"),
                "quality_score": 0.85,
                "tags": ["bugbounty", "curated"] + list(tags)[:5],
            }, text)
            stats.add("bugbounty", ok)
            if ok:
                saved += 1

    console.print(f"  [green]Saved {saved} pentester.land writeups[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 5: NVD NIST
# ══════════════════════════════════════════════════════════════════════════════

def scrape_nvd(api_key: str | None = None, min_cvss: float = 7.0, limit: int = 1000):
    console.print("\n[bold cyan]━━ NVD NIST (CVEs)[/bold cyan]")

    nvd_headers = dict(HEADERS)
    if api_key:
        nvd_headers["apiKey"] = api_key

    saved = 0
    start_index = 0
    results_per_page = 100

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task(f"Fetching NVD CVEs (CVSS≥{min_cvss})...", total=limit)
        while saved < limit:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=nvd_headers,
                params={
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                    "cvssV3Severity": "HIGH" if min_cvss >= 7.0 else "MEDIUM",
                },
                timeout=30,
            )
            time.sleep(0.6)

            if r.status_code != 200:
                console.print(f"  [red]NVD API error: {r.status_code}[/red]")
                break

            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                published = cve.get("published", "")[:10]

                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                if not desc:
                    continue

                metrics = cve.get("metrics", {})
                cvss_score = 0
                for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metric_list = metrics.get(version_key, [])
                    if metric_list:
                        cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0)
                        break

                if cvss_score < min_cvss:
                    continue

                # Fetch references for ALL CVEs — skip known dead/blocked domains only
                references = cve.get("references", [])
                content_parts = [f"CVE ID: {cve_id}", f"CVSS Score: {cvss_score}", "", desc, ""]

                for ref_url in [ref.get("url", "") for ref in references][:5]:
                    domain = urlparse(ref_url).netloc.lstrip("www.")
                    if any(blocked in domain for blocked in SKIP_REF_DOMAINS):
                        continue
                    if any(kw in ref_url for kw in ["exploit-db", "github.com", "writeup", "poc", "advisory", "blog"]):
                        rr = get(ref_url)
                        if rr:
                            ref_text = html_to_text(rr.text, ref_url)
                            if ref_text and len(ref_text) > 200:
                                content_parts.append(f"\n--- Reference: {ref_url} ---\n{ref_text[:3000]}")

                content = "\n".join(content_parts)
                quality = min(cvss_score / 10.0, 1.0)

                ok = save_doc("cve", {
                    "title": cve_id,
                    "source": "nvd.nist.gov",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "date": published,
                    "quality_score": quality,
                    "cve_id": cve_id,
                    "cvss": str(cvss_score),
                    "tags": ["cve", f"cvss-{cvss_score}"],
                }, content)
                stats.add("cve", ok)
                if ok:
                    saved += 1
                    progress.advance(task)
                if saved >= limit:
                    break

            start_index += results_per_page
            if start_index >= data.get("totalResults", 0):
                break

    console.print(f"  [green]Saved {saved} CVE records[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 6: exploit-db (GitLab mirror)
# ══════════════════════════════════════════════════════════════════════════════

def scrape_exploitdb(limit: int = 2000):
    console.print("\n[bold cyan]━━ exploit-db (git mirror)[/bold cyan]")

    repo_dir = Path("/tmp/exploitdb")
    if not repo_dir.exists():
        console.print("  Cloning exploit-db mirror (one time, ~500MB)...")
        ret = os.system(
            "git clone --depth=1 https://gitlab.com/exploit-database/exploitdb /tmp/exploitdb 2>&1 | tail -3"
        )
        if ret != 0:
            console.print("  [yellow]Could not clone exploit-db.[/yellow]")
            return
    else:
        console.print("  [dim]Using cached exploit-db clone[/dim]")

    csv_path = repo_dir / "files_exploits.csv"
    exploits = []
    if csv_path.exists():
        import csv
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            for row in csv.DictReader(f):
                exploits.append(row)

    console.print(f"  Found [green]{len(exploits)}[/green] exploits in index")
    exploits.sort(key=lambda x: x.get("date_published", ""), reverse=True)

    saved = 0
    for exploit in exploits[:limit]:
        file_path = repo_dir / exploit.get("file", "")
        if not file_path.exists():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if len(content) < 200:
            continue
        cve_ids = re.findall(r'CVE-\d{4}-\d+', content, re.I)
        eid = exploit.get("id", "")
        ok = save_doc("cve", {
            "title": exploit.get("description", f"exploit-db-{eid}"),
            "source": "exploit-db.com",
            "url": f"https://www.exploit-db.com/exploits/{eid}",
            "date": exploit.get("date_published", ""),
            "quality_score": 0.9,
            "cve_id": cve_ids[0] if cve_ids else None,
            "tags": ["exploit-db", exploit.get("platform", ""), exploit.get("type", "")],
        }, content)
        stats.add("cve", ok)
        if ok:
            saved += 1

    console.print(f"  [green]Saved {saved} exploit-db entries[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 7: Medium / infosec-writeups RSS
# ══════════════════════════════════════════════════════════════════════════════

def scrape_medium(limit: int = 300):
    console.print("\n[bold cyan]━━ Medium (infosec-writeups)[/bold cyan]")

    try:
        import feedparser
    except ImportError:
        console.print("  [yellow]feedparser not installed, skipping Medium[/yellow]")
        return

    feeds = [
        ("https://infosecwriteups.com/feed", "bugbounty"),
        ("https://medium.com/feed/tag/ctf", "ctf"),
        ("https://medium.com/feed/tag/bug-bounty", "bugbounty"),
        ("https://medium.com/feed/tag/cve", "cve"),
        ("https://medium.com/feed/tag/penetration-testing", "bugbounty"),
    ]

    all_entries = []
    for feed_url, category in feeds:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries:
            all_entries.append((category, entry))

    console.print(f"  Found [green]{len(all_entries)}[/green] Medium articles via RSS")

    saved = 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Scraping Medium articles...", total=min(len(all_entries), limit))
        for category, entry in all_entries[:limit]:
            progress.advance(task)
            url = entry.get("link", "")
            if not url:
                continue
            r = get(url)
            if not r:
                continue
            text = html_to_text(r.text, url)
            if not text or len(text) < 500:
                continue
            published = entry.get("published", datetime.now().isoformat())[:10]
            tags = [t.get("term", "") for t in entry.get("tags", [])]
            ok = save_doc(category, {
                "title": entry.get("title", "Medium Article"),
                "source": "medium.com",
                "url": url,
                "date": published,
                "quality_score": 0.7,
                "tags": [category, "medium"] + tags[:5],
            }, text)
            stats.add(category, ok)
            if ok:
                saved += 1

    console.print(f"  [green]Saved {saved} Medium articles[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER 8: Vulhub (reproducible CVE PoCs)
# ══════════════════════════════════════════════════════════════════════════════

def scrape_vulhub(limit: int = 500):
    console.print("\n[bold cyan]━━ Vulhub (CVE PoCs)[/bold cyan]")

    r = requests.get(
        "https://api.github.com/repos/vulhub/vulhub/git/trees/master",
        headers=HEADERS,
        params={"recursive": "1"},
        timeout=30,
    )
    time.sleep(0.5)
    if r.status_code != 200:
        console.print(f"  [yellow]GitHub API error: {r.status_code}[/yellow]")
        return

    readmes = [
        f for f in r.json().get("tree", [])
        if f.get("path", "").lower().endswith("readme.md")
        and f.get("type") == "blob"
    ]

    console.print(f"  Found [green]{len(readmes)}[/green] Vulhub CVE writeups")

    saved = 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Scraping Vulhub READMEs...", total=min(len(readmes), limit))
        for readme in readmes[:limit]:
            progress.advance(task)
            path = readme["path"]
            parts = path.split("/")
            r2 = get(f"https://raw.githubusercontent.com/vulhub/vulhub/master/{path}")
            if not r2:
                continue
            content = markdown_to_text(r2.text)
            if len(content) < 200:
                continue
            cve_ids = [p for p in parts if p.upper().startswith("CVE-")]
            cve_id = cve_ids[0] if cve_ids else None
            software = parts[0] if parts else "unknown"
            ok = save_doc("cve", {
                "title": f"Vulhub: {cve_id or path}",
                "source": "vulhub.org",
                "url": f"https://github.com/vulhub/vulhub/tree/master/{'/'.join(parts[:-1])}",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "quality_score": 0.95,
                "cve_id": cve_id,
                "tags": ["vulhub", "cve", software, "reproducible-poc"],
            }, content)
            stats.add("cve", ok)
            if ok:
                saved += 1

    console.print(f"  [green]Saved {saved} Vulhub CVE writeups[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="H-MAS Writeup Scraper")
    parser.add_argument("--only", choices=["ctf", "bugbounty", "cve"])
    parser.add_argument("--min-stars", type=int, default=20)
    parser.add_argument("--min-cvss", type=float, default=7.0)
    parser.add_argument("--min-ctf-rating", type=float, default=0.0)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--github-token", type=str, default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--nvd-api-key", type=str, default=os.environ.get("NVD_API_KEY"))
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    console.print("[bold green]H-MAS Writeup Scraper[/bold green]")
    console.print(f"Output: [cyan]{OUTPUT_DIR.absolute()}[/cyan]")
    console.print(f"Min GitHub stars: [cyan]{args.min_stars}[/cyan] | Min CVSS: [cyan]{args.min_cvss}[/cyan]")

    only = args.only

    if not only or only == "ctf":
        scrape_ctftime(limit=args.limit, min_rating=args.min_ctf_rating)
        # scrape_github(token=args.github_token, min_stars=args.min_stars, limit=args.limit)
        scrape_medium(limit=200)

    if not only or only == "bugbounty":
        scrape_hackerone(limit=args.limit)
        scrape_pentesterland(limit=args.limit)
        if only != "ctf":
            scrape_github(token=args.github_token, min_stars=args.min_stars, limit=args.limit)

    if not only or only == "cve":
        scrape_nvd(api_key=args.nvd_api_key, min_cvss=args.min_cvss, limit=args.limit)
        scrape_exploitdb(limit=args.limit * 4)
        scrape_vulhub(limit=args.limit)

    stats.show()

    total = sum(
        len(list((OUTPUT_DIR / cat).glob("*.txt")))
        for cat in ["ctf", "bugbounty", "cve"]
        if (OUTPUT_DIR / cat).exists()
    )
    console.print(f"\n[bold green]Total documents: {total}[/bold green]")
    console.print(f"Ready for vectorization: [cyan]{OUTPUT_DIR.absolute()}[/cyan]")


if __name__ == "__main__":
    main()