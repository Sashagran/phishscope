"""Command line interface for phishscope."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import Report, analyze_file

_VERDICT_COLOR = {"malicious": "\033[1;97;41m", "suspicious": "\033[1;31m", "caution": "\033[33m", "clean": "\033[32m"}
_BAR_COLOR = {"malicious": "\033[31m", "suspicious": "\033[31m", "caution": "\033[33m", "clean": "\033[32m"}
_RESET = "\033[0m"


def _bar(score: int, width: int = 30) -> str:
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def render_text(path: str, r: Report, color: bool) -> str:
    verdict = r.verdict.upper()
    bar = _bar(r.score)
    if color:
        verdict = _VERDICT_COLOR[r.verdict] + f" {verdict} " + _RESET
        bar = _BAR_COLOR[r.verdict] + bar + _RESET
    out = [
        f"── {path}",
        f"   Subject : {r.subject}",
        f"   From    : {r.sender}",
        f"   Auth    : SPF={r.auth['spf']}  DKIM={r.auth['dkim']}  DMARC={r.auth['dmarc']}  ({r.received_hops} Received hops)",
        f"   Score   : {bar} {r.score}/100  {verdict}",
        "",
    ]
    if r.indicators:
        out.append("   Indicators")
        for i in r.indicators:
            out.append(f"     +{i.weight:<3} [{i.category}] {i.title}")
            if i.details:
                out.append(f"          {i.details}")
        out.append("")
    if r.links:
        out.append(f"   Links ({len(r.links)})")
        for l in r.links[:15]:
            out.append(f"     - {l.url}" + (f'   text: "{l.text[:50]}"' if l.text else ""))
        out.append("")
    if r.attachments:
        out.append("   Attachments")
        for a in r.attachments:
            flag = "!!" if a.risky else "  "
            out.append(f"     {flag} {a.filename} ({a.content_type}, {a.size} B) sha256={a.sha256}")
        out.append("")
    return "\n".join(out)


def render_markdown(path: str, r: Report) -> str:
    lines = [
        f"## phishscope report: `{Path(path).name}`",
        "",
        f"**Verdict:** {r.verdict.upper()} — **score {r.score}/100**",
        "",
        "| Field | Value |", "|---|---|",
        f"| Subject | {r.subject} |",
        f"| From | `{r.sender}` |",
        f"| SPF / DKIM / DMARC | {r.auth['spf']} / {r.auth['dkim']} / {r.auth['dmarc']} |",
        "",
        "### Indicators", "",
        "| Weight | Category | Indicator | Details |", "|---:|---|---|---|",
        *[f"| +{i.weight} | {i.category} | {i.title} | {i.details.replace('|', '/')} |" for i in r.indicators],
        "",
        "### IOCs", "",
        *[f"- URL: `{l.url}`" for l in r.links],
        *[f"- SHA-256 `{a.sha256}` ({a.filename})" for a in r.attachments],
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishscope", description="Static phishing analysis for .eml files.")
    ap.add_argument("emails", nargs="+", help=".eml files or directories")
    ap.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    ap.add_argument("--threshold", type=int, default=40, help="exit code 2 if any message scores >= threshold")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    files: list[Path] = []
    for item in args.emails:
        p = Path(item)
        files.extend(sorted(p.glob("*.eml")) if p.is_dir() else [p])

    results = []
    worst = 0
    for f in files:
        r = analyze_file(f)
        worst = max(worst, r.score)
        results.append((str(f), r))

    color = not args.no_color and sys.stdout.isatty()
    if args.format == "json":
        print(json.dumps([{"file": f, **r.to_dict()} for f, r in results], indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print("\n".join(render_markdown(f, r) for f, r in results))
    else:
        print("\n".join(render_text(f, r, color) for f, r in results))

    return 2 if worst >= args.threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
