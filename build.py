#!/usr/bin/env python3
"""Convert Okazakee's default AdGuard list into a safe RouterOS exact-name Adlist.

Only exact names are representable by RouterOS Adlist. Regex and inherited
subdomain matching are NOT representable here; see README.md for limitations.
No third-party Python packages required.
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/Okazakee/tv-dns-blocklist/"
    "main/blocklist.txt"
)
DOMAIN = re.compile(r"(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+\Z")
# Only the documented source syntax is accepted. Unexpected new syntax fails
# rather than being silently interpreted incorrectly.
BLOCK = re.compile(r"\|\|([a-z0-9._-]+)\^")
ALLOW = re.compile(r"@@\|{1,2}([a-z0-9._-]+)\^\$important")


def validate_domain(domain: str) -> str:
    if not DOMAIN.fullmatch(domain) or not re.fullmatch(r"[a-z]{2,63}", domain.rsplit(".", 1)[-1]):
        raise ValueError(f"Unsafe or unsupported domain: {domain!r}")
    return domain


def convert(source: str) -> tuple[str, dict]:
    blocks: set[str] = set()
    protected: set[str] = set()
    skipped_regex = 0
    version = "unknown"

    for number, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("! Version:"):
            version = line.partition(":")[2].strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if match := BLOCK.fullmatch(line):
            blocks.add(validate_domain(match.group(1)))
        elif match := ALLOW.fullmatch(line):
            protected.add(validate_domain(match.group(1)))
        elif line.startswith("/") and line.endswith("/") and len(line) > 2:
            skipped_regex += 1
        elif DOMAIN.fullmatch(line):
            blocks.add(validate_domain(line))
        else:
            raise ValueError(f"Unexpected upstream syntax at line {number}: {line!r}")

    # Fail closed if upstream has unexpectedly changed shape or become empty.
    if not 150 <= len(blocks) <= 2000:
        raise ValueError(f"Unexpected number of block names: {len(blocks)}")
    if not 80 <= len(protected) <= 1000:
        raise ValueError(f"Unexpected number of protected names: {len(protected)}")
    if skipped_regex > 100:
        raise ValueError("Unexpectedly many non-convertible regex rules")

    # A rule with suffix semantics can cover a protected descendant. Because
    # RouterOS cannot express a wildcard with an exception in an Adlist,
    # omit that parent outright instead of risking streaming/update breakage.
    conflicts = sorted(
        d for d in blocks
        if any(p == d or p.endswith("." + d) for p in protected)
    )
    safe = sorted(blocks.difference(conflicts))
    if not safe:
        raise ValueError("Conversion unexpectedly produced no domains")

    header = [
        "# RouterOS Adlist — Okazakee TV telemetry (default/safe tier)",
        f"# Source: {SOURCE_URL}",
        f"# Upstream version: {version}",
        "# Exact hostnames ONLY: RouterOS Adlist has no suffix or regex support.",
        "# Protected names and parent domains of protected names are excluded.",
        "# See README.md before subscribing. Do not use upstream AdGuard file directly.",
        "",
    ]
    feed = "\n".join(header + safe) + "\n"
    report = {
        "upstream": SOURCE_URL,
        "upstream_version": version,
        "input_unique_block_names": len(blocks),
        "upstream_protected_names": len(protected),
        "unsupported_regex_rules": skipped_regex,
        "excluded_parent_or_protected_domains": conflicts,
        "output_exact_names": len(safe),
        "note": "AdGuard suffix/regex matching is not available in RouterOS Adlist; no FWD allow rules are installed.",
    }
    return feed, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", type=Path, help="For offline testing")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args()
    if args.source_file:
        source = args.source_file.read_text(encoding="utf-8")
    else:
        req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "Zeus-RouterOS-TV-list-converter/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            source = response.read(1_000_001).decode("utf-8")
            if len(source) > 1_000_000:
                raise ValueError("Upstream list unexpectedly large")
    feed, report = convert(source)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "tv-telemetry-adlist.txt").write_text(feed, encoding="utf-8", newline="\n")
    (args.output_dir / "build-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
