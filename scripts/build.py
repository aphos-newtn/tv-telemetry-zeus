#!/usr/bin/env python3
"""Publish a conservative RouterOS exact-name subset of Okazakee's TV list.

AdGuard suffix matching, regex and allowlist precedence cannot be reproduced by
RouterOS DNS Adlist. This script never claims that its output is equivalent.
Only Python's standard library is required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.request
from pathlib import Path

REPO = "Okazakee/tv-dns-blocklist"
SOURCE_URL = f"https://raw.githubusercontent.com/{REPO}/main/blocklist.txt"
COMMITS_URL = f"https://api.github.com/repos/{REPO}/commits?path=blocklist.txt&per_page=1"
MAX_SOURCE_BYTES = 1_000_000
MAX_REMOVAL_PERCENT = 10.0
MAX_ADDITION_PERCENT = 25.0

DOMAIN = re.compile(r"(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+\Z")
BLOCK = re.compile(r"\|\|([a-z0-9._-]+)\^")
ALLOW = re.compile(r"@@(\|\|?|)([a-z0-9._-]+)\^\$important")
VERSION = re.compile(r"20\d{2}\.\d{2}\.\d{2}(?:\.\d+)*\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
HEADERS = {"User-Agent": "RouterOS-TV-Telemetry-Converter/2.0", "Accept": "application/vnd.github+json"}


def validate_domain(domain: str) -> str:
    if not DOMAIN.fullmatch(domain) or not re.fullmatch(r"[a-z]{2,63}", domain.rsplit(".", 1)[-1]):
        raise ValueError(f"Unsafe or unsupported domain: {domain!r}")
    return domain


def convert(source: str) -> tuple[str, dict]:
    """Validate all lines and convert only explicit, safe exact hostnames."""
    suffix_blocks: set[str] = set()
    exact_blocks: set[str] = set()
    protected_suffix: set[str] = set()
    protected_exact: set[str] = set()
    regex_rules: list[str] = []
    version: str | None = None

    for number, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("! Version:"):
            if version is not None:
                raise ValueError("Duplicate upstream version headers")
            version = line.partition(":")[2].strip()
        if not line or line.startswith(("!", "#")):
            continue
        if match := BLOCK.fullmatch(line):
            suffix_blocks.add(validate_domain(match.group(1)))
        elif match := ALLOW.fullmatch(line):
            # || indicates a suffix exception; | is an apex-only exception.
            target = protected_suffix if match.group(1) == "||" else protected_exact
            target.add(validate_domain(match.group(2)))
        elif line.startswith("/") and line.endswith("/") and len(line) > 2:
            regex_rules.append(line)
        elif DOMAIN.fullmatch(line):
            exact_blocks.add(validate_domain(line))
        else:
            raise ValueError(f"Unexpected upstream syntax at line {number}: {line!r}")

    if version is None or not VERSION.fullmatch(version):
        raise ValueError(f"Missing or unrecognised upstream version: {version!r}")
    blocks = suffix_blocks | exact_blocks
    protected = protected_suffix | protected_exact
    if not 150 <= len(blocks) <= 2000:
        raise ValueError(f"Unexpected number of block names: {len(blocks)}")
    if not 80 <= len(protected) <= 1000:
        raise ValueError(f"Unexpected number of protected names: {len(protected)}")
    if len(regex_rules) > 100:
        raise ValueError("Unexpected number of unsupported regex rules")

    def conflict(domain: str) -> bool:
        # Direct protection, including protect-the-whole-suffix rules.
        if domain in protected_exact or any(
            domain == p or domain.endswith("." + p) for p in protected_suffix
        ):
            return True
        # Upstream suffix block might otherwise cover a protected descendant.
        # Conservatively drop the parent even though our output is exact-only.
        if domain in suffix_blocks and any(
            p.endswith("." + domain) for p in protected
        ):
            return True
        return False

    conflicts = sorted(d for d in blocks if conflict(d))
    safe = sorted(blocks.difference(conflicts))
    if len(safe) < 100:
        raise ValueError("Conversion produced unexpectedly few safe names")

    feed = "\n".join([
        "# RouterOS Adlist - Okazakee TV telemetry (default tier)",
        f"# Source: {SOURCE_URL}",
        f"# Upstream version: {version}",
        "# Exact hostnames only: suffix / regex / allowlist behaviour is NOT preserved.",
        "# Protected hostnames and conflicting parents are excluded.",
        "", *safe, "",
    ])
    report = {
        "upstream": SOURCE_URL,
        "upstream_version": version,
        "input_unique_block_names": len(blocks),
        "input_suffix_rules": len(suffix_blocks),
        "input_exact_rules": len(exact_blocks),
        "upstream_protected_names": len(protected),
        "protected_suffix_exceptions": len(protected_suffix),
        "protected_exact_exceptions": len(protected_exact),
        "unsupported_regex_rules": len(regex_rules),
        "excluded_parent_or_protected_domains": conflicts,
        "output_exact_names": len(safe),
        "suffix_rules_reduced_to_exact_names": len(suffix_blocks.difference(conflicts)),
        "note": "This is an exact-hostname subset, not full AdGuard matching; regex/suffix coverage and allowlist precedence are absent.",
    }
    return feed, report


def feed_names(text: str) -> set[str]:
    names = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if len(names) != len(set(names)):
        raise ValueError("Existing feed contains duplicates")
    return {validate_domain(name) for name in names}


def assess_changes(old_feed: str | None, new_feed: str,
                   *, allow_large_change: bool = False) -> dict:
    new = feed_names(new_feed)
    previous = feed_names(old_feed) if old_feed is not None else set()
    added = sorted(new - previous)
    removed = sorted(previous - new)
    removed_pct = 100 * len(removed) / len(previous) if previous else 0.0
    added_pct = 100 * len(added) / len(previous) if previous else 0.0
    if previous and not allow_large_change and (
        removed_pct > MAX_REMOVAL_PERCENT or added_pct > MAX_ADDITION_PERCENT
    ):
        raise ValueError(
            f"Change guard rejected new feed: removed {len(removed)}/{len(previous)} "
            f"({removed_pct:.1f}%), added {len(added)} ({added_pct:.1f}%). "
            "Inspect upstream diff, then rerun with --allow-large-change if intentional."
        )
    return {
        "previous_exact_names": len(previous),
        "added_names": added,
        "removed_names": removed,
        "added_percent_of_previous": round(added_pct, 2),
        "removed_percent_of_previous": round(removed_pct, 2),
        "change_guard_override": bool(allow_large_change),
    }


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def get_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("Upstream response exceeded the safety size limit")
    return data


def fetch_upstream() -> tuple[str, str, str]:
    """Resolve a file commit, then fetch by immutable commit URL (avoids race)."""
    commits = json.loads(get_url(COMMITS_URL).decode("utf-8"))
    if not isinstance(commits, list) or not commits or not isinstance(commits[0], dict):
        raise ValueError("Unexpected GitHub commits API response")
    commit = commits[0].get("sha")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError("Invalid upstream commit SHA")
    url = f"https://raw.githubusercontent.com/{REPO}/{commit}/blocklist.txt"
    raw = get_url(url)
    return raw.decode("utf-8"), commit, sha256(raw)


def atomic_write(path: Path, data: str) -> None:
    """Replace a single file only after the entire new content is available."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".tv-feed-",
                                         delete=False) as stream:
            temp_path = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def build(source: str, output_dir: Path, *, commit: str | None = None,
          source_sha: str | None = None, allow_large_change: bool = False) -> dict:
    """Validate before replacing output; keep old report stable on no-op runs."""
    feed, report = convert(source)
    path = output_dir / "tv-telemetry-adlist.txt"
    report_path = output_dir / "build-report.json"
    old = path.read_text(encoding="utf-8") if path.exists() else None
    changes = assess_changes(old, feed, allow_large_change=allow_large_change)
    digest = source_sha or sha256(source.encode("utf-8"))
    report.update(changes)
    report.update({
        "upstream_commit": commit,
        "upstream_content_sha256": digest,
        "output_sha256": sha256(feed.encode("utf-8")),
    })

    # Preserve previous change log on identical upstream snapshots: otherwise
    # a build after a change would generate a second, empty-diff commit.
    if old == feed and report_path.exists():
        saved = json.loads(report_path.read_text(encoding="utf-8"))
        if (saved.get("upstream_content_sha256") == digest and
                saved.get("output_sha256") == report["output_sha256"]):
            return saved

    formatted = json.dumps(report, indent=2, sort_keys=True) + "\n"
    atomic_write(path, feed)
    atomic_write(report_path, formatted)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-file", type=Path, help="Use local input instead of GitHub")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--allow-large-change", action="store_true",
                        help="Override percentage guards after reviewing changes")
    args = parser.parse_args()
    if args.source_file:
        source = args.source_file.read_text(encoding="utf-8")
        commit, digest = None, None
    else:
        source, commit, digest = fetch_upstream()
    result = build(source, args.output_dir, commit=commit, source_sha=digest,
                   allow_large_change=args.allow_large_change)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
