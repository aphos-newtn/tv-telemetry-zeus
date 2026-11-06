# Smart TV Telemetry Blocklist for MikroTik RouterOS

A daily refreshed, **exact-hostname-only** DNS blocklist for MikroTik RouterOS 7 derived from the **default (non-strict)** [Okazakee TV DNS Blocklist](https://github.com/Okazakee/tv-dns-blocklist).

Targets telemetry, analytics, advertising and ACR endpoints for Sony BRAVIA, Samsung, Roku, LG, Hisense, Vizio, Fire TV, Philips, Xiaomi and Panasonic. Coverage depends on the TV and firmware; this is **not** equivalent to the original AdGuard Home list.

## Subscribe on RouterOS

```routeros
/ip dns adlist add url="https://raw.githubusercontent.com/aphos-newtn/tv-telemetry-zeus/main/tv-telemetry-adlist.txt" ssl-verify=yes
/ip dns adlist print detail
```

Confirm the new entry has a nonzero `name-count`. Clients must send their DNS requests to the RouterOS resolver. Adlists do not prevent telemetry to fixed IPs or through separate encrypted DNS services. The repository must be public for unauthenticated RouterOS downloads.

RouterOS checks remote Adlists periodically (approximately every four hours). To request a refresh:

```routeros
/ip dns adlist reload
```

To disable only this subscription:

```routeros
/ip dns adlist disable [find where url="https://raw.githubusercontent.com/aphos-newtn/tv-telemetry-zeus/main/tv-telemetry-adlist.txt"]
```

## Conversion limitations

The original AdGuard rule `||samba.tv^` matches `samba.tv` **and subdomains**. RouterOS Adlist matches only the exact `samba.tv` entry. Subdomains such as `api.samba.tv` remain unblocked unless explicitly present in this or another list. Upstream regular expressions are also omitted.

Protected entries (`@@...$important`) are **not** imported as allowlist rules. The converter excludes explicitly protected names and any incompatible blocked parents; it also excludes specific blocked names beneath an upstream suffix-level exception. This prevents known direct conflicts within this feed, but **other subscribed Adlists may still block essential TV services**. For full suffix/regex/exception behaviour, use AdGuard Home or another compatible DNS filtering engine instead.

## Automated updates and safety checks

GitHub Actions runs [the workflow](.github/workflows/update.yml) every day at **05:17 UTC**, with manual execution under **Actions → Update TV telemetry feed → Run workflow**. It:

1. Runs offline unit tests.
2. Resolves the latest upstream commit affecting `blocklist.txt`, then downloads the file **pinned to that immutable commit**.
3. Validates supported syntax, a dated upstream version, list size and protected rules.
4. Converts supported entries and checks additions/deletions against the previously published feed.
5. Stops automatically if **more than 10% of names were removed** or **more than 25% were added** relative to the previous feed.
6. Records upstream commit SHA, input/output SHA-256 hashes, exact vs suffix-converted counts, skipped regex, protected exceptions and names added/removed in [`build-report.json`](build-report.json).
7. Commits `tv-telemetry-adlist.txt` and `build-report.json` only when the published content or report changes.

A failed download, test or safety check fails the workflow before a commit. The last published feed therefore remains accessible to RouterOS. Watch Actions for failed scheduled runs; upstream format or rule-set changes may require maintenance.

A stable upstream snapshot produces no repository changes. If the feed is unchanged but upstream content changes, the report is updated for auditability.

## Review and override a large upstream change

First inspect Okazakee's upstream diff and the existing published feed. The guard is intentionally conservative; an upstream removal of many obsolete entries can require manual review. After verifying the change, run locally:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py --allow-large-change
```

Review `git diff -- tv-telemetry-adlist.txt build-report.json` before committing. This flag bypasses **only the percentage change guard**, not syntax, version, or input-size validation. It is not used by the automated GitHub Actions workflow.

## Local development

Python 3.10+ is recommended; no third-party Python packages are required.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py
```

For a fully offline conversion, save a copy of upstream `blocklist.txt` locally and run:

```bash
python3 scripts/build.py --source-file blocklist.txt --output-dir .
```

The offline mode records a null upstream commit because no immutable GitHub commit was verified.

## Verification and troubleshooting

```routeros
/ip dns adlist print detail
/log print where topics~"dns"
```

To verify one listed hostname through your router:

```bash
dig @ROUTER_DNS_IP samsungacr.com A +short
```

A blocked A query normally returns `0.0.0.0`. A DNS test proves only the individual name was blocked, not that all TV telemetry has stopped. If a device feature fails, disable this subscription temporarily and check for conflicts with other Adlists before submitting an issue.

## Credits

Rules and research originate with [Okazakee/tv-dns-blocklist](https://github.com/Okazakee/tv-dns-blocklist), licensed under the MIT License. This is a separate compatibility converter, not an official upstream publication. For upstream verification details and exceptions, consult their [README](https://github.com/Okazakee/tv-dns-blocklist), [sources](https://github.com/Okazakee/tv-dns-blocklist/blob/main/SOURCES.md) and [changelog](https://github.com/Okazakee/tv-dns-blocklist/blob/main/CHANGELOG.md).
