# Smart TV Telemetry Blocklist for MikroTik RouterOS

An automatically updated DNS blocklist for **MikroTik RouterOS 7**, derived from the **default (non-strict)** [Okazakee TV DNS Blocklist](https://github.com/Okazakee/tv-dns-blocklist).

It aims to reduce smart-TV advertising, Automatic Content Recognition (ACR), analytics and telemetry requests, while avoiding domains the upstream project identifies as necessary for everyday TV functionality.

The upstream project covers Sony BRAVIA, Samsung Tizen, Roku, LG webOS, Hisense VIDAA, Vizio SmartCast, Amazon Fire TV, Philips, Xiaomi and Panasonic. Actual protection depends on the specific TV, firmware and DNS requests it makes.

## Subscribe from RouterOS

The feed is published at:

```text
https://raw.githubusercontent.com/aphos-newtn/tv-telemetry-zeus/main/tv-telemetry-adlist.txt
```

Add it to an existing RouterOS DNS Adlist configuration:

```routeros
/ip dns adlist add url="https://raw.githubusercontent.com/aphos-newtn/tv-telemetry-zeus/main/tv-telemetry-adlist.txt" ssl-verify=yes
/ip dns adlist print detail
```

Check that the new entry has a nonzero `name-count`. The feed can coexist with other Adlists; duplicate names do not need to be removed manually. Clients must use the router's DNS resolver for the list to take effect. **The repository and generated feed must be publicly accessible** for unauthenticated RouterOS downloads.

RouterOS checks subscribed Adlist URLs periodically (approximately every four hours). To request a refresh immediately:

```routeros
/ip dns adlist reload
```

To disable only this feed:

```routeros
/ip dns adlist disable [find where url="https://raw.githubusercontent.com/aphos-newtn/tv-telemetry-zeus/main/tv-telemetry-adlist.txt"]
```

## What this conversion can—and cannot—do

**This feed is an exact-hostname subset of the original list, not an equivalent translation of its AdGuard rules.**

- AdGuard rules such as `||samba.tv^` match the named domain *and its subdomains*. The converted RouterOS feed contains `samba.tv` as an exact hostname; it does **not** automatically block `api.samba.tv`.
- Upstream regular-expression rules cannot be represented in a standard RouterOS DNS Adlist and are omitted.
- The converter excludes upstream protected hostnames, and removes any blocked parent domain when a protected hostname sits beneath it. This prioritises avoiding known functionality conflicts over maximum coverage.
- The upstream project's explicit allow rules are **not** installed as RouterOS exceptions. Other DNS Adlists may still block a required service.

Consequently, the feed is intended as a conservative supplement to existing DNS filtering. It cannot guarantee that a TV's telemetry is blocked or that every feature will continue working. DNS blocking also cannot prevent connections to hardcoded IP addresses or to independent encrypted DNS resolvers (such as DNS-over-HTTPS).

For full AdGuard-style suffix, regex and exception semantics, use a DNS filtering engine that implements those rules, rather than this converted RouterOS feed.

## Automatic updates

GitHub Actions runs the [update workflow](.github/workflows/update.yml) daily at **05:17 UTC** and supports manual runs through **Actions → Update Zeus TV telemetry feed → Run workflow**.

Each run:

1. Tests the converter.
2. Downloads the current upstream *default* `blocklist.txt`.
3. Validates the input, rejects unexpected syntax or abnormal list sizes, and builds the RouterOS feed.
4. Writes `tv-telemetry-adlist.txt` and `build-report.json`.
5. Commits the generated files only when their content changes.

A failed download or validation causes the workflow to fail without committing a replacement feed, so the last published version remains available. The report records the upstream version and the numbers of converted, protected, skipped and excluded entries. GitHub may suspend scheduled workflows in inactive repositories; check the Actions tab if updates stop.

## Run or test locally

Requires Python 3; no third-party Python packages are needed.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py
```

The build creates or updates `tv-telemetry-adlist.txt` and `build-report.json` in the current working directory. It may also be run against a local input file:

```bash
python3 scripts/build.py --source-file blocklist.txt --output-dir .
```

## Troubleshooting

Check the Adlist state and DNS log on RouterOS:

```routeros
/ip dns adlist print detail
/log print where topics~"dns"
```

From a client using the router for DNS, test a hostname contained in the generated feed (replace the placeholder with your router's DNS IP):

```bash
dig @ROUTER_DNS_IP samsungacr.com A +short
```

A blocked A-record query normally returns `0.0.0.0`. This verifies only that particular DNS name is blocked through that resolver; it does not prove all TV telemetry is blocked. If a TV feature stops working, disable this feed temporarily to isolate it from other subscribed lists and report the specific hostname or feature affected.

## Upstream project and attribution

The filtering rules and research basis originate from [Okazakee/tv-dns-blocklist](https://github.com/Okazakee/tv-dns-blocklist), which is licensed under the MIT License. This repository provides a separate compatibility conversion for MikroTik RouterOS; it is not an official upstream distribution and does not claim equivalent filtering behaviour.

For rule details, verification notes and upstream changes, consult the [upstream README](https://github.com/Okazakee/tv-dns-blocklist#readme), [sources](https://github.com/Okazakee/tv-dns-blocklist/blob/main/SOURCES.md) and [changelog](https://github.com/Okazakee/tv-dns-blocklist/blob/main/CHANGELOG.md).
