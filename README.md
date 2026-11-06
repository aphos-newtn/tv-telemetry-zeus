# Zeus TV telemetry feed

This repository automatically converts the **default**, conservative [Okazakee TV DNS Blocklist](https://github.com/Okazakee/tv-dns-blocklist) into a plain-domain Adlist suitable for **MikroTik RouterOS 7.25+**.

## Critical limitation

This is a **safe exact-hostname subset**, not a lossless translation of the AdGuard list. RouterOS `/ip dns adlist` blocks exact DNS names, not the subdomains of each entry. Okazakee rules such as `||samba.tv^` have suffix semantics in AdGuard but become only `samba.tv` here. Regex tracking patterns are not converted. A separate DNS engine with complete AdGuard syntax is needed for equivalent coverage.

The converter skips protected allowlist domains and any blocked parent of an allowed hostname, rather than silently blocking update/DRM/casting services. It **does not** install MikroTik `FWD` exceptions (which would override your other adlists, including StevenBlack and HaGeZi). If another existing list blocks an essential hostname, test and selectively allow that hostname using `/ip dns static add name=HOSTNAME type=FWD` after verifying the requirement.

## Configure a GitHub repository

1. Create a **public** GitHub repository (suggested name: `tv-telemetry-zeus`) with an empty `main` branch, then copy all files from this project into it, including `.github/workflows/update.yml`.
2. Ensure GitHub Actions are enabled. Go to **Settings → Actions → General → Workflow permissions** and allow the workflow to write repository contents if necessary; the workflow itself requests `contents: write`.
3. Open the **Actions** tab, choose **Update Zeus TV telemetry feed**, and select **Run workflow**. Check that `tv-telemetry-adlist.txt` and `build-report.json` have appeared in `main`.
4. On Zeus, subscribe to the actual URL of your published repository:

```routeros
/ip dns adlist add url="https://raw.githubusercontent.com/aphos-newtn/tv-telemetry-zeus/main/tv-telemetry-adlist.txt" ssl-verify=yes
/ip dns adlist print detail
```

**That URL is an example and will not work until the repository exists, is public, and has generated the file.** Modify the owner/repository if you choose another name.

GitHub Actions runs every day at 05:17 UTC and can also be triggered manually. The action fetches the newest upstream list; validates supported syntax and sanity bounds; writes the output and report; commits only if changed. RouterOS automatically checks its URLs about every four hours (or `/ip dns adlist reload` to check immediately).

## Tests and troubleshooting

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py
```

Look at `build-report.json` to see how many entries were converted and excluded. A failure in the upstream fetch or unexpected syntax causes GitHub Actions to fail, keeping the previously published list in place. Check the GitHub Actions run if updates stop. GitHub may disable scheduled workflows on a public repository after extended inactivity; manually re-enable if that happens.

Verify on the router:

```routeros
/ip dns adlist print detail
/log print where topics~"dns"
```

From a client, test `dig @10.0.1.1 samsungacr.com A`; it should return `0.0.0.0` if that exact hostname is included. This does **not** prove subdomain tracking has been blocked, nor does it detect DNS-over-HTTPS bypass by a TV.

For your setup, leave Sony/Samsung/Roku TVs on Primary VLAN 5 for casting. Your existing forced IPv4 DNS and IPv6 DNS port-53 filtering provide a useful baseline; encrypted DNS using HTTPS can bypass this filtering. Never assume that a DNS blocklist alone establishes complete privacy.
