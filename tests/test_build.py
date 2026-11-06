"""Offline tests for the RouterOS DNS Adlist converter and publication safeguards."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build import (
    assess_changes, build, convert, feed_names, fetch_upstream,
    get_url, sha256, validate_domain,
)


def fixture(body="", *, blocks=155, allows=85, version="2026.11.01"):
    baseline = "\n".join(f"||tracker-{i}.example.com^" for i in range(blocks))
    permitted = "\n".join(f"@@||safe-{i}.example.com^$important" for i in range(allows))
    return f"! Version: {version}\n{baseline}\n{permitted}\n{body}\n"


class ConvertTests(unittest.TestCase):
    def test_counts_and_version(self):
        feed, report = convert(fixture())
        self.assertEqual(len(feed_names(feed)), 155)
        self.assertEqual(report["input_suffix_rules"], 155)
        self.assertEqual(report["protected_suffix_exceptions"], 85)
        self.assertEqual(report["upstream_version"], "2026.11.01")

    def test_protected_descendant_omits_suffix_parent(self):
        feed, report = convert(fixture("||example.net^\n@@||updates.example.net^$important"))
        self.assertNotIn("example.net", feed_names(feed))
        self.assertEqual(report["excluded_parent_or_protected_domains"], ["example.net"])

    def test_protected_exact_apex_omits_parent(self):
        feed, _ = convert(fixture("||myhomescreen.tv^\n@@|myhomescreen.tv^$important"))
        self.assertNotIn("myhomescreen.tv", feed_names(feed))

    def test_protected_suffix_overrides_specific_block(self):
        feed, report = convert(fixture("||ads.example.net^\n@@||example.net^$important"))
        self.assertNotIn("ads.example.net", feed_names(feed))
        self.assertIn("ads.example.net", report["excluded_parent_or_protected_domains"])

    def test_exact_block_and_protected_descendant_independent(self):
        feed, report = convert(fixture("ads.example.net\n@@||updates.ads.example.net^$important"))
        self.assertIn("ads.example.net", feed_names(feed))
        self.assertNotIn("ads.example.net", report["excluded_parent_or_protected_domains"])

    def test_exact_hostname_and_regex(self):
        feed, report = convert(fixture("||ads.example.org^\nfoo.example.org\n/^tracker\\d+\\.example.org$/"))
        self.assertIn("ads.example.org", feed_names(feed))
        self.assertIn("foo.example.org", feed_names(feed))
        self.assertEqual(report["unsupported_regex_rules"], 1)
        self.assertEqual(report["input_exact_rules"], 1)

    def test_duplicate_entries_deduplicated(self):
        feed, report = convert(fixture("||tracker-0.example.com^\n||tracker-0.example.com^"))
        self.assertEqual(report["input_unique_block_names"], 155)
        self.assertEqual(len(feed_names(feed)), 155)

    def test_unknown_syntax_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unexpected upstream syntax"):
            convert(fixture("||/oops^"))

    def test_injection_rejected(self):
        with self.assertRaises(ValueError):
            validate_domain('abc.com"; /system reset-configuration')

    def test_missing_and_malformed_versions_rejected(self):
        for version in ("", "unknown", "2026-last-night"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                convert(fixture(version=version))

    def test_duplicate_version_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate upstream version"):
            convert(fixture("! Version: 2026.11.02"))

    def test_empty_truncated_list_rejected(self):
        with self.assertRaisesRegex(ValueError, "block names"):
            convert(fixture(blocks=10))

    def test_allowlist_never_becomes_blocklist(self):
        feed, _ = convert(fixture("@@||update.example.net^$important"))
        self.assertNotIn("update.example.net", feed_names(feed))


class ChangeGuardTests(unittest.TestCase):
    @staticmethod
    def make_feed(count, offset=0):
        return "# test\n" + "\n".join(f"tracker-{i}.example.com" for i in range(offset, offset + count)) + "\n"

    def test_small_delta_allowed(self):
        old = self.make_feed(200)
        new = self.make_feed(201)
        diff = assess_changes(old, new)
        self.assertEqual(diff["added_names"], ["tracker-200.example.com"])
        self.assertEqual(diff["removed_names"], [])

    def test_large_removal_rejected(self):
        with self.assertRaisesRegex(ValueError, "removed"):
            assess_changes(self.make_feed(200), self.make_feed(150))

    def test_large_addition_rejected(self):
        with self.assertRaisesRegex(ValueError, "added"):
            assess_changes(self.make_feed(200), self.make_feed(270))

    def test_explicit_override_is_reported(self):
        diff = assess_changes(self.make_feed(200), self.make_feed(150), allow_large_change=True)
        self.assertTrue(diff["change_guard_override"])
        self.assertEqual(len(diff["removed_names"]), 50)

    def test_first_build_does_not_trigger_guard(self):
        diff = assess_changes(None, self.make_feed(155))
        self.assertEqual(diff["previous_exact_names"], 0)

    def test_duplicate_old_feed_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicates"):
            assess_changes("a.com\na.com\n", self.make_feed(155))


class BuildTests(unittest.TestCase):
    def test_initial_build_and_noop_preserves_report(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            first = build(fixture(), path, commit="1" * 40)
            feed_path = path / "tv-telemetry-adlist.txt"
            report_path = path / "build-report.json"
            self.assertEqual(first["output_sha256"], sha256(feed_path.read_bytes()))
            self.assertEqual(first["upstream_commit"], "1" * 40)
            old_report = report_path.read_bytes()
            second = build(fixture(), path, commit="1" * 40)
            self.assertEqual(second, first)
            self.assertEqual(report_path.read_bytes(), old_report)

    def test_failed_guard_does_not_replace_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            build(fixture(), path)
            before = {p.name: p.read_bytes() for p in path.iterdir()}
            with self.assertRaisesRegex(ValueError, "Change guard"):
                build(fixture("\n".join(f"||new-{i}.other.net^" for i in range(60))), path)
            self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})

    def test_invalid_upstream_does_not_replace_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            build(fixture(), path)
            before = {p.name: p.read_bytes() for p in path.iterdir()}
            with self.assertRaises(ValueError):
                build("! Version: 2026.11.01\n||malformed^^", path)
            self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})


class FetchTests(unittest.TestCase):
    def test_immutable_commit_fetch_and_hash(self):
        upstream = fixture().encode()
        commit = "a" * 40
        with patch("build.get_url", side_effect=[json.dumps([{"sha": commit}]).encode(), upstream]) as fetch:
            text, result_commit, digest = fetch_upstream()
        self.assertEqual(text, fixture())
        self.assertEqual(result_commit, commit)
        self.assertEqual(digest, hashlib.sha256(upstream).hexdigest())
        self.assertIn(commit, fetch.call_args_list[1].args[0])

    def test_invalid_commit_rejected_before_raw_download(self):
        with patch("build.get_url", return_value=b'[{"sha": "not-a-sha"}]') as fetch:
            with self.assertRaises(ValueError):
                fetch_upstream()
        self.assertEqual(fetch.call_count, 1)

    def test_unexpected_api_shape_rejected(self):
        with patch("build.get_url", return_value=b'{"message":"rate limit"}'):
            with self.assertRaises(ValueError):
                fetch_upstream()


if __name__ == "__main__":
    unittest.main()
