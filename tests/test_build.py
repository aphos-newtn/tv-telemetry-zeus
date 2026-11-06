import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build import convert, validate_domain


def fixture(body: str) -> str:
    # A minimum-size fixture exercises production sanity checks without network.
    base = "\n".join(f"||tracker-{i}.example.com^" for i in range(155))
    allows = "\n".join(f"@@||safe-{i}.example.com^$important" for i in range(85))
    return "! Version: test\n" + base + "\n" + allows + "\n" + body


class ConvertTests(unittest.TestCase):
    def test_protected_subdomain_omits_parent(self):
        out, info = convert(fixture("||example.net^\n@@||updates.example.net^$important\n"))
        self.assertNotIn("\nexample.net\n", out)
        self.assertEqual(info["excluded_parent_or_protected_domains"], ["example.net"])

    def test_exact_and_regex(self):
        out, info = convert(fixture("||ads.example.org^\nfoo.example.org\n/^tracker\\d+\\.example.org$/\n"))
        self.assertIn("\nads.example.org\n", out)
        self.assertIn("\nfoo.example.org\n", out)
        self.assertEqual(info["unsupported_regex_rules"], 1)

    def test_single_pipe_anchored_exception(self):
        out, info = convert(fixture("||myhomescreen.tv^\n@@|myhomescreen.tv^$important\n"))
        self.assertNotIn("\nmyhomescreen.tv\n", out)

    def test_reject_unknown_syntax(self):
        with self.assertRaisesRegex(ValueError, "Unexpected upstream syntax"):
            convert(fixture("||/oops^\n"))

    def test_reject_injection(self):
        with self.assertRaises(ValueError):
            validate_domain('abc.com"; /system reset-configuration')

    def test_allowlist_never_becomes_blocklist(self):
        out, _ = convert(fixture("@@||updates.example.net^$important\n"))
        self.assertNotIn("updates.example.net\n", out)


if __name__ == "__main__":
    unittest.main()
