"""Unit tests for the scanner.

Fixture secrets are assembled at runtime from two string pieces so that this
file never contains a complete secret-looking literal (which would trip the
scanner, and GitHub's own secret scanning, on the test file itself).
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import secret_scan  # noqa: E402

SCRIPT = ROOT / "scripts" / "secret_scan.py"
RULES = secret_scan.load_rules(secret_scan.DEFAULT_RULES)

AWS = "AKIA" + "IOSFODNN7EXAMPLE"                       # AWS's documented example key ID
GOOGLE = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"   # AIza + 35 chars
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"   # ghp_ + 36 chars
STRIPE = "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"         # sk_live_ + 24 chars
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"
GENERIC_VALUE = "q8Zr3LmV0xT9bNc2Wd7Y"                    # 20 chars, high entropy

# One positive example per rule id.
POSITIVES = {
    "aws-access-key-id": f'aws_key = "{AWS}"',
    "google-api-key": f"url = 'https://x.test/?key={GOOGLE}'",
    "github-token": f"export GH={GITHUB}",
    "stripe-live-secret-key": f"stripe = {STRIPE}",
    "private-key-block": PEM,
    "generic-hardcoded-secret": f'const apiKey = "{GENERIC_VALUE}";',
}


def rule_ids(text):
    return [f.rule_id for f in secret_scan.scan_text(RULES, text)]


class FixtureSanity(unittest.TestCase):
    def test_fixture_lengths(self):
        self.assertEqual(len(AWS), 20)
        self.assertEqual(len(GOOGLE), 39)
        self.assertEqual(len(GITHUB), 40)
        self.assertEqual(len(STRIPE), 32)

    def test_every_rule_has_a_positive_example(self):
        self.assertEqual({r["id"] for r in RULES}, set(POSITIVES))

    def test_rule_ids_unique(self):
        ids = [r["id"] for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))


class PositiveDetection(unittest.TestCase):
    def test_each_rule_fires_on_its_example(self):
        for expected_id, sample in POSITIVES.items():
            with self.subTest(rule=expected_id):
                self.assertEqual(rule_ids(sample), [expected_id])

    def test_temporary_aws_key_prefix(self):
        self.assertEqual(rule_ids("k=" + "ASIA" + "IOSFODNN7EXAMPLE"), ["aws-access-key-id"])

    def test_json_style_assignment(self):
        self.assertEqual(rule_ids(f'{{"client_secret": "{GENERIC_VALUE}"}}'), ["generic-hardcoded-secret"])

    def test_html_attribute_style(self):
        self.assertEqual(rule_ids(f'<div data-api-key="{GENERIC_VALUE}"></div>'), ["generic-hardcoded-secret"])


class NegativeDetection(unittest.TestCase):
    def test_aws_wrong_length_or_case(self):
        self.assertEqual(rule_ids("k=" + AWS[:-1]), [])           # 19 chars
        self.assertEqual(rule_ids("k=" + AWS + "Q"), [])          # 21 chars
        self.assertEqual(rule_ids("k=" + AWS.lower()), [])        # lowercase

    def test_google_wrong_length(self):
        self.assertEqual(rule_ids("k=" + GOOGLE[:-1]), [])        # 38 chars
        self.assertEqual(rule_ids("k=" + GOOGLE + "Z"), [])       # 40 chars

    def test_github_too_short(self):
        self.assertEqual(rule_ids("t=" + GITHUB[:-1]), [])

    def test_stripe_test_key_not_flagged(self):
        self.assertEqual(rule_ids("k=" + "sk_test_" + "A1b2C3d4E5f6G7h8I9j0K1l2"), [])

    def test_generic_ignores_placeholders(self):
        for value in ("YOUR_API_KEY_HERE_PLEASE", "changeme_changeme_1", "<paste-your-token-here>"):
            with self.subTest(value=value):
                self.assertEqual(rule_ids(f'const apiKey = "{value}";'), [])

    def test_generic_ignores_low_entropy(self):
        self.assertEqual(rule_ids('const apiKey = "' + "a" * 20 + '";'), [])

    def test_generic_ignores_short_values(self):
        self.assertEqual(rule_ids('const apiKey = "abc123";'), [])

    def test_generic_ignores_env_lookup(self):
        self.assertEqual(rule_ids("const apiKey = process.env.API_KEY;"), [])

    def test_generic_ignores_unrelated_names(self):
        self.assertEqual(rule_ids(f'const username = "{GENERIC_VALUE}";'), [])


class ScannerLogic(unittest.TestCase):
    def test_entropy_values(self):
        self.assertEqual(secret_scan.shannon_entropy("aaaa"), 0.0)
        self.assertGreater(secret_scan.shannon_entropy(GENERIC_VALUE), 3.0)

    def test_dedup_specific_rule_wins_over_generic(self):
        findings = secret_scan.scan_text(RULES, f'const API_KEY = "{GOOGLE}";')
        self.assertEqual([f.rule_id for f in findings], ["google-api-key"])

    def test_line_numbers(self):
        findings = secret_scan.scan_text(RULES, f"ok\nok\nk={AWS}\n")
        self.assertEqual([f.line for f in findings], [3])

    def test_allow_marker_suppresses_line(self):
        self.assertEqual(rule_ids(f"k={AWS} // secretscan:allow"), [])

    def test_redaction_never_contains_full_secret(self):
        for sample in POSITIVES.values():
            for f in secret_scan.scan_text(RULES, sample):
                self.assertNotIn(GOOGLE, f.redacted)
                self.assertNotIn(AWS, f.redacted)
                self.assertIn("*", f.redacted)

    def test_redact_short_value_fully_masked(self):
        self.assertEqual(secret_scan.redact("abcd"), "****")


class CommandLine(unittest.TestCase):
    def run_cli(self, directory, *extra):
        env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY")}
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(directory), *extra],
            capture_output=True, text=True, env=env,
        )

    def test_exit_1_and_no_full_secret_in_output_when_leak_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "page.html").write_text(f'<script>const k = "{GOOGLE}";</script>')
            result = self.run_cli(tmp)
            self.assertEqual(result.returncode, 1)
            self.assertIn("google-api-key", result.stdout)
            self.assertNotIn(GOOGLE, result.stdout + result.stderr)

    def test_exit_0_on_clean_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "page.html").write_text("<p>hello</p>")
            self.assertEqual(self.run_cli(tmp).returncode, 0)

    def test_excluded_directory_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "vendor").mkdir()
            Path(tmp, "vendor", "a.js").write_text(f"k={AWS}")
            self.assertEqual(self.run_cli(tmp, "--exclude-dir", "vendor").returncode, 0)
            self.assertEqual(self.run_cli(tmp).returncode, 1)

    def test_binary_files_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "blob.bin").write_bytes(b"\x00\x01" + AWS.encode())
            self.assertEqual(self.run_cli(tmp).returncode, 0)

    def test_bad_rules_file_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp, "bad.json")
            bad.write_text("{not json")
            result = self.run_cli(tmp, "--rules", str(bad))
            self.assertEqual(result.returncode, 2)

    def test_github_annotation_emitted_in_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.js").write_text(f"k={AWS}")
            env = dict(os.environ, GITHUB_ACTIONS="true")
            env.pop("GITHUB_STEP_SUMMARY", None)
            result = subprocess.run([sys.executable, str(SCRIPT), tmp],
                                    capture_output=True, text=True, env=env)
            self.assertIn("::error file=", result.stdout)


if __name__ == "__main__":
    unittest.main()
