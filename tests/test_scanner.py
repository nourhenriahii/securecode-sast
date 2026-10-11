"""Regression tests: run with  python3 -m unittest discover -s tests -v"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scanner  # noqa: E402

SAMPLES = ROOT / "test_samples"
FAKE_SECRETS = ["sk-test-123456789", "Xk29fjs8dh3", "sk-live-9f8a7b6c5d4e", "r7Tq92LmZpw1"]


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = scanner.scan_path(SAMPLES)

    def lines(self, filename, rule=None):
        return {f["line"] for f in self.found
                if Path(f["file"]).name == filename and (rule is None or f["rule"] == rule)}

    def test_detects_expected_rules(self):
        rules = {f["rule"] for f in self.found}
        expected = {"hardcoded-credential", "dangerous-exec", "shell-true", "sql-injection",
                    "unsafe-deserialization", "os-system", "applescript-injection",
                    "applescript-escaped", "debug-mode", "bind-all-interfaces"}
        self.assertTrue(expected <= rules, f"missing rules: {expected - rules}")

    def test_sql_injection_lines(self):
        # f-string, concatenation, % formatting, and a query built in a variable
        self.assertEqual(self.lines("vulnerable.py", "sql-injection"), {22, 23, 24, 28})

    def test_safe_code_is_not_reported(self):
        vulnerable = self.lines("vulnerable.py")
        self.assertNotIn(25, vulnerable)   # parameterized query
        self.assertNotIn(7, vulnerable)    # placeholder password "changeme"
        self.assertNotIn(8, vulnerable)    # low-entropy value
        # config.js: only the 3 real secrets, not the placeholder or process.env
        self.assertEqual(self.lines("config.js"), {1, 2, 3})

    def test_env_example_is_scanned(self):
        self.assertEqual(self.lines(".env.example"), {1})

    def test_secrets_are_masked_in_output(self):
        for f in self.found:
            for secret in FAKE_SECRETS:
                self.assertNotIn(secret, f["snippet"])

    def test_redact_masks_before_sending_to_ai(self):
        runtime_token = "gsk_" + "abcdefghijklmnop1234"   # built at runtime: no token-shaped literal in the repo
        for line in ('api_key = "sk-test-123456789"', "DB_PASSWORD=Xk29fjs8dh3",
                     "x = 'sk-live-9f8a7b6c5d4e'", "key = " + runtime_token):
            out = scanner.redact(line)
            for secret in FAKE_SECRETS + [runtime_token]:
                self.assertNotIn(secret, out)

    def test_known_token_format_with_unusual_name(self):
        # built at runtime so no token-shaped string is committed to the repo
        fake = "gsk_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ" * 2
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text(f"private-key={fake}\n", encoding="utf-8")
            (Path(tmp) / "app.py").write_text(f'x = "{fake}"\n', encoding="utf-8")
            (Path(tmp) / "notes.py").write_text('title = "task-list-manager-application"\n', encoding="utf-8")
            found = scanner.scan_path(tmp)
        by_file = {Path(f["file"]).name: f for f in found}
        self.assertEqual(set(by_file), {".env", "app.py"})   # notes.py is not a token
        for f in found:
            self.assertEqual(f["severity"], "HIGH")
            self.assertNotIn(fake, f["snippet"])

    def test_ai_stops_on_first_invalid_key(self):
        import ai_layer
        calls = []

        def fake_urlopen(*args, **kwargs):
            calls.append(1)
            raise urllib.error.HTTPError("https://x", 401, "Unauthorized", {}, io.BytesIO(b"{}"))

        fake_key = "gsk_" + "x" * 52   # built at runtime
        findings = scanner.scan_path(SAMPLES)
        with mock.patch.dict(os.environ, {"GROQ_API_KEY": fake_key}), \
                mock.patch("urllib.request.urlopen", fake_urlopen), \
                contextlib.redirect_stderr(io.StringIO()):
            ai_layer.annotate(findings, scanner.redact, "en", None, 10)
        self.assertEqual(len(calls), 1)   # stopped after the first 401, no retries

    def test_html_report_is_escaped(self):
        fake = [{"file": "<script>x</script>.py", "line": 1, "severity": "HIGH",
                 "rule": "dangerous-exec", "message": "m", "snippet": "<b>"}]
        page = scanner.build_html(fake, "t")
        self.assertNotIn("<script>x</script>", page)


if __name__ == "__main__":
    unittest.main()
