import contextlib
import io
import json
import tempfile
import unittest

from pathcase_lab.cli import main


class CliTests(unittest.TestCase):
    def test_audit_json_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["audit", temporary, "--json"])
            report = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["findings"], [])

    def test_missing_target_is_usage_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["audit", "/this/pathcase/path/does/not/exist"])
        self.assertEqual(status, 2)
        self.assertIn("pathcase:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
