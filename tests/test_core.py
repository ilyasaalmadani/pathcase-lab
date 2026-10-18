import os
import tempfile
import unittest
from pathlib import Path

from pathcase_lab.core import (
    PROBE_PAIRS,
    _component_findings,
    _portable_key,
    audit_tree,
    probe_filesystem,
)


class PortablePolicyTests(unittest.TestCase):
    def test_canonical_and_casefold_candidates(self):
        self.assertEqual(_portable_key("café.txt"), _portable_key("cafe\u0301.txt"))
        self.assertEqual(_portable_key("Atlas.txt"), _portable_key("atlas.txt"))
        self.assertEqual(_portable_key("Straße.txt"), _portable_key("STRASSE.txt"))
        self.assertEqual(_portable_key("plan.txt"), _portable_key(" plan.txt "))

    def test_windows_rules_include_superscript_devices(self):
        codes = {item["code"] for item in _component_findings("COM¹.log", "COM¹.log")}
        self.assertIn("windows_reserved_device", codes)
        codes = {item["code"] for item in _component_findings("bad?.txt ", "bad?.txt ")}
        self.assertEqual(codes, {"windows_forbidden_character", "windows_trailing_dot_or_space"})


class AuditTests(unittest.TestCase):
    def test_audit_is_read_only_and_excludes_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "safe.txt").write_text("data")
            (root / ".git").mkdir()
            (root / ".git" / "CON.txt").write_text("ignored")
            before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
            report = audit_tree(root)
            after = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
            self.assertEqual(before, after)
            self.assertEqual(report["errors"], [])
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["scanned_entries"], 2)

    @unittest.skipIf(os.name == "nt", "Windows cannot create this reserved name")
    def test_audit_reports_reserved_name_and_glob_exclusion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "CON.txt").write_text("one")
            report = audit_tree(root)
            self.assertEqual([finding["code"] for finding in report["findings"]], ["windows_reserved_device"])
            self.assertEqual(audit_tree(root, ["CON.txt"])["findings"], [])


class ProbeTests(unittest.TestCase):
    def test_probe_uses_and_removes_isolated_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            report = probe_filesystem(parent)
            self.assertEqual(len(report["cases"]), len(PROBE_PAIRS))
            self.assertEqual(list(parent.iterdir()), [])
            self.assertTrue(all(case["result"] in {"distinct", "collision", "unsupported"} for case in report["cases"]))
            self.assertEqual([case["id"] for case in report["cases"]], [case[0] for case in PROBE_PAIRS])


if __name__ == "__main__":
    unittest.main()
