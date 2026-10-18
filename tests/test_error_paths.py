import os
import tempfile
import unittest
from pathlib import Path

from pathcase_lab.core import audit_tree, probe_filesystem


class ErrorPathTests(unittest.TestCase):
    def test_audit_handles_scandir_error(self):
        # Create a directory and remove read permission to force OSError on scandir
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            d = root / "noaccess"
            d.mkdir()
            (d / "file.txt").write_text("data")
            # remove permissions
            d.chmod(0)
            try:
                report = audit_tree(root)
                # Should record an error for the unreadable directory
                self.assertTrue(report["errors"], "Expected errors in report for unreadable dir")
            finally:
                # restore permissions so temp dir can be cleaned up
                d.chmod(0o700)

    def test_probe_handles_unwritable_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            # make parent unwritable
            parent.chmod(0)
            try:
                with self.assertRaises(ValueError):
                    probe_filesystem(parent)
            finally:
                parent.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
