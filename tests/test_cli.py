import tempfile
import unittest
from pathlib import Path

from tripwire.cli import cgroup_id_from_path


class CgroupIdTests(unittest.TestCase):
    def test_returns_inode_only_for_descendant_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            child = root / "agent"
            child.mkdir(parents=True)

            self.assertEqual(cgroup_id_from_path(child, root=root), child.stat().st_ino)

    def test_rejects_cgroup_root_and_outside_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            with self.assertRaisesRegex(ValueError, "must be a child"):
                cgroup_id_from_path(root, root=root)
            with self.assertRaisesRegex(ValueError, "must be a child"):
                cgroup_id_from_path(outside, root=root)

    def test_rejects_symlink_that_escapes_cgroup_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "must be a child"):
                cgroup_id_from_path(root / "escape", root=root)


if __name__ == "__main__":
    unittest.main()
