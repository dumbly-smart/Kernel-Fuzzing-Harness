import unittest

import os
from pathlib import Path
from tempfile import TemporaryDirectory

from tripwire.benign_corpus import resolve_benign_corpus


class BenignCorpusResolutionTests(unittest.TestCase):
    def _make_corpus(self, directory: Path) -> None:
        directory.mkdir(parents=True)
        (directory / "runs.jsonl").write_text("{}\n", encoding="utf-8")
        (directory / "joined.jsonl").write_text("{}\n", encoding="utf-8")

    def test_prefers_explicit_corpus_path(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_corpus(root / "data/phase3-corpus-older")
            explicit = root / "other-corpus"
            self._make_corpus(explicit)

            self.assertEqual(
                resolve_benign_corpus(root / "data", explicit), explicit)

    def test_prefers_canonical_corpus_then_latest_complete_run(self):
        with TemporaryDirectory() as directory:
            data_dir = Path(directory) / "data"
            older = data_dir / "phase3-corpus-older"
            newer = data_dir / "phase3-corpus-newer"
            self._make_corpus(older)
            self._make_corpus(newer)
            (older / "manifest.json").write_text("{}\n", encoding="utf-8")
            (newer / "manifest.json").write_text("{}\n", encoding="utf-8")
            os.utime(older / "manifest.json", ns=(1_000_000_000, 1_000_000_000))
            os.utime(newer / "manifest.json", ns=(2_000_000_000, 2_000_000_000))

            self.assertEqual(resolve_benign_corpus(data_dir), newer)

            canonical = data_dir / "phase3-corpus"
            self._make_corpus(canonical)
            self.assertEqual(resolve_benign_corpus(data_dir), canonical)

    def test_rejects_explicit_corpus_missing_detector_artifacts(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "joined.jsonl"):
                resolve_benign_corpus(Path(directory), Path(directory))

    def test_reports_when_no_complete_corpus_exists(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no complete benign corpus"):
                resolve_benign_corpus(Path(directory))


if __name__ == "__main__":
    unittest.main()
