import unittest

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from tripwire.benign_corpus import resolve_benign_corpus


class BenignCorpusResolutionTests(unittest.TestCase):
    def _make_corpus(self, directory: Path, *, manifest_run_count=1,
                     joined_records=()) -> None:
        directory.mkdir(parents=True)
        run = {"run_id": "task-a-seed-11", "task_id": "task-a",
               "task_type": "search", "seed": 11, "success": False}
        (directory / "runs.jsonl").write_text(
            json.dumps(run) + "\n", encoding="utf-8")
        (directory / "joined.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in joined_records),
            encoding="utf-8")
        manifest = {
            "task_count": manifest_run_count,
            "seed_count": 1,
            "run_count": manifest_run_count,
            "success_count": 0,
            "seeds": [11],
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8")

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
            os.utime(older / "manifest.json", ns=(1_000_000_000, 1_000_000_000))
            os.utime(newer / "manifest.json", ns=(2_000_000_000, 2_000_000_000))

            self.assertEqual(resolve_benign_corpus(data_dir), newer)

            canonical = data_dir / "phase3-corpus"
            self._make_corpus(canonical)
            self.assertEqual(resolve_benign_corpus(data_dir), canonical)

    def test_rejects_explicit_corpus_missing_detector_artifacts(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "complete Phase 3 corpus"):
                resolve_benign_corpus(Path(directory), Path(directory))

    def test_rejects_explicit_corpus_when_manifest_run_count_exceeds_rows(self):
        with TemporaryDirectory() as directory:
            corpus = Path(directory) / "phase3-corpus"
            self._make_corpus(corpus, manifest_run_count=2)

            with self.assertRaisesRegex(ValueError, "complete Phase 3 corpus"):
                resolve_benign_corpus(Path(directory), corpus)

    def test_skips_truncated_newest_corpus_and_allows_empty_joined_file(self):
        with TemporaryDirectory() as directory:
            data_dir = Path(directory) / "data"
            complete = data_dir / "phase3-corpus-complete"
            partial = data_dir / "phase3-corpus-partial"
            self._make_corpus(complete)
            self._make_corpus(partial, manifest_run_count=2)
            os.utime(complete / "manifest.json", ns=(1_000_000_000, 1_000_000_000))
            os.utime(partial / "manifest.json", ns=(2_000_000_000, 2_000_000_000))

            self.assertEqual(resolve_benign_corpus(data_dir), complete)

    def test_reports_when_no_complete_corpus_exists(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no complete benign corpus"):
                resolve_benign_corpus(Path(directory))


if __name__ == "__main__":
    unittest.main()
