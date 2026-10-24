import tempfile
import unittest
from pathlib import Path

from eval.plot_ablations import render_svg


class AblationPlotTests(unittest.TestCase):
    def test_writes_dependency_free_svg_and_marks_missing_attack_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = root / "results.json"
            result.write_text(
                '{"ablations":{"network":{"targets":{"0.05":'
                '{"true_positive_rate":0.5}}},"files":{"targets":{"0.05":'
                '{"true_positive_rate":null}}}}}', encoding="utf-8")
            output = root / "plot.svg"
            render_svg(result, output)
            svg = output.read_text(encoding="utf-8")
            self.assertIn("Tripwire feature ablations", svg)
            self.assertIn("TPR 0.500", svg)
            self.assertIn("n/a (no attack positives)", svg)


if __name__ == "__main__":
    unittest.main()
