#!/usr/bin/env python3
"""Render a dependency-free SVG of measured ablation TPR at each target FPR."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path


def render_svg(results_path: Path, output_path: Path) -> None:
    report = json.loads(results_path.read_text(encoding="utf-8"))
    names = list(report.get("ablations", {}))
    targets = sorted({key for item in report.get("ablations", {}).values()
                      for key in item.get("targets", {})}, key=float)
    width, height = 900, max(250, 105 + len(names) * 44 + len(targets) * 28)
    rows = []
    y = 68
    for target in targets:
        rows.append(f'<text x="12" y="{y}" font-size="15">Target FPR {html.escape(target)}</text>')
        y += 26
        for name in names:
            metrics = report["ablations"][name]["targets"][target]
            tpr = metrics["true_positive_rate"]
            x = 180
            label = "n/a (no attack positives)" if tpr is None else f"TPR {tpr:.3f}"
            bar_width = 0 if tpr is None else round(560 * tpr)
            color = "#7f8c8d" if tpr is None else "#2878b5"
            rows.append(f'<text x="24" y="{y + 16}" font-size="14">{html.escape(name)}</text>')
            rows.append(f'<rect x="{x}" y="{y}" width="{bar_width}" height="22" fill="{color}"/>')
            rows.append(f'<text x="{x + bar_width + 10}" y="{y + 16}" font-size="13">{label}</text>')
            y += 34
        y += 14
    content = "\n".join(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}"><title>Tripwire feature ablations</title>'
        f'<rect width="100%" height="100%" fill="white"/>{content}</svg>\n',
        encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render_svg(args.results, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
