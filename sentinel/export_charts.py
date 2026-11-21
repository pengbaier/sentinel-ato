"""Export every dashboard chart as a PNG (for the README) and an interactive HTML file.

  python -m sentinel.export_charts        ->  docs/charts/*.png and docs/charts/*.html
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from . import viz
from .pipeline import DATA

OUT = DATA.parent / "docs" / "charts"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    scored = pd.read_csv(DATA / "rba_scored.csv.gz")
    sample = pd.read_csv(DATA / "rba_sample.csv.gz", usecols=["Login Timestamp", "Is Account Takeover"])
    results = json.loads((DATA / "results.json").read_text(encoding="utf-8"))["cases"]
    sweep = json.loads((DATA / "rba_sweep.json").read_text(encoding="utf-8"))
    rt_path = DATA / "redteam_llm.json" if (DATA / "redteam_llm.json").exists() else DATA / "redteam.json"
    rt = json.loads(rt_path.read_text(encoding="utf-8"))
    charts = {
        "1_decision_matrix": (viz.decision_matrix(scored), 760),
        "2_takeover_fingerprint": (viz.takeover_fingerprint(scored), 620),
        "3_risk_separation": (viz.risk_separation(scored), None),
        "4_when_heatmaps": (viz.when_heatmaps(sample), 470),
        "5_country_profile": (viz.country_profile(scored), 620),
        "6_tradeoff_curve": (viz.tradeoff_curve(sweep), 560),
        "7_scenario_rules": (viz.scenario_rule_heatmap(results), 820),
        "8_risk_ladder": (viz.risk_ladder(results), 760),
        "9_redteam_heatmap": (viz.redteam_heatmap(rt), 520),
    }
    for name, (chart, width) in charts.items():
        c = chart.properties(width=width) if width and not name.startswith("4_") else chart
        if name.startswith("4_"):  # hconcat: size each panel
            c = chart
        c = c.configure(background="white")
        c.save(OUT / f"{name}.png", scale_factor=2)
        c.save(OUT / f"{name}.html")
        print("wrote", name)


if __name__ == "__main__":
    main()
