"""Export every chart in demo-story order as a PNG (for the README / deck) and an interactive HTML file.

  python -m sentinel.export_charts        ->  docs/charts/*.png and docs/charts/*.html

Order follows the dashboard's Visual insights acts:
  1 The threat · 2 Detection · 3 Decisions · 4 Holding the line · 5 Scenario lab
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
    for old in OUT.glob("*.*"):  # numbering changed: clear stale exports
        old.unlink()
    scored = pd.read_csv(DATA / "rba_scored.csv.gz")
    sample = pd.read_csv(DATA / "rba_sample.csv.gz", usecols=["Login Timestamp", "Is Account Takeover"])
    results = json.loads((DATA / "results.json").read_text(encoding="utf-8"))["cases"]
    sweep = json.loads((DATA / "rba_sweep.json").read_text(encoding="utf-8"))
    rt_path = DATA / "redteam_llm.json" if (DATA / "redteam_llm.json").exists() else DATA / "redteam.json"
    rt = json.loads(rt_path.read_text(encoding="utf-8"))
    # the case where the floor matters most, with a fully persuaded AI
    ex = min((c for c in results if c["action"] == "lock" and c["label"] == 1),
             key=lambda c: c["anomaly_risk"] - c["floor"])
    charts = {
        "1-1_when_heatmaps": (viz.when_heatmaps(sample), None),
        "1-2_country_profile": (viz.country_profile(scored), 620),
        "2-1_signal_lift": (viz.signal_lift(scored), 620),
        "2-2_risk_separation": (viz.risk_separation(scored), None),
        "2-3_takeover_fingerprint": (viz.takeover_fingerprint(scored), 620),
        "3-1_triage_funnel": (viz.triage_funnel(scored), None),
        "3-2_decision_matrix": (viz.decision_matrix(scored), 760),
        "3-3_tradeoff_curve": (viz.tradeoff_curve(sweep), 560),
        "4-1_verdict_anatomy_persuaded": (viz.verdict_anatomy(
            ex["floor"], ex["anomaly_risk"], 10, max(ex["floor"], 10),
            f"{ex['scenario'].replace('_', ' ')} case with the AI persuaded down to 10: final stays at the floor"), 640),
        "4-2_redteam_heatmap": (viz.redteam_heatmap(rt), 560),
        "5-1_scenario_rules": (viz.scenario_rule_heatmap(results), 820),
        "5-2_risk_ladder": (viz.risk_ladder(results), 760),
    }
    for name, (chart, width) in charts.items():
        c = chart.properties(width=width) if width else chart
        c = c.configure(background="white")
        c.save(OUT / f"{name}.png", scale_factor=2)
        c.save(OUT / f"{name}.html")
        print("wrote", name)


if __name__ == "__main__":
    main()
