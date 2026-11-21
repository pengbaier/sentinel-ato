"""End-to-end scoring: profiles -> features -> rules floor -> anomaly model -> AI investigator -> policy.

Run:  python -m sentinel.pipeline            (offline analyst, no keys needed)
      python -m sentinel.pipeline --llm      (AI investigator via Nicrron, traces to PRISM)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from . import investigator, rules
from .features import ProfileStore, group_sessions, session_features, vector
from .integrations import detect_manipulation

DATA = Path(__file__).resolve().parent.parent / "data"
TRIAGE_THRESHOLD = 25  # below this, no LLM call: the case is cleared cheaply


class AnomalyModel:
    def __init__(self):
        self.model = IsolationForest(n_estimators=200, contamination="auto", random_state=0)
        self.train_scores: list[float] = []

    def fit(self, X):
        self.model.fit(X)
        self.train_scores = sorted((-self.model.score_samples(X)).tolist())
        n = len(self.train_scores)
        self.p90, self.p99, self.p999 = (self.train_scores[int(q * (n - 1))] for q in (0.9, 0.99, 0.999))
        self.top = self.train_scores[-1]

    def risk(self, x) -> int:
        a = float(-self.model.score_samples([x])[0])
        if a <= self.p90:
            return 0
        if a <= self.p99:
            return int(10 + 30 * (a - self.p90) / (self.p99 - self.p90 + 1e-9))
        if a <= self.p999:
            return int(40 + 25 * (a - self.p99) / (self.p999 - self.p99 + 1e-9))
        span = max(self.top - self.p999, 1e-3)
        return int(min(90, 65 + 25 * (a - self.p999) / span))


def decide(final_risk: int, hits: list[dict]) -> str:
    """Policy engine. The AI recommends; this decides. Hard rules >= 70 always lock."""
    if final_risk >= 70 or any(h["floor"] >= 70 for h in hits):
        return "lock"
    if final_risk >= 30:
        return "step_up"
    return "allow"


class Sentinel:
    def __init__(self):
        self.profiles = ProfileStore()
        self.anomaly = AnomalyModel()

    # -------------------------------------------------------------- training
    def warm_up(self, sessions: list[list[dict]]):
        X = []
        for evs in sessions:
            p = self.profiles.get(evs[0]["user_id"])
            if p.sessions >= 3:
                X.append(vector(session_features(evs, p, self.profiles.glob)))
            self.profiles.learn(evs[0]["user_id"], evs)
        self.anomaly.fit(np.array(X))
        return len(X)

    # -------------------------------------------------------------- scoring
    def build_case(self, evs: list[dict], extra_chat: list[str] | None = None) -> dict:
        uid, sid = evs[0]["user_id"], evs[0]["session_id"]
        prof = self.profiles.get(uid)
        f = session_features(evs, prof, self.profiles.glob)
        chats = [e["text"] for e in evs if e["type"] == "support_chat"] + (extra_chat or [])
        manip = None
        if chats:
            manip = detect_manipulation("\n".join(chats), sid)
            f["has_chat"] = 1
        hits = rules.evaluate(f, evs, manip)
        return {"case_id": sid, "user_id": uid, "events": evs, "features": f,
                "hits": [h.__dict__ for h in hits], "floor": rules.floor_of(hits),
                "anomaly_risk": self.anomaly.risk(vector(f)), "manipulation": manip,
                "extra_chat": extra_chat or []}

    def score(self, evs: list[dict], use_llm=False, extra_chat=None, update_profile=True) -> dict:
        case = self.build_case(evs, extra_chat)
        pre = max(case["floor"], case["anomaly_risk"])
        case["pre_score"] = pre
        if pre >= TRIAGE_THRESHOLD or case["features"]["has_chat"]:
            ai = investigator.investigate(case, use_llm=use_llm)
        else:
            ai = {"verdict": "benign", "risk": pre, "evidence": [], "benign_explanations":
                  ["within this user's normal behaviour"], "manipulation_detected": False,
                  "recommended_action": "allow", "engine": "triage"}
        case["ai"] = ai
        case["final_risk"] = max(case["floor"], ai["risk"])  # belt and braces
        case["action"] = decide(case["final_risk"], case["hits"])
        if update_profile and case["action"] == "allow":
            self.profiles.learn(case["user_id"], evs)  # only trusted sessions teach the baseline
        return case


def load():
    events = [json.loads(l) for l in open(DATA / "events.jsonl", encoding="utf-8")]
    cases = {c["case_id"]: c for c in json.loads((DATA / "cases.json").read_text(encoding="utf-8"))}
    sessions = group_sessions(events)
    hist = [s for sid, s in sessions.items() if cases[sid]["phase"] == "history"]
    live = [s for sid, s in sessions.items() if cases[sid]["phase"] == "live"]
    hist.sort(key=lambda s: s[0]["ts"])
    live.sort(key=lambda s: s[0]["ts"])
    return hist, live, cases


def build(use_llm=False, verbose=True):
    hist, live, labels = load()
    s = Sentinel()
    n = s.warm_up(hist)
    if verbose:
        print(f"trained anomaly model on {n} history sessions; scoring {len(live)} live sessions "
              f"({'LLM' if use_llm else 'offline analyst'})")
    results = []
    for i, evs in enumerate(live):
        c = s.score(evs, use_llm=use_llm)
        lab = labels[c["case_id"]]
        c["label"], c["scenario"], c["note"] = lab["label"], lab["scenario"], lab["note"]
        results.append(c)
        if verbose and use_llm and c["ai"].get("engine") not in ("triage",) and i % 10 == 0:
            print(f"  {i}/{len(live)} {c['scenario']:<20} final={c['final_risk']} {c['action']}")
    return s, results


def metrics(results: list[dict]) -> dict:
    tp = sum(1 for r in results if r["label"] == 1 and r["action"] != "allow")
    fn = sum(1 for r in results if r["label"] == 1 and r["action"] == "allow")
    fp_lock = sum(1 for r in results if r["label"] == 0 and r["action"] == "lock")
    fp_step = sum(1 for r in results if r["label"] == 0 and r["action"] == "step_up")
    tn = sum(1 for r in results if r["label"] == 0 and r["action"] == "allow")
    ato_locked = sum(1 for r in results if r["label"] == 1 and r["action"] == "lock")
    pos = tp + fn
    neg = tn + fp_lock + fp_step
    by = {}
    for r in results:
        d = by.setdefault(r["scenario"], {"label": r["label"], "n": 0, "allow": 0, "step_up": 0, "lock": 0})
        d["n"] += 1
        d[r["action"]] += 1
    return {"ato_cases": pos, "caught": tp, "caught_pct": round(100 * tp / max(pos, 1), 1),
            "locked_pct": round(100 * ato_locked / max(pos, 1), 1),
            "good_cases": neg, "good_cleared_pct": round(100 * tn / max(neg, 1), 1),
            "false_lock_pct": round(100 * fp_lock / max(neg, 1), 2),
            "step_up_pct": round(100 * fp_step / max(neg, 1), 2), "by_scenario": by}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="use the AI investigator via Nicrron")
    a = ap.parse_args()
    _, results = build(use_llm=a.llm)
    m = metrics(results)
    out = DATA / ("results_llm.json" if a.llm else "results.json")
    out.write_text(json.dumps({"metrics": m, "cases": results}, default=str), encoding="utf-8")
    print(json.dumps({k: v for k, v in m.items() if k != "by_scenario"}, indent=1))
    print(f"{'scenario':<22}{'label':>6}{'n':>5}{'allow':>7}{'step':>6}{'lock':>6}")
    for k, d in sorted(m["by_scenario"].items(), key=lambda kv: (-kv[1]["label"], kv[0])):
        print(f"{k:<22}{d['label']:>6}{d['n']:>5}{d['allow']:>7}{d['step_up']:>6}{d['lock']:>6}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
