"""Evaluate Sentinel on the public RBA login dataset (Wiefling et al., 2022, CC BY 4.0).

  python -m sentinel.rba sample          # stream the CSV out of data/raw/rba-dataset.zip, keep a user sample
  python -m sentinel.rba eval            # offline: rules + anomaly + offline analyst
  python -m sentinel.rba eval --no-threat-intel   # ablation: ignore the "Is Attack IP" feed
  python -m sentinel.rba eval --llm 150  # also send up to 150 triaged cases to the AI investigator

Labels come from the service's incident-response team ("Is Account Takeover").
The dataset has login events only, so only login-level rules can fire.
Cite: Wiefling, Jørgensen, Thunem, Lo Iacono. ACM TOPS 2022. doi:10.1145/3546069
"""
from __future__ import annotations

import argparse
import json
import random
import re
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from . import investigator, rules
from .features import ProfileStore, session_features, vector
from .pipeline import AnomalyModel, decide

ROOT = Path(__file__).resolve().parent.parent
ZIP = ROOT / "data" / "raw" / "rba-dataset.zip"
SAMPLE = ROOT / "data" / "rba_sample.csv.gz"
OUT = ROOT / "data"
USER_MOD = 64  # keep users with id % 64 == 0  (~1/64 of 3.3M users) plus every user with a takeover


def _open_csv(zf: zipfile.ZipFile):
    name = next(n for n in zf.namelist() if n.endswith(".csv"))
    return zf.open(name)


def sample():
    t0 = time.time()
    with zipfile.ZipFile(ZIP) as zf:
        ato_users, n = set(), 0
        with _open_csv(zf) as f:
            for ch in pd.read_csv(f, usecols=["User ID", "Is Account Takeover"], chunksize=2_000_000):
                ato_users |= set(ch.loc[ch["Is Account Takeover"], "User ID"].tolist())
                n += len(ch)
        print(f"pass 1: {n:,} rows, {len(ato_users)} users with a takeover ({time.time()-t0:.0f}s)")
        parts = []
        with _open_csv(zf) as f:
            for ch in pd.read_csv(f, chunksize=2_000_000, low_memory=False):
                keep = (ch["User ID"] % USER_MOD == 0) | ch["User ID"].isin(ato_users)
                parts.append(ch[keep])
    df = pd.concat(parts)
    df.to_csv(SAMPLE, index=False, compression="gzip")
    print(f"pass 2: kept {len(df):,} rows from {df['User ID'].nunique():,} users, "
          f"{int(df['Is Account Takeover'].sum())} takeover rows -> {SAMPLE} ({time.time()-t0:.0f}s)")


_VER = re.compile(r"[\s/]*[\d][\w.]*$")


def device_key(os_name, browser, dtype) -> str:
    strip = lambda s: _VER.sub("", str(s)).strip()  # "Chrome Mobile 46.0.2490" -> "Chrome Mobile"
    return f"{strip(os_name)}|{strip(browser)}|{dtype}"


def to_events(df: pd.DataFrame, threat_intel=True, coarse_device=True) -> list[dict]:
    ts = pd.to_datetime(df["Login Timestamp"]).astype("int64") / 1e9
    ev = []
    for i, (r, t) in enumerate(zip(df.itertuples(index=False), ts)):
        ua = r[df.columns.get_loc("User Agent String")]
        ev.append({
            "ts": float(t), "user_id": str(r[df.columns.get_loc("User ID")]), "session_id": f"rba-{i}",
            "type": "login", "success": bool(r[df.columns.get_loc("Login Successful")]),
            "ip": r[df.columns.get_loc("IP Address")], "asn": int(r[df.columns.get_loc("ASN")]),
            "asn_name": f"AS{int(r[df.columns.get_loc('ASN')])}", "hosting": False,
            "country": r[df.columns.get_loc("Country")], "city": str(r[df.columns.get_loc("City")]),
            "lat": None, "lon": None,
            # device fingerprint proxy (no device id in the dataset): OS family + browser family + type,
            # so a browser/OS version update doesn't look like a brand-new device
            "device_id": device_key(r[df.columns.get_loc("OS Name and Version")],
                                    r[df.columns.get_loc("Browser Name and Version")],
                                    r[df.columns.get_loc("Device Type")]) if coarse_device else str(ua),
            "ua": str(ua),
            "device_type": str(r[df.columns.get_loc("Device Type")]),
            "rtt_ms": r[df.columns.get_loc("Round-Trip Time [ms]")],
            "attack_ip": bool(r[df.columns.get_loc("Is Attack IP")]) if threat_intel else False,
            "label": int(bool(r[df.columns.get_loc("Is Account Takeover")])),
        })
    return ev


def calibrate(am: AnomalyModel, train_rows: list[dict], budget: float):
    """Pick anomaly lock thresholds WITHOUT labels: on held-out training users (assumed ~all legit,
    takeovers are ~1 in 200k logins), choose the lowest thresholds whose combined lock rate stays
    within `budget` (e.g. 0.002 = 0.2% of logins)."""
    a = [_risk_from_raw(am, s) for s in -am.model.score_samples(np.array([vector(t["f"]) for t in train_rows]))]
    n = len(a)
    weak = np.array([t["weak"] for t in train_rows])
    nohit = np.array([not t["hit"] for t in train_rows])
    a = np.array(a)
    corr = next((t for t in range(40, 101) if ((a >= t) & weak).sum() / n <= budget * 0.75), 101)
    alone = next((t for t in range(60, 101) if ((a >= t) & nohit).sum() / n <= budget * 0.25), 101)
    investigator.LOCK_POLICY.update(corroborated=corr, alone=alone)
    print(f"calibrated on {n:,} unlabeled training logins: lock if anomaly>={corr} + a rule, "
          f"or anomaly>={alone} alone (budget {budget:.2%})")


def evaluate(threat_intel=True, llm_n=0, blend=True, budget=0.001):
    t0 = time.time()
    df = pd.read_csv(SAMPLE, low_memory=False).sort_values("Login Timestamp", kind="stable")
    events = to_events(df, threat_intel)
    # Split by USER, not time: half of the random-sample users train the anomaly model (labels unused),
    # the other half plus every takeover user are evaluated over their whole history, online.
    ato_users = set(df.loc[df["Is Account Takeover"], "User ID"].astype(str))
    def is_train(uid):
        return uid not in ato_users and (hash(uid) & 1) == 0
    profiles, X_train, train_rows = ProfileStore(), [], []
    rows = []
    for e in events:
        p = profiles.get(e["user_id"])
        f = session_features([e], p, profiles.glob)
        gate = True
        if is_train(e["user_id"]):
            if e["success"] and p.sessions >= 1:
                X_train.append(vector(f))
                train_rows.append({"f": f, "weak": any(h.floor >= 40 for h in rules.evaluate(f, [e])),
                                   "hit": bool(rules.evaluate(f, [e]))})
        elif p.sessions >= 1 or not e["success"]:  # first-ever login has no baseline to compare with
            hits = rules.evaluate(f, [e])
            rows.append({"e": e, "f": f, "hits": [h.__dict__ for h in hits], "floor": rules.floor_of(hits)})
            gate = rules.floor_of(hits) < 70  # only rules gate profile learning (no label leakage)
        if not e["success"]:
            p.recent_fails.append(e["ts"])
        elif gate:
            profiles.learn(e["user_id"], [e])
    print(f"{len(events):,} logins; warm-up {len(X_train):,} train vectors; scoring {len(rows):,} ({time.time()-t0:.0f}s)")

    am = AnomalyModel()
    am.fit(np.array(X_train))
    raw = -am.model.score_samples(np.array([vector(r["f"]) for r in rows]))
    for r, a in zip(rows, raw):
        r["anomaly"] = _risk_from_raw(am, a)
    if blend:
        calibrate(am, train_rows, budget)
    else:
        investigator.LOCK_POLICY.update(corroborated=101, alone=101)

    llm_ids = set()
    if llm_n:
        triaged = [i for i, r in enumerate(rows) if max(r["floor"], r["anomaly"]) >= 25]
        llm_ids = set(random.Random(0).sample(triaged, k=min(llm_n, len(triaged))))
    for i, r in enumerate(rows):
        pre = max(r["floor"], r["anomaly"])
        case = {"case_id": r["e"]["session_id"], "user_id": r["e"]["user_id"], "events": [r["e"]],
                "features": r["f"], "hits": r["hits"], "floor": r["floor"], "anomaly_risk": r["anomaly"],
                "manipulation": None}
        if i in llm_ids:
            ai = investigator.investigate(case, use_llm=True)
        elif pre >= 25:
            ai = investigator.enforce_floor(investigator.offline_analyst(case), r["floor"])
        else:
            ai = {"risk": pre, "verdict": "benign", "engine": "triage"}
        r["final"] = max(r["floor"], ai["risk"])
        r["action"] = decide(r["final"], r["hits"])
        r["engine"] = ai.get("engine")
    return _report(rows, threat_intel, llm_ids)


def _risk_from_raw(am: AnomalyModel, a: float) -> int:
    if a <= am.p90:
        return 0
    if a <= am.p99:
        return int(10 + 30 * (a - am.p90) / (am.p99 - am.p90 + 1e-9))
    if a <= am.p999:
        return int(40 + 25 * (a - am.p99) / (am.p999 - am.p99 + 1e-9))
    return int(min(90, 65 + 25 * (a - am.p999) / max(am.top - am.p999, 1e-3)))


def _report(rows, threat_intel, llm_ids):
    y = np.array([r["e"]["label"] for r in rows])
    succ = np.array([r["e"]["success"] for r in rows])
    act = np.array([r["action"] for r in rows])
    final = np.array([r["final"] for r in rows])
    pos, neg = y == 1, (y == 0) & succ
    def pct(a, b):
        return round(100 * a / max(b, 1), 2)
    m = {
        "source": "RBA dataset (Wiefling et al. 2022), user sample",
        "threat_intel_feed": threat_intel,
        "eval_logins": int(len(rows)), "takeover_logins": int(pos.sum()),
        "legit_successful_logins": int(neg.sum()),
        "takeovers_challenged_or_locked_pct": pct(((act != "allow") & pos).sum(), pos.sum()),
        "takeovers_locked_pct": pct(((act == "lock") & pos).sum(), pos.sum()),
        "legit_allowed_silently_pct": pct(((act == "allow") & neg).sum(), neg.sum()),
        "legit_step_up_pct": pct(((act == "step_up") & neg).sum(), neg.sum()),
        "legit_locked_pct": pct(((act == "lock") & neg).sum(), neg.sum()),
        "auc_final": round(float(roc_auc_score(y, final)), 4) if pos.any() else None,
        "auc_anomaly_only": round(float(roc_auc_score(y, [r["anomaly"] for r in rows])), 4) if pos.any() else None,
        "auc_rules_only": round(float(roc_auc_score(y, [r["floor"] for r in rows])), 4) if pos.any() else None,
        "llm_cases": len(llm_ids),
        "lock_policy": dict(investigator.LOCK_POLICY),
        "takeover_actions": {k: int(((act == k) & pos).sum()) for k in ("allow", "step_up", "lock")},
        "rule_hits_on_takeovers": {},
    }
    for r in rows:
        if r["e"]["label"]:
            for h in r["hits"]:
                m["rule_hits_on_takeovers"][h["code"]] = m["rule_hits_on_takeovers"].get(h["code"], 0) + 1
    name = "rba_metrics" + ("" if threat_intel else "_no_ti") + ("_llm" if llm_ids else "") + ".json"
    (OUT / name).write_text(json.dumps(m, indent=1), encoding="utf-8")
    ato = [{"user": r["e"]["user_id"], "ts": r["e"]["ts"], "country": r["e"]["country"],
            "device_type": r["e"]["device_type"], "success": r["e"]["success"], "action": r["action"],
            "final": r["final"], "floor": r["floor"], "anomaly": r["anomaly"],
            "rules": [h["code"] for h in r["hits"]]} for r in rows if r["e"]["label"]]
    (OUT / name.replace("metrics", "takeovers")).write_text(json.dumps(ato, indent=1), encoding="utf-8")
    if name == "rba_metrics.json":  # per-login scores for the dashboard's visual tab
        pd.DataFrame([{
            "ts": r["e"]["ts"], "country": r["e"]["country"], "device_type": r["e"]["device_type"],
            "success": r["e"]["success"], "label": r["e"]["label"], "action": r["action"],
            "final": r["final"], "anomaly": r["anomaly"], "floor": r["floor"],
            "rules": ";".join(h["code"] for h in r["hits"]),
            **{k: r["f"][k] for k in ("new_device", "new_country", "new_asn", "threat_ip", "failed_logins",
                                     "country_rarity", "asn_rarity", "profile_maturity", "hours_since_last")},
        } for r in rows]).to_csv(OUT / "rba_scored.csv.gz", index=False, compression="gzip")
    print(json.dumps(m, indent=1))
    return m


def sweep():
    """Trade-off curve for the dashboard: how lock budget moves catches vs. false locks."""
    keep = ("takeovers_challenged_or_locked_pct", "takeovers_locked_pct", "legit_allowed_silently_pct",
            "legit_step_up_pct", "legit_locked_pct", "auc_final", "lock_policy")
    out = []
    for label, kw in [("no blending", dict(blend=False)), ("target 0.05%", dict(budget=0.0005)),
                      ("target 0.2%", dict(budget=0.002)), ("target 0.4%", dict(budget=0.004)),
                      ("no threat intel", dict(threat_intel=False)), ("target 0.1% (default)", dict())]:
        m = evaluate(**kw)
        out.append({"setting": label} | {k: m[k] for k in keep})
    (OUT / "rba_sweep.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"wrote {OUT / 'rba_sweep.json'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["sample", "eval", "sweep"])
    ap.add_argument("--no-threat-intel", action="store_true")
    ap.add_argument("--llm", type=int, default=0)
    ap.add_argument("--no-blend", action="store_true", help="anomaly score may never lock")
    ap.add_argument("--budget", type=float, default=0.001, help="target share of (unlabeled) training logins the anomaly may lock; lands ~2x on eval")
    a = ap.parse_args()
    if a.cmd == "sample":
        sample()
    elif a.cmd == "sweep":
        sweep()
    else:
        evaluate(threat_intel=not a.no_threat_intel, llm_n=a.llm, blend=not a.no_blend, budget=a.budget)


if __name__ == "__main__":
    main()
