"""Altair charts for the dashboard's Visual insights tab.

Colour by job (validated with the dataviz skill's palette checker):
  * identity  - legit = blue #2a78d6, takeover = orange #eb6834 (CVD dE 24.7, pass)
  * magnitude - one-hue sequential ramps (blue; orange for takeover-only views)
  * polarity  - diverging red <-> gray <-> blue (red = AI talked down, blue = AI raised)
  * state     - status green/amber/red for allow/MFA/lock, always with an icon + label
"""
from __future__ import annotations

import altair as alt
import numpy as np
import pandas as pd

BLUE = ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]
ORANGE = ["#fde4d8", "#f6a582", "#eb6834", "#b84a1d", "#7a2e0f"]
DIVERGING = ["#e34948", "#f0efec", "#2a78d6"]
TRUTH = {"Legitimate": "#2a78d6", "Takeover": "#eb6834"}
ACTION_LABEL = {"allow": "🟢 allow", "step_up": "🟡 MFA challenge", "lock": "🔴 lock"}
ACTION_COLOR = {"🟢 allow": "#0ca30c", "🟡 MFA challenge": "#fab219", "🔴 lock": "#d03b3b"}
DOW = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

_AX = dict(labelColor="#888780", titleColor="#888780", gridOpacity=0.25, domainOpacity=0.3, tickOpacity=0.3)


def _cfg(c: alt.Chart) -> alt.Chart:
    return c.configure_axis(**_AX).configure_view(stroke=None).configure_legend(
        labelColor="#888780", titleColor="#888780", orient="top")


def _text_on(color_field: str, threshold: float, dark="#0b0b0b", light="#ffffff"):
    """Readable cell text: light ink on dark cells, dark ink on light cells."""
    return alt.condition(f"datum['{color_field}'] > {threshold}", alt.value(light), alt.value(dark))


# ======================================================================= real data
def when_heatmaps(sample: pd.DataFrame) -> alt.Chart:
    """Hour x weekday: all login volume (blue) beside takeover logins (orange)."""
    t = pd.to_datetime(sample["Login Timestamp"])
    d = pd.DataFrame({"hour": t.dt.hour, "dow": t.dt.dayofweek.map(dict(enumerate(DOW))),
                      "ato": sample["Is Account Takeover"].astype(int)})
    g = d.groupby(["dow", "hour"]).agg(logins=("ato", "size"), takeovers=("ato", "sum")).reset_index()
    g["rate"] = (g["takeovers"] / g["logins"] * 100_000).round(1)
    base = alt.Chart(g).encode(
        x=alt.X("hour:O", title="Hour of day (UTC; Norway = UTC+1)", axis=alt.Axis(labelAngle=0, values=list(range(0, 24, 3)))),
        y=alt.Y("dow:O", sort=DOW, title=None),
        tooltip=[alt.Tooltip("dow:N", title="Day"), alt.Tooltip("hour:O", title="Hour"),
                 alt.Tooltip("logins:Q", format=","), alt.Tooltip("takeovers:Q"),
                 alt.Tooltip("rate:Q", title="Takeovers per 100k logins")])
    left = base.mark_rect(cornerRadius=3, stroke="white", strokeWidth=2).encode(
        color=alt.Color("logins:Q", scale=alt.Scale(range=BLUE), title="All logins")
    ).properties(title="Every login", height=230)
    right = base.mark_rect(cornerRadius=3, stroke="white", strokeWidth=2).encode(
        color=alt.Color("takeovers:Q", scale=alt.Scale(range=ORANGE), title="Takeover logins")
    ).properties(title="Account takeovers", height=230)
    return _cfg(alt.hconcat(left, right).resolve_scale(color="independent"))


def decision_matrix(scored: pd.DataFrame) -> alt.Chart:
    """Truth x action, colour = share of that truth row."""
    s = scored.copy()
    s["truth"] = np.where(s["label"] == 1, "Takeover",
                          np.where(s["success"], "Legitimate (successful)", "Legitimate (failed attempt)"))
    s["action"] = s["action"].map(ACTION_LABEL)
    g = s.groupby(["truth", "action"]).size().rename("n").reset_index()
    g["share"] = g["n"] / g.groupby("truth")["n"].transform("sum") * 100
    g["label"] = g.apply(lambda r: f"{r.share:.1f}%  ({r.n:,})", axis=1)
    order_y = ["Takeover", "Legitimate (successful)", "Legitimate (failed attempt)"]
    order_x = list(ACTION_LABEL.values())
    base = alt.Chart(g).encode(x=alt.X("action:N", sort=order_x, title="Sentinel's decision", axis=alt.Axis(labelAngle=0, orient="top")),
                               y=alt.Y("truth:N", sort=order_y, title=None, axis=alt.Axis(labelLimit=260, labelFontSize=12)))
    rect = base.mark_rect(cornerRadius=4, stroke="white", strokeWidth=2).encode(
        color=alt.Color("share:Q", scale=alt.Scale(range=BLUE, domain=[0, 100]), title="% of row",
                        legend=alt.Legend(orient="right")),
        tooltip=["truth", "action", alt.Tooltip("n:Q", format=",", title="logins"), alt.Tooltip("share:Q", format=".2f", title="% of row")])
    text = base.mark_text(fontSize=13, fontWeight=600).encode(text="label:N", color=_text_on("share", 45))
    return _cfg((rect + text).properties(height=alt.Step(52)))


def risk_separation(scored: pd.DataFrame) -> alt.Chart:
    """Distribution of final risk per truth group, each normalised to 100% (small multiples, shared x)."""
    s = scored[(scored["label"] == 1) | scored["success"]].copy()
    s["truth"] = np.where(s["label"] == 1, "Takeover", "Legitimate")
    s["bin"] = (s["final"] // 10 * 10).clip(0, 100).astype(int)
    g = s.groupby(["truth", "bin"]).size().rename("n").reset_index()
    g["share"] = g["n"] / g.groupby("truth")["n"].transform("sum") * 100
    bars = alt.Chart(g).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=26).encode(
        x=alt.X("bin:O", title="Final risk score (bucket start)", axis=alt.Axis(labelAngle=0)),
        y=alt.Y("share:Q", title="% of group"),
        color=alt.Color("truth:N", scale=alt.Scale(domain=list(TRUTH), range=list(TRUTH.values())), legend=None),
        tooltip=["truth", alt.Tooltip("bin:O", title="risk ≥"), alt.Tooltip("n:Q", format=",", title="logins"),
                 alt.Tooltip("share:Q", format=".2f", title="% of group")])
    return _cfg(alt.layer(bars).properties(height=150, width=320).facet(
        row=alt.Row("truth:N", sort=["Legitimate", "Takeover"], title=None,
                    header=alt.Header(labelAngle=0, labelAlign="left", labelColor="#888780")))
        .resolve_scale(y="independent"))


SIGNALS = [("new_device", "New device"), ("new_country", "New country"), ("new_asn", "New network"),
           ("threat_ip", "Threat-intel IP"), ("failed_logins", "Recent failed logins"),
           ("country_rarity", "Rare country"), ("asn_rarity", "Rare network"),
           ("anomaly", "Anomaly score"), ("floor", "Rule floor"), ("final", "Final risk")]


def takeover_fingerprint(scored: pd.DataFrame) -> alt.Chart:
    """One row per takeover login, one column per signal: which evidence each attack left behind."""
    a = scored[scored["label"] == 1].copy()
    a["action_l"] = a["action"].map(ACTION_LABEL)
    order = {"lock": 0, "step_up": 1, "allow": 2}
    a = a.sort_values(["action", "final"], key=lambda c: c.map(order) if c.name == "action" else -c)
    a["row"] = [f"#{i+1:02d} {c}" for i, c in enumerate(a["country"])]
    rows = []
    for _, r in a.iterrows():
        for k, name in SIGNALS:
            v = float(r[k])
            norm = {"failed_logins": min(v / 5, 1), "country_rarity": min(v / 4, 1), "asn_rarity": min(v / 5, 1),
                    "anomaly": v / 100, "floor": v / 100, "final": v / 100}.get(k, v)
            rows.append({"row": r["row"], "signal": name, "strength": norm, "value": v,
                         "action": r["action_l"], "rules": r["rules"] or "—"})
    d = pd.DataFrame(rows)
    dec = d.drop_duplicates("row").assign(signal="Decision")
    sig_order = ["Decision"] + [n for _, n in SIGNALS]
    # one shared x/y so the decision column lines up row-for-row with the signals
    x = alt.X("signal:N", sort=sig_order, title=None,
              axis=alt.Axis(orient="top", labelAngle=-35, labelOverlap=False, labelLimit=140))
    y = alt.Y("row:N", sort=list(a["row"]), title=None, axis=alt.Axis(labels=False, ticks=False, domain=False))
    heat = alt.Chart(d).mark_rect(stroke="white", strokeWidth=1.5, cornerRadius=2).encode(
        x=x, y=y, color=alt.Color("strength:Q", scale=alt.Scale(range=BLUE, domain=[0, 1]), title="Signal strength",
                                  legend=alt.Legend(orient="top", gradientLength=160)),
        tooltip=["row", "signal", alt.Tooltip("value:Q", format=".2f"), "action", "rules"])
    strip = alt.Chart(dec).mark_rect(stroke="white", strokeWidth=1.5).encode(
        x=x, y=y, color=alt.Color("action:N", scale=alt.Scale(domain=list(ACTION_COLOR), range=list(ACTION_COLOR.values())),
                                  title="Decision", legend=alt.Legend(orient="top")),
        tooltip=["row", "action", "rules"])
    return _cfg(alt.layer(strip, heat).resolve_scale(color="independent").properties(
        height=alt.Step(7), title=alt.TitleParams(
            f"{len(a)} takeover logins · sorted locked → challenged → missed", anchor="start", color="#888780")))


def country_profile(scored: pd.DataFrame, top=14) -> alt.Chart:
    """Countries x metrics, each metric column scaled to its own max, true values printed in the cell."""
    s = scored.copy()
    g = s.groupby("country").agg(logins=("label", "size"), takeovers=("label", "sum"),
                                 threat=("threat_ip", "mean"), locked=("action", lambda x: (x == "lock").mean()),
                                 challenged=("action", lambda x: (x == "step_up").mean())).reset_index()
    pick = pd.concat([g.nlargest(top, "logins"), g[g["takeovers"] > 0]]).drop_duplicates("country")
    pick = pick.sort_values("logins", ascending=False)
    metrics = [("logins", "Logins", "{:,.0f}"), ("takeovers", "Takeover logins", "{:.0f}"),
               ("threat", "Threat-IP share", "{:.0%}"), ("challenged", "MFA rate", "{:.1%}"),
               ("locked", "Lock rate", "{:.2%}")]
    rows = []
    for _, r in pick.iterrows():
        for k, name, fmt in metrics:
            mx = pick[k].max() or 1
            rows.append({"country": r["country"], "metric": name, "rel": r[k] / mx, "txt": fmt.format(r[k])})
    d = pd.DataFrame(rows)
    base = alt.Chart(d).encode(x=alt.X("metric:N", sort=[m[1] for m in metrics], title=None, axis=alt.Axis(orient="top", labelAngle=0)),
                               y=alt.Y("country:N", sort=list(pick["country"]), title=None, axis=alt.Axis(labelOverlap=False)))
    rect = base.mark_rect(stroke="white", strokeWidth=2, cornerRadius=3).encode(
        color=alt.Color("rel:Q", scale=alt.Scale(range=BLUE, domain=[0, 1]), title="Relative to column max"),
        tooltip=["country", "metric", alt.Tooltip("txt:N", title="value")])
    text = base.mark_text(fontSize=11).encode(text="txt:N", color=_text_on("rel", 0.55))
    return _cfg((rect + text).properties(height=alt.Step(24)))


def tradeoff_curve(sweep: list[dict]) -> alt.Chart:
    d = pd.DataFrame([{"setting": s["setting"], "legit": s["legit_locked_pct"], "ato": s["takeovers_locked_pct"],
                       "challenged": s["takeovers_challenged_or_locked_pct"]} for s in sweep])
    blended = d[d["setting"].str.startswith(("target", "no blending"))].sort_values("legit")
    line = alt.Chart(blended).mark_line(strokeWidth=2, color="#2a78d6", point=alt.OverlayMarkDef(size=90, filled=True, color="#2a78d6")).encode(
        x=alt.X("legit:Q", title="Legitimate logins locked (%)"),
        y=alt.Y("ato:Q", title="Takeover logins locked (%)", scale=alt.Scale(domain=[0, 100])),
        tooltip=["setting", alt.Tooltip("legit:Q", title="legit locked %"), alt.Tooltip("ato:Q", title="takeovers locked %"),
                 alt.Tooltip("challenged:Q", title="takeovers challenged or locked %")])
    lab = blended[blended["setting"].isin(["no blending", "target 0.1% (default)", "target 0.4%"])].copy()
    lab["dy"] = [14, -12, -12][: len(lab)]
    labels = alt.Chart(lab).mark_text(align="left", dx=8, fontSize=11, color="#888780").encode(
        x="legit:Q", y="ato:Q", text="setting:N", yOffset="dy:Q")
    noti = alt.Chart(d[d["setting"] == "no threat intel"]).mark_point(shape="diamond", size=110, filled=True, color="#eb6834").encode(
        x="legit:Q", y="ato:Q", tooltip=["setting", "legit", "ato"])
    noti_l = alt.Chart(d[d["setting"] == "no threat intel"]).mark_text(align="left", dx=8, fontSize=11, color="#888780").encode(
        x="legit:Q", y="ato:Q", text="setting:N")
    ceiling = alt.Chart(pd.DataFrame({"x": [0.2]})).mark_rule(strokeDash=[4, 4], color="#888780").encode(x="x:Q")
    return _cfg((ceiling + line + labels + noti + noti_l).properties(height=320))


# ======================================================================= synthetic
def scenario_rule_heatmap(results: list[dict]) -> alt.Chart:
    rows = []
    for c in results:
        if c["scenario"] == "normal":
            continue
        codes = {h["code"] for h in c["hits"]} or {"(no rule)"}
        for code in codes:
            rows.append({"scenario": c["scenario"], "label": c["label"], "rule": code, "case": c["case_id"]})
    d = pd.DataFrame(rows)
    n = pd.DataFrame([{"scenario": c["scenario"], "case": c["case_id"]} for c in results if c["scenario"] != "normal"]
                     ).groupby("scenario").size().rename("n")
    g = d.groupby(["scenario", "label", "rule"]).size().rename("hits").reset_index().join(n, on="scenario")
    g["share"] = g["hits"] / g["n"] * 100
    g["kind"] = np.where(g["label"] == 1, "Takeover", "Look-alike (legit)")
    scen_order = list(g.sort_values(["label", "scenario"], ascending=[False, True])["scenario"].drop_duplicates())
    rule_order = list(g.groupby("rule")["hits"].sum().sort_values(ascending=False).index)
    truth = g.drop_duplicates("scenario").assign(rule="Truth")
    x = alt.X("rule:N", sort=["Truth"] + rule_order, title=None,
              axis=alt.Axis(orient="top", labelAngle=-35, labelOverlap=False, labelLimit=200))
    y = alt.Y("scenario:N", sort=scen_order, title=None, axis=alt.Axis(labelOverlap=False))
    rect = alt.Chart(g).mark_rect(stroke="white", strokeWidth=2, cornerRadius=3).encode(
        x=x, y=y, color=alt.Color("share:Q", scale=alt.Scale(range=BLUE, domain=[0, 100]), title="% of cases"),
        tooltip=["scenario", "kind", "rule", alt.Tooltip("share:Q", format=".0f", title="% of cases"), "hits", "n"])
    text = alt.Chart(g).mark_text(fontSize=11).encode(
        x=x, y=y, text=alt.Text("share:Q", format=".0f"), color=_text_on("share", 55))
    side = alt.Chart(truth).mark_rect(stroke="white", strokeWidth=2, cornerRadius=3).encode(
        x=x, y=y, color=alt.Color("kind:N", scale=alt.Scale(domain=["Takeover", "Look-alike (legit)"],
                                                            range=["#eb6834", "#2a78d6"]), title="Truth"),
        tooltip=["scenario", "kind"])
    return _cfg(alt.layer(side, rect, text).resolve_scale(color="independent").properties(height=alt.Step(30)))


def risk_ladder(results: list[dict]) -> alt.Chart:
    d = pd.DataFrame([{"scenario": c["scenario"], "risk": c["final_risk"], "action": ACTION_LABEL[c["action"]],
                       "truth": "Takeover" if c["label"] else "Legitimate", "case": c["case_id"]} for c in results])
    order = list(d.groupby("scenario")["risk"].median().sort_values(ascending=False).index)
    band = alt.Chart(pd.DataFrame([{"a": 0, "b": 30, "z": "🟢 allow"}, {"a": 30, "b": 70, "z": "🟡 MFA challenge"},
                                   {"a": 70, "b": 100, "z": "🔴 lock"}])).mark_rect(opacity=0.08).encode(
        x="a:Q", x2="b:Q", color=alt.Color("z:N", scale=alt.Scale(domain=list(ACTION_COLOR), range=list(ACTION_COLOR.values())), title="Zone"))
    pts = alt.Chart(d).mark_circle(size=70, opacity=0.75, stroke="white", strokeWidth=1).encode(
        x=alt.X("risk:Q", title="Final risk", scale=alt.Scale(domain=[0, 100])),
        y=alt.Y("scenario:N", sort=order, title=None),
        yOffset=alt.YOffset("jitter:Q"),
        color=alt.Color("truth:N", scale=alt.Scale(domain=list(TRUTH), range=list(TRUTH.values())), title="Truth"),
        tooltip=["case", "scenario", "truth", "risk", "action"]).transform_calculate(jitter="random()")
    return _cfg(alt.layer(band, pts).resolve_scale(color="independent").properties(height=380))


# ======================================================================= red team
def redteam_heatmap(rt: dict) -> alt.Chart:
    d = pd.DataFrame(rt["rows"]).copy()
    d["swing"] = d["ai_raw_risk"] - d["base_risk"]
    d["case_l"] = np.where(d["label"] == 1, "ATO · ", "legit · ") + d["scenario"] + " · " + d["case"].str[-4:]
    d["held_l"] = np.where(d["held"], "held", "BROKEN")
    attack_order = list(d.groupby("attack")["swing"].mean().sort_values().index)
    base = alt.Chart(d).encode(x=alt.X("case_l:N", title="Case under attack", axis=alt.Axis(labelAngle=-30, labelOverlap=False, labelLimit=200)),
                               y=alt.Y("attack:N", sort=attack_order, title=None,
                                       axis=alt.Axis(labelLimit=380, labelOverlap=False)))
    rect = base.mark_rect(stroke="white", strokeWidth=1.5, cornerRadius=2).encode(
        color=alt.Color("swing:Q", scale=alt.Scale(range=DIVERGING, domain=[-40, 0, 40], clamp=True, interpolate="lab"),
                        title="AI's own risk vs. no attack"),
        tooltip=["attack", "scenario", alt.Tooltip("base_risk:Q", title="risk without attack"),
                 alt.Tooltip("ai_raw_risk:Q", title="AI's raw risk"), alt.Tooltip("final_risk:Q", title="final (floor-enforced)"),
                 "action", "held_l", "manipulation_flagged"])
    mark = base.transform_filter("datum.swing <= -10").mark_text(text="▼", fontSize=12, color="#14213D")
    return _cfg((rect + mark).properties(height=alt.Step(26)))


# ======================================================================= additions for the demo story
SIGNAL_TESTS = [
    ("New country", lambda s: s["new_country"] == 1),
    ("Anomaly score ≥ 40", lambda s: s["anomaly"] >= 40),
    ("Rare country (population)", lambda s: s["country_rarity"] >= 2),
    ("Rare network (population)", lambda s: s["asn_rarity"] >= 3),
    ("New network", lambda s: s["new_asn"] == 1),
    ("Threat-intel IP", lambda s: s["threat_ip"] == 1),
    ("Rule floor ≥ 40", lambda s: s["floor"] >= 40),
    ("New device", lambda s: s["new_device"] == 1),
    ("Recent failed logins", lambda s: s["failed_logins"] > 0),
]


def signal_lift_table(scored: pd.DataFrame) -> pd.DataFrame:
    legit = scored[(scored["label"] == 0) & scored["success"]]
    ato = scored[scored["label"] == 1]
    rows = []
    for name, f in SIGNAL_TESTS:
        pl, pa = f(legit).mean() * 100, f(ato).mean() * 100
        rows.append({"signal": name, "Legitimate": round(pl, 2), "Takeover": round(pa, 1),
                     "lift": round(pa / max(pl, 0.01), 1)})
    return pd.DataFrame(rows).sort_values("lift", ascending=False)


def signal_lift(scored: pd.DataFrame) -> alt.Chart:
    """Dumbbell: share of legit vs takeover logins showing each signal; the gap is the signal's power."""
    t = signal_lift_table(scored)
    order = list(t["signal"])
    long = t.melt(id_vars=["signal", "lift"], value_vars=["Legitimate", "Takeover"], var_name="truth", value_name="pct")
    y = alt.Y("signal:N", sort=order, title=None, axis=alt.Axis(labelLimit=260, labelOverlap=False))
    rule = alt.Chart(t).mark_rule(color="#B8B5AC", strokeWidth=3).encode(
        y=y, x=alt.X("Legitimate:Q", title="% of logins showing the signal", scale=alt.Scale(domain=[0, 100])), x2="Takeover:Q")
    dots = alt.Chart(long).mark_circle(size=220, opacity=1, stroke="white", strokeWidth=2).encode(
        y=y, x="pct:Q",
        color=alt.Color("truth:N", scale=alt.Scale(domain=list(TRUTH), range=list(TRUTH.values())), title=None,
                        legend=alt.Legend(orient="top")),
        tooltip=["signal", "truth", alt.Tooltip("pct:Q", format=".2f", title="% of logins"),
                 alt.Tooltip("lift:Q", title="× more common in takeovers")])
    lift = alt.Chart(t).mark_text(align="left", dx=12, fontSize=12, color="#888780").encode(
        y=y, x="Takeover:Q", text=alt.Text("lift:Q", format=".0f"))
    lift = lift.transform_calculate(lbl="format(datum.lift, '.0f') + '×'").encode(text="lbl:N")
    return _cfg((rule + dots + lift).properties(height=alt.Step(34)))


def funnel_table(scored: pd.DataFrame) -> pd.DataFrame:
    s = scored[scored["success"] | (scored["label"] == 1)].copy()
    s["pre"] = s[["floor", "anomaly"]].max(axis=1)
    stages = [("Successful logins scored", s.index == s.index),
              ("Triaged (risk ≥ 25)", s["pre"] >= 25),
              ("MFA challenge or lock", s["action"] != "allow"),
              ("Locked", s["action"] == "lock")]
    rows = []
    for i, (name, m) in enumerate(stages):
        rows.append({"stage": f"{i+1}. {name}", "Legitimate": int((m & (s["label"] == 0)).sum()),
                     "Takeover": int((m & (s["label"] == 1)).sum())})
    return pd.DataFrame(rows)


def triage_funnel(scored: pd.DataFrame) -> alt.Chart:
    """How the traffic narrows: legit volume on a log scale beside takeovers kept at each stage."""
    t = funnel_table(scored)
    order = list(t["stage"])
    y = alt.Y("stage:N", sort=order, title=None, axis=alt.Axis(labelLimit=280, labelOverlap=False))
    legit = alt.Chart(t).mark_bar(color=TRUTH["Legitimate"], cornerRadiusEnd=4, height=26).encode(
        y=y, x=alt.X("Legitimate:Q", title="Legitimate logins (log scale)", scale=alt.Scale(type="log", domain=[10, 100000])),
        x2=alt.datum(10),  # log bars need a positive baseline
        tooltip=["stage", alt.Tooltip("Legitimate:Q", format=",")])
    legit_t = alt.Chart(t).mark_text(align="left", dx=6, fontSize=12, color="#888780").encode(
        y=y, x="Legitimate:Q", text=alt.Text("Legitimate:Q", format=","))
    ato = alt.Chart(t).mark_bar(color=TRUTH["Takeover"], cornerRadiusEnd=4, height=26).encode(
        y=alt.Y("stage:N", sort=order, title=None, axis=None),
        x=alt.X("Takeover:Q", title="Takeover logins kept", scale=alt.Scale(domain=[0, 100])),
        tooltip=["stage", "Takeover"])
    ato_t = alt.Chart(t).mark_text(align="left", dx=6, fontSize=12, color="#888780").encode(
        y=alt.Y("stage:N", sort=order, axis=None), x="Takeover:Q", text="Takeover:Q")
    return _cfg(alt.hconcat((legit + legit_t).properties(width=420, height=alt.Step(44)),
                            (ato + ato_t).properties(width=220, height=alt.Step(44)), spacing=16))


def verdict_anatomy(floor: int, anomaly: int, ai_risk: int, final: int, title: str = "") -> alt.Chart:
    """One case: the three opinions and the final max(), against the policy bands."""
    d = pd.DataFrame([{"layer": "1. Rule floor", "risk": floor, "kind": "rules"},
                      {"layer": "2. Anomaly model", "risk": anomaly, "kind": "model"},
                      {"layer": "3. AI investigator", "risk": ai_risk, "kind": "model"},
                      {"layer": "4. Final = max(floor, AI)", "risk": final, "kind": "final"}])
    order = list(d["layer"])
    band = alt.Chart(pd.DataFrame([{"a": 0, "b": 30, "z": "🟢 allow"}, {"a": 30, "b": 70, "z": "🟡 MFA challenge"},
                                   {"a": 70, "b": 100, "z": "🔴 lock"}])).mark_rect(opacity=0.10).encode(
        x="a:Q", x2="b:Q", color=alt.Color("z:N", scale=alt.Scale(domain=list(ACTION_COLOR), range=list(ACTION_COLOR.values())),
                                           title="Policy band", legend=alt.Legend(orient="top")))
    y = alt.Y("layer:N", sort=order, title=None, axis=alt.Axis(labelLimit=260, labelOverlap=False))
    bars = alt.Chart(d).mark_bar(cornerRadiusEnd=4, height=22).encode(
        y=y, x=alt.X("risk:Q", title="Risk (0–100)", scale=alt.Scale(domain=[0, 100])),
        color=alt.Color("kind:N", scale=alt.Scale(domain=["rules", "model", "final"], range=["#6A6862", "#86B6EF", "#14213D"]),
                        legend=None),
        tooltip=["layer", "risk"])
    txt = alt.Chart(d).mark_text(align="left", dx=6, fontSize=13, fontWeight=600, color="#14213D").encode(
        y=y, x="risk:Q", text="risk:Q")
    c = alt.layer(band, bars, txt).resolve_scale(color="independent").properties(height=alt.Step(40))
    return _cfg(c.properties(title=alt.TitleParams(title, anchor="start", color="#888780")) if title else c)


# ======================================================================= numbers for captions
def insights(scored=None, sample=None, results=None, rt=None, sweep=None) -> dict:
    k: dict = {}
    if sample is not None:
        a = sample[sample["Is Account Takeover"]]
        t = pd.to_datetime(a["Login Timestamp"])
        k["ato_total"] = len(a)
        k["ato_weekend_pct"] = round((t.dt.dayofweek >= 5).mean() * 100)
        k["ato_night_pct"] = round(((t.dt.hour + 1) % 24).between(0, 5).mean() * 100)  # 00-06 Norway local (UTC+1)
        ta = pd.to_datetime(sample["Login Timestamp"])
        k["all_night_pct"] = round(((ta.dt.hour + 1) % 24).between(0, 5).mean() * 100)
        k["all_weekend_pct"] = round((ta.dt.dayofweek >= 5).mean() * 100)
    if scored is not None:
        legit = scored[(scored["label"] == 0) & scored["success"]]
        ato = scored[scored["label"] == 1]
        c = ato["country"].value_counts()
        k["top_country"], k["top_country_n"], k["ato_n"] = c.index[0], int(c.iloc[0]), len(ato)
        tc = scored[scored["country"] == c.index[0]]
        k["top_country_logins"] = len(tc)
        k["top_country_threat"] = round(tc["threat_ip"].mean() * 100)
        lt = signal_lift_table(scored)
        k["best_signal"], k["best_lift"] = lt.iloc[0]["signal"], lt.iloc[0]["lift"]
        k["best_legit"], k["best_ato"] = lt.iloc[0]["Legitimate"], lt.iloc[0]["Takeover"]
        k["fails_lift"] = float(lt[lt["signal"] == "Recent failed logins"]["lift"].iloc[0])
        ft = funnel_table(scored)
        k["funnel"] = ft
        k["queue_legit"] = int(ft.iloc[2]["Legitimate"])
        k["queue_pct"] = round(ft.iloc[2]["Legitimate"] / ft.iloc[0]["Legitimate"] * 100, 1)
        k["queue_ato"] = int(ft.iloc[2]["Takeover"])
        k["locked_legit"], k["locked_ato"] = int(ft.iloc[3]["Legitimate"]), int(ft.iloc[3]["Takeover"])
        k["legit_low"] = round((legit["final"] < 30).mean() * 100, 1)
        k["ato_high"] = round((ato["final"] >= 70).mean() * 100, 1)
        k["missed"] = int((ato["action"] == "allow").sum())
    if rt is not None:
        d = pd.DataFrame(rt["rows"])
        k["rt_attempts"], k["rt_held"] = len(d), int(d["held"].sum())
        k["rt_raised"] = int((d["ai_raw_risk"] > d["base_risk"] + 10).sum())
        sw = d[d["ai_raw_risk"] < d["base_risk"] - 10]
        k["rt_lowered"], k["rt_lowered_ato"] = len(sw), int((sw["label"] == 1).sum())
        k["rt_floor_lifted"] = int((d["final_risk"] > d["ai_raw_risk"]).sum())
        k["rt_ato_min_raw"] = int(d[d["label"] == 1]["ai_raw_risk"].min())
    if results is not None:
        k["syn_ato"] = sum(1 for c in results if c["label"] == 1)
        k["syn_caught"] = sum(1 for c in results if c["label"] == 1 and c["action"] != "allow")
        look = [c for c in results if c["label"] == 0 and c["scenario"] != "normal"]
        k["look_n"] = len(look)
        k["look_allowed"] = sum(1 for c in look if c["action"] == "allow")
        k["look_with_rule"] = sum(1 for c in look if c["hits"])
        frict = [c["scenario"] for c in look if c["action"] != "allow"]
        k["look_friction"] = ", ".join(f"{s.replace('_', ' ')} ×{n}" for s, n in pd.Series(frict).value_counts().items()) if frict else "none"
    if sweep:
        lo = min(sweep, key=lambda s: s["legit_locked_pct"]); hi = max(sweep, key=lambda s: s["legit_locked_pct"])
        k["sweep_lo"], k["sweep_hi"] = lo, hi
    return k
