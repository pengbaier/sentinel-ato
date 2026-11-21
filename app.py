"""Sentinel dashboard.  Run:  streamlit run app.py"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from sentinel import integrations as ix
from sentinel import investigator, viz
from sentinel.pipeline import DATA, build, decide, metrics

st.set_page_config(page_title="Sentinel · ATO defense", page_icon="🛡️", layout="wide")

ACTION_BADGE = {"allow": "🟢 allow", "step_up": "🟡 step-up MFA", "lock": "🔴 lock + notify owner"}


@st.cache_resource(show_spinner="Training baselines and scoring the live window…")
def load_system():
    if not (DATA / "events.jsonl").exists():  # fresh clone: synthesize the scenario data first (~5 s)
        from sentinel.data_gen import Gen
        Gen().run(DATA)
    s, results = build(use_llm=False, verbose=False)
    return s, results


def ts(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%m-%d %H:%M:%S")


sentinel, results = load_system()
by_id = {c["case_id"]: c for c in results}

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.title("🛡️ Sentinel")
    st.caption("Catches the bad cases, clears the good ones, and can't be talked out of it.")
    st.subheader("Integrations")
    st.write(("✅" if ix.llm_enabled() else "⚪") + f" Nicrron gateway: `{ix.NICRRON_MODEL}`")
    st.write(("✅" if ix.prism_enabled() else "⚪") + " PRISM tracing + injection guardrail")
    if not ix.llm_enabled():
        st.info("No NICRRON_API_KEY: the offline analyst stands in for the AI. Add keys to .env to go live.")
    st.subheader("How a verdict is made")
    st.markdown(
        "1. **Rules** set a risk *floor*\n"
        "2. **Per-user anomaly model** scores how unlike *this user* it is\n"
        "3. **AI investigator** explains, may raise risk, **cannot go below the floor**\n"
        "4. **Policy engine** (code, not the AI) picks the action\n"
        "5. Within an open case, risk only goes **up**")

tab_feed, tab_chat, tab_red, tab_real, tab_viz, tab_eval = st.tabs(
    ["📡 Live cases", "💬 Attacker chat (try to talk it down)", "🧨 Red team",
     "🌍 Real-data benchmark", "🔥 Visual insights", "📊 Synthetic evaluation"])

# ------------------------------------------------------------------ live feed
with tab_feed:
    m = metrics(results)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Takeovers caught", f"{m['caught']}/{m['ato_cases']}", f"{m['caught_pct']}%")
    c2.metric("Legit sessions cleared silently", f"{m['good_cleared_pct']}%")
    c3.metric("Legit users locked", f"{m['false_lock_pct']}%")
    c4.metric("Legit users asked for MFA", f"{m['step_up_pct']}%")

    df = pd.DataFrame([{
        "time": ts(c["events"][0]["ts"]), "case": c["case_id"], "user": c["user_id"],
        "action": ACTION_BADGE[c["action"]], "risk": c["final_risk"], "floor": c["floor"],
        "anomaly": c["anomaly_risk"], "rules": ", ".join(h["code"] for h in c["hits"]),
        "truth": c["scenario"] + (" (ATO)" if c["label"] else ""),
    } for c in results])
    show = st.radio("Show", ["Flagged + look-alikes", "Everything"], horizontal=True)
    if show != "Everything":
        df = df[(df["risk"] >= 25) | (df["truth"] != "normal")]
    df = df.sort_values("risk", ascending=False)
    st.dataframe(df, width="stretch", hide_index=True, height=300)

    pick = st.selectbox("Open case", df["case"].tolist(),
                        format_func=lambda x: f"{x} · {by_id[x]['scenario']} · risk {by_id[x]['final_risk']}")
    if pick:
        c = by_id[pick]
        a, b = st.columns([3, 2])
        with a:
            st.markdown(f"### {ACTION_BADGE[c['action']]} · risk **{c['final_risk']}**")
            st.caption(f"user {c['user_id']} · ground truth: {c['scenario']} — {c['note']}")
            tl = pd.DataFrame([{
                "time": ts(e["ts"]), "event": e["type"] + ("" if e["success"] else " ✗"),
                "where": f"{e['city']}, {e['country']}", "network": e["asn_name"] + (" (DC)" if e["hosting"] else ""),
                "device": e["device_id"], "detail": e.get("text") or e.get("new_value") or
                (f"${e['amount']:,.0f} → {e['beneficiary']}" if "amount" in e else ""),
            } for e in c["events"]])
            st.dataframe(tl, width="stretch", hide_index=True)
            st.markdown("**Rule hits (floor)**")
            for h in c["hits"] or [{"code": "none", "floor": 0, "why": "no deterministic rule fired"}]:
                st.write(f"`{h['code']}` floor {h['floor']} — {h['why']}")
        with b:
            ai = c["ai"]
            st.markdown(f"**Investigator** (`{ai.get('engine')}`): verdict **{ai['verdict']}**")
            st.progress(c["final_risk"] / 100, text=f"floor {c['floor']} · anomaly {c['anomaly_risk']} · final {c['final_risk']}")
            if ai.get("floor_enforced"):
                st.warning(f"AI suggested {ai['ai_raw_risk']}, raised to the rule floor {c['floor']}.")
            if ai.get("manipulation_detected"):
                st.error("Manipulation attempt detected in user text")
            for ev in ai.get("evidence", []):
                st.write("• " + ev)
            for be in ai.get("benign_explanations", []):
                st.write("✓ " + be)
            if ix.llm_enabled() and st.button("Re-investigate with the deep model", key="deep"):
                case = sentinel.build_case(c["events"])
                ai2 = investigator.investigate(case, use_llm=True, deep=True)
                st.json(ai2)
            with st.expander("Features"):
                st.json(c["features"])

# ------------------------------------------------------------------ attacker chat
with tab_chat:
    st.markdown("Pick a locked takeover. You are the attacker in the support chat. "
                "Every message is re-scored; within a case **risk can only go up**.")
    locked = [c for c in results if c["action"] == "lock"]
    sel = st.selectbox("Account under attack", [c["case_id"] for c in locked],
                       format_func=lambda x: f"{by_id[x]['user_id']} · {by_id[x]['scenario']} · risk {by_id[x]['final_risk']}",
                       key="atk_case")
    state = st.session_state.setdefault("chats", {})
    conv = state.setdefault(sel, {"msgs": [], "risk": by_id[sel]["final_risk"]})
    for role, text in conv["msgs"]:
        st.chat_message(role).write(text)
    st.metric("Current risk (monotonic)", conv["risk"])
    msg = st.chat_input("Say anything to get the account unlocked…")
    if msg:
        conv["msgs"].append(("user", msg))
        attacker_lines = [t for r, t in conv["msgs"] if r == "user"]
        c = sentinel.score(by_id[sel]["events"], use_llm=ix.llm_enabled(), extra_chat=attacker_lines,
                           update_profile=False)
        new_risk = max(conv["risk"], c["final_risk"])
        conv["risk"] = new_risk
        action = decide(new_risk, c["hits"])
        flags = []
        if c["ai"].get("manipulation_detected"):
            flags.append("manipulation detected")
        if c["ai"].get("floor_enforced"):
            flags.append(f"AI suggested {c['ai']['ai_raw_risk']}, floor held at {c['floor']}")
        reply = (f"**{ACTION_BADGE[action]}** · risk {new_risk}"
                 + (f" · _{'; '.join(flags)}_" if flags else "")
                 + "\n\nI can't change account access through chat. If this is your account, "
                   "use the recovery link we sent to the email and device already on file.")
        conv["msgs"].append(("assistant", reply))
        st.rerun()

# ------------------------------------------------------------------ red team
with tab_red:
    found = False
    for name in ("redteam_llm.json", "redteam.json"):
        p = DATA / name
        if p.exists():
            found = True
            rt = json.loads(p.read_text(encoding="utf-8"))
            s = rt["summary"]
            st.subheader(f"{name} — engine: {s['engine']}")
            k1, k2, k3 = st.columns(3)
            k1.metric("Verdict held", f"{s['verdict_held']}/{s['attempts']}", f"{s['held_pct']}%")
            k2.metric("Manipulation flagged", f"{s['manipulation_flagged_pct']}%")
            k3.metric("AI raw opinion swayed (>10 pts)", s["model_raw_opinion_swayed"])
            st.dataframe(pd.DataFrame(rt["rows"]), width="stretch", hide_index=True, height=350)
    if not found:
        st.info("Run `python -m sentinel.redteam` to generate results.")

# ------------------------------------------------------------------ real-data benchmark
def _load(name):
    p = DATA / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


with tab_real:
    rm, rm_ti, sweep, ato = (_load("rba_metrics.json"), _load("rba_metrics_no_ti.json"),
                             _load("rba_sweep.json"), _load("rba_takeovers.json"))
    if not rm:
        st.info("Run `python -m sentinel.rba sample` then `python -m sentinel.rba eval`.")
    else:
        st.markdown(
            "**Login Data Set for Risk-Based Authentication** — 33M logins / 3.3M users of a large Norwegian "
            "online service (single sign-on to cloud storage and billing), Feb 2020–Feb 2021. "
            "Takeover labels come from the service's incident-response team; IPs, user agents and "
            "round-trip times were re-generated by the authors for privacy. Logins only: no resets, "
            "email changes or payouts, so session rules can't fire here.")
        st.caption(f"Sample: {rm['eval_logins']:,} evaluated logins · {rm['takeover_logins']} takeover logins · "
                   f"{rm['legit_successful_logins']:,} legitimate successful logins. Users split in half: "
                   "one half trains the anomaly model and sets lock thresholds without labels, "
                   "the other half (plus every takeover user) is scored.")
        k = st.columns(5)
        k[0].metric("Takeovers challenged or locked", f"{rm['takeovers_challenged_or_locked_pct']}%")
        k[1].metric("Takeovers locked", f"{rm['takeovers_locked_pct']}%")
        k[2].metric("Legit logins silent", f"{rm['legit_allowed_silently_pct']}%")
        k[3].metric("Legit logins locked", f"{rm['legit_locked_pct']}%")
        k[4].metric("Ranking quality (AUC)", rm["auc_final"])

        a, b = st.columns([3, 2])
        with a:
            st.subheader("Trade-off: how much legitimate friction buys how many locks")
            if sweep:
                sw = pd.DataFrame([{
                    "setting": s["setting"],
                    "takeovers locked %": s["takeovers_locked_pct"],
                    "takeovers challenged or locked %": s["takeovers_challenged_or_locked_pct"],
                    "legit locked %": s["legit_locked_pct"],
                    "legit MFA %": s["legit_step_up_pct"],
                    "AUC": s["auc_final"],
                } for s in sweep])
                st.dataframe(sw, width="stretch", hide_index=True)
                st.scatter_chart(sw, x="legit locked %", y="takeovers locked %", color="setting", height=260)
            else:
                st.info("Run `python -m sentinel.rba sweep` for the trade-off table.")
        with b:
            st.subheader("What happened to each takeover")
            ta = rm.get("takeover_actions", {})
            st.bar_chart(pd.DataFrame({"takeover logins": [ta.get("lock", 0), ta.get("step_up", 0), ta.get("allow", 0)]},
                                      index=["🔴 locked", "🟡 MFA challenge", "🟢 missed"]), height=220)
            st.markdown("**Rules that fired on takeovers**")
            st.write(rm.get("rule_hits_on_takeovers", {}))
            if rm_ti:
                st.markdown(f"Without the threat-intel IP feed: **{rm_ti['takeovers_challenged_or_locked_pct']}%** "
                            f"challenged or locked, **{rm_ti['takeovers_locked_pct']}%** locked, "
                            f"**{rm_ti['legit_locked_pct']}%** legit locked.")

        if ato:
            with st.expander(f"All {len(ato)} takeover logins"):
                adf = pd.DataFrame(ato)
                adf["time"] = adf["ts"].map(ts)
                adf["action"] = adf["action"].map(ACTION_BADGE)
                adf["rules"] = adf["rules"].map(", ".join)
                st.dataframe(adf[["time", "user", "country", "device_type", "action", "final", "floor",
                                  "anomaly", "rules"]].sort_values("final"), width="stretch", hide_index=True)
        st.caption("Misses are successful logins that look exactly like the owner (same country, device, network). "
                   "Catching them needs post-login behaviour this dataset doesn't have. "
                   "Source: Wiefling et al., ACM TOPS 2022, doi:10.1145/3546069 (CC BY 4.0).")

# ------------------------------------------------------------------ visual insights
@st.cache_data(show_spinner="Loading real-data scores…")
def load_viz_data():
    scored = pd.read_csv(DATA / "rba_scored.csv.gz") if (DATA / "rba_scored.csv.gz").exists() else None
    sample = (pd.read_csv(DATA / "rba_sample.csv.gz", usecols=["Login Timestamp", "Is Account Takeover"])
              if (DATA / "rba_sample.csv.gz").exists() else None)
    return scored, sample


with tab_viz:
    scored, sample = load_viz_data()
    section = st.segmented_control(
        "View", ["Real logins", "Synthetic scenarios", "Red team"], default="Real logins",
        label_visibility="collapsed")

    if section == "Real logins":
        if scored is None:
            st.info("Run `python -m sentinel.rba eval` to export per-login scores.")
        else:
            st.subheader("1 · Did the right people get stopped?")
            st.caption("Each row sums to 100%. The top-left cell is takeovers locked; the middle-right cell is legitimate users wrongly locked.")
            st.altair_chart(viz.decision_matrix(scored), width="stretch")

            c1, c2 = st.columns([3, 2])
            with c1:
                st.subheader("2 · Fingerprint of every takeover")
                st.caption("One row per takeover login, one column per signal; darker = stronger. "
                           "Locked takeovers light up on threat-intel and anomaly; the missed ones at the bottom "
                           "are nearly blank, meaning they look exactly like the owner.")
                st.altair_chart(viz.takeover_fingerprint(scored), width="stretch")
            with c2:
                st.subheader("3 · How far apart are the scores?")
                st.caption("Final risk for legitimate vs. takeover logins, each normalised to 100%. "
                           "MFA starts at 30, lock at 70.")
                st.altair_chart(viz.risk_separation(scored), width="content")

            st.subheader("4 · When do takeovers happen?")
            if sample is not None:
                st.caption("Hour × weekday for every login in the sample (left) and for the 141 takeover logins (right). "
                           "Hover a cell for counts and the rate per 100k logins.")
                st.altair_chart(viz.when_heatmaps(sample), width="stretch")

            c3, c4 = st.columns([3, 2])
            with c3:
                st.subheader("5 · Country risk profile")
                st.caption("Busiest countries plus every country with a takeover. Each column is shaded against its own "
                           "maximum, and the real value is printed in the cell.")
                st.altair_chart(viz.country_profile(scored), width="stretch")
            with c4:
                st.subheader("6 · The lock-budget trade-off")
                sweep = _load("rba_sweep.json")
                if sweep:
                    st.caption("Each point is a lock budget. Left of the dashed line = at most 0.2% of legitimate logins locked. "
                               "The diamond is the default with the threat-intel feed switched off.")
                    st.altair_chart(viz.tradeoff_curve(sweep), width="stretch")
                else:
                    st.info("Run `python -m sentinel.rba sweep`.")

    elif section == "Synthetic scenarios":
        st.subheader("Which rule catches which attack, and do look-alikes stay clean?")
        st.caption("% of cases in each scenario where a rule fired (background traffic excluded). "
                   "The Truth column on the left marks takeovers (orange) and legitimate look-alikes (blue).")
        st.altair_chart(viz.scenario_rule_heatmap(results), width="stretch")
        st.subheader("Risk ladder")
        st.caption("Every case's final risk; the shaded zones are the policy bands. Takeovers should sit in the red zone "
                   "and look-alikes in the green.")
        st.altair_chart(viz.risk_ladder(results), width="stretch")

    else:
        rt = _load("redteam_llm.json") or _load("redteam.json")
        if not rt:
            st.info("Run `python -m sentinel.redteam --llm`.")
        else:
            s = rt["summary"]
            st.subheader("Could the attacker talk the AI down?")
            st.caption(f"Engine: {s['engine']}. Each cell = the AI's own risk with that message minus its risk without it. "
                       "Red = the message talked the AI down; ⛨ = it dropped ≥10 points and the rule floor held anyway. "
                       "Blue = the AI treated the message as a red flag and raised risk, which is the right reaction on clean accounts. "
                       f"Verdict held in {s['verdict_held']}/{s['attempts']} attempts.")
            st.altair_chart(viz.redteam_heatmap(rt), width="stretch")

# ------------------------------------------------------------------ eval
with tab_eval:
    st.dataframe(pd.DataFrame(metrics(results)["by_scenario"]).T, width="stretch")
    st.caption("Synthetic data. Rules were written with these scenario families in mind, so treat "
               "100% recall as an upper bound; the honest test is held-out scenario variants.")
