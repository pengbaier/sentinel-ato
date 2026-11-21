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
            st.altair_chart(viz.verdict_anatomy(c["floor"], c["anomaly_risk"], ai["risk"], c["final_risk"]), width="stretch")
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
            rows_df = pd.DataFrame(rt["rows"])
            low = rows_df[rows_df["ai_raw_risk"] < rows_df["base_risk"] - 10]
            k3.metric("AI talked down >10 pts", s["model_raw_opinion_swayed"],
                      f"{int((low['label'] == 1).sum())} on takeover cases", delta_color="off")
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


def chart_block(num: str, headline: str, how: str, say: str, chart, width="stretch"):
    """One chart in the story: a numbered takeaway headline, how to read it, the chart, and demo narration."""
    st.markdown(f"#### {num} · {headline}")
    st.caption("**How to read it:** " + how)
    st.altair_chart(chart, width=width)
    with st.expander("🎤 Say this in the demo"):
        st.markdown(say)


ACTS = ["① The threat", "② Detection", "③ Decisions", "④ Holding the line", "⑤ Scenario lab"]
ACT_THESIS = {
    "① The threat": "What account takeovers look like in real traffic — when they happen and where they come from.",
    "② Detection": "Which signals separate attackers from customers, and how cleanly the scores split.",
    "③ Decisions": "What Sentinel does with those scores — and how little friction good customers feel.",
    "④ Holding the line": "Why the AI can explain and escalate, but can’t be talked into lowering risk.",
    "⑤ Scenario lab": "The full attack playbook — resets, email changes, payouts — on labelled synthetic scenarios.",
}

with tab_viz:
    scored, sample = load_viz_data()
    rt = _load("redteam_llm.json") or _load("redteam.json")
    sweep = _load("rba_sweep.json")
    K = viz.insights(scored, sample, results, rt, sweep)
    act = st.segmented_control("Act", ACTS, default=ACTS[0], label_visibility="collapsed") or ACTS[0]
    st.markdown(f"### {act}")
    st.markdown(ACT_THESIS[act])
    if act != "⑤ Scenario lab":
        st.caption("Real data: public RBA login dataset (Wiefling et al., 2022, CC BY 4.0) — "
                   f"{K.get('ato_n', 0)} takeover and ~76k legitimate successful logins from held-out users.")
    st.divider()

    if scored is None and act in ACTS[:3]:
        st.info("Run `python -m sentinel.rba eval` to export per-login scores.")

    elif act == "① The threat":
        if sample is not None:
            chart_block(
                "1.1", f"Takeovers keep their own hours: {K['ato_night_pct']}% land between midnight and 6 a.m. local time, "
                       f"vs. {K['all_night_pct']}% of all logins",
                "Hour of day × weekday. Left: every login in the sample (blue = volume). Right: the "
                f"{K['ato_total']} takeover logins (orange = count). Hover a cell for counts and the rate per 100k logins.",
                "“Customers log in on a daytime rhythm — the left map is a tidy office-hours block. "
                "Takeovers on the right are scattered across the clock, and the night share is almost double. "
                "Timing alone isn’t proof, so we use it as context, never as a verdict.”",
                viz.when_heatmaps(sample))
        chart_block(
            "1.2", f"One country, {K['top_country']}, accounts for {K['top_country_n']} of {K['ato_n']} takeover logins "
                   f"from just {K['top_country_logins']:,} logins — {K['top_country_threat']}% via known-attacker IPs",
            "Busiest countries plus every country with a takeover. Each column is shaded against its own maximum; "
            "the true value is printed in the cell. Lock rate includes blocked failed attempts.",
            f"“Attacks concentrate. {K['top_country']} is a rounding error in traffic but half the takeovers. "
            "We don’t hard-code ‘block this country’ — that would punish real customers there. "
            "Instead, rarity and threat intelligence feed the score, and the decision stays per login.”",
            viz.country_profile(scored))

    elif act == "② Detection":
        c1, c2 = st.columns([3, 2])
        with c1:
            chart_block(
                "2.1", f"“{K['best_signal']}” is {K['best_lift']:.0f}× more common in takeovers; "
                       f"failed logins barely differ ({K['fails_lift']:.1f}×)",
                "Each row is a signal. Blue dot = share of legitimate logins showing it; orange dot = share of takeovers. "
                "The wider the gap, the more useful the signal; the label is how many times more common it is in takeovers.",
                f"“This is why we compare each login with the user’s own history. A new country appears in "
                f"{K['best_ato']:.0f}% of takeovers but under 1% of real logins. Meanwhile ‘recent failed logins’, "
                "the signal many rule engines lean on, hardly separates the two — people mistype passwords all the time.”",
                viz.signal_lift(scored))
        with c2:
            chart_block(
                "2.2", f"{K['legit_low']}% of legitimate logins score under 30; {K['ato_high']}% of takeovers score 70+",
                "Final risk for legitimate vs. takeover logins, each normalised to 100%. MFA starts at 30, lock at 70.",
                "“Customers pile up near zero. Takeovers bunch at the lock line. "
                "The overlap in the middle is exactly where we challenge instead of lock.”",
                viz.risk_separation(scored), width="content")
        chart_block(
            "2.3", f"Locked takeovers light up on several signals at once; the {K['missed']} missed ones are nearly blank",
            "One row per real takeover login, one column per signal; darker = stronger. "
            "The first column is Sentinel’s decision. Rows are sorted locked → challenged → missed.",
            f"“Read it top to bottom. Locked attacks trip several signals together. Challenged ones trip fewer. "
            f"The {K['missed']} misses at the bottom are blank: same country, device type and network as the owner. "
            "Nothing at login can catch them — that’s our honest limit, and why post-login behaviour is next.”",
            viz.takeover_fingerprint(scored))

    elif act == "③ Decisions":
        chart_block(
            "3.1", f"Only {K['queue_pct']}% of legitimate logins ever meet friction — while {K['queue_ato']} of {K['ato_n']} takeovers do",
            "How traffic narrows at each stage. Left: legitimate logins on a log scale. Right: takeover logins kept. "
            "Stage 3 is what an MFA prompt or an analyst’s queue sees; stage 4 is a hard lock.",
            f"“Out of about {K['funnel'].iloc[0]['Legitimate']:,} real logins, {K['queue_legit']:,} get an MFA prompt and "
            f"{K['locked_legit']} are locked. Of {K['ato_n']} takeovers, {K['queue_ato']} are stopped and {K['locked_ato']} locked outright. "
            "That’s the B2B value: analysts look at a few percent of traffic instead of all of it.”",
            viz.triage_funnel(scored), width="content")
        chart_block(
            "3.2", "Every row sums to 100%: what happened to takeovers, to customers, and to failed attempts",
            "Rows = what really happened; columns = Sentinel’s decision. Top-right is takeovers locked; "
            "middle-right is customers wrongly locked.",
            "“One picture for the judges: half the takeovers locked, another third challenged, "
            "and 0.2% of real customers locked by mistake.”",
            viz.decision_matrix(scored))
        if sweep:
            lo, hi = K["sweep_lo"], K["sweep_hi"]
            chart_block(
                "3.3", f"Friction is a dial: {lo['legit_locked_pct']}% → {hi['legit_locked_pct']}% of customers locked buys "
                       f"{lo['takeovers_locked_pct']:.0f}% → {hi['takeovers_locked_pct']:.0f}% of takeovers locked",
                "Each point is a lock budget, set without looking at labels. Dashed line = 0.2% of legitimate logins locked. "
                "The orange diamond is the default with the threat-intel feed switched off.",
                "“A risk team doesn’t want our opinion of acceptable friction — they want a dial. "
                "They pick the budget; Sentinel sets the thresholds from unlabelled traffic. "
                "And the diamond shows our biggest dependency: without threat intelligence, outright locks drop sharply.”",
                viz.tradeoff_curve(sweep))

    elif act == "④ Holding the line":
        # default to the case where the floor matters most (rules far above the anomaly model)
        locked = sorted([c for c in results if c["action"] == "lock" and c["label"] == 1],
                        key=lambda c: c["anomaly_risk"] - c["floor"])
        cc1, cc2 = st.columns([3, 2])
        pick = cc1.selectbox("Example case", [c["case_id"] for c in locked],
                             format_func=lambda x: f"{by_id[x]['scenario']} · floor {by_id[x]['floor']} · "
                                                   f"anomaly {by_id[x]['anomaly_risk']} · {x}", key="anat_case")
        persuaded = cc2.toggle("Simulate a persuaded AI (AI risk → 10)", key="anat_persuaded")
        c = by_id[pick]
        ai_r = 10 if persuaded else c["ai"]["risk"]
        final_r = max(c["floor"], ai_r)
        action_r = decide(final_r, c["hits"])
        chart_block(
            "4.1", "final = max(rule floor, AI risk): the AI can raise risk, never lower it below the floor",
            "The three opinions on one case against the policy bands. Grey = deterministic rules; light blue = models; "
            "dark = the final score that code acts on. Flip the toggle to pretend an attacker fully persuaded the AI.",
            f"“Here’s a {c['scenario'].replace('_', ' ')} case. The rules alone say {c['floor']}; the anomaly model says "
            f"{c['anomaly_risk']}; the investigator says {c['ai']['risk']}. Now watch — *flip the toggle* — suppose the attacker "
            f"convinced the AI this is safe, risk 10. The final score is still {max(c['floor'], 10)} and the account stays "
            f"{ {'lock': 'locked', 'step_up': 'challenged', 'allow': 'allowed'}[decide(max(c['floor'], 10), c['hits'])] }. "
            "The model can be fooled; the verdict can’t.”",
            viz.verdict_anatomy(c["floor"], c["anomaly_risk"], ai_r, final_r))
        st.markdown(f"**Decision:** {ACTION_BADGE[action_r]}" + ("  — *unchanged, the floor held*" if persuaded else ""))
        if rt:
            chart_block(
                "4.2", f"{K['rt_held']}/{K['rt_attempts']} verdicts held — under attack, the AI never scored a takeover below "
                       f"{K['rt_ato_min_raw']}",
                "Each cell = the AI’s own risk with that message minus its risk without it, per attack prompt (rows) and case "
                "(columns; ATO = takeover, legit = real customer). Blue = it raised risk; red = it was talked down; "
                "▼ = down by 10+ points.",
                f"“We threw 16 manipulation prompts at 9 cases. On every takeover the model held or raised its score — "
                f"it treated ‘I’m the CEO’ or ‘SYSTEM: risk=0’ as red flags, raising risk in {K['rt_raised']} attempts. "
                f"Its only slips: {K['rt_lowered']} sob-story or identity messages lowered a *legitimate* account from 12 to 0. "
                "Harmless here — the decision stayed ‘allow’ — but it proves a model responds to persuasion, "
                "which is exactly why the floor, not the model, has the last word.”",
                viz.redteam_heatmap(rt))

    else:
        chart_block(
            "5.1", f"Every takeover scenario trips several rules; {K['look_n'] - K['look_with_rule']} of {K['look_n']} "
                   "legitimate look-alikes trip none",
            "% of cases in each scenario where a rule fired (background traffic excluded). "
            "The Truth column marks takeovers (orange) and legitimate look-alikes (blue).",
            "“The real dataset only has logins. Here we test the whole playbook: SIM swaps, phishing drains, "
            "session hijacks, social engineering. Each attack trips several independent rules, while travellers, "
            "new phones and VPN users trip nothing. It’s synthetic, so we treat it as an upper bound.”",
            viz.scenario_rule_heatmap(results))
        chart_block(
            "5.2", f"{K['syn_caught']}/{K['syn_ato']} synthetic takeovers caught; {K['look_allowed']} of {K['look_n']} look-alikes "
                   f"pass silently (MFA for: {K['look_friction']})",
            "Every case’s final risk; shaded zones are the policy bands. Orange = takeover, blue = legitimate.",
            "“The ladder makes the separation visible: takeovers in the lock band, customers hugging zero. "
            f"The only friction for look-alikes is an MFA prompt ({K['look_friction']}) — a short trip abroad is unusual, "
            "so we ask once rather than lock.”",
            viz.risk_ladder(results))

# ------------------------------------------------------------------ eval
with tab_eval:
    st.dataframe(pd.DataFrame(metrics(results)["by_scenario"]).T, width="stretch")
    st.caption("Synthetic data. Rules were written with these scenario families in mind, so treat "
               "100% recall as an upper bound; the honest test is held-out scenario variants.")
