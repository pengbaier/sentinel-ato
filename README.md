# 🛡️ Sentinel — AI account-takeover defense that can't be talked out of it

> Hackathon theme: **Trust & Risk — build the AI that holds the line.**
> It catches the bad cases, clears the good ones, and can't be talked out of it.

Sentinel scores every account session for takeover (ATO) risk with a layered pipeline:
deterministic rules set a **risk floor**, a per-user anomaly model measures how unlike *this user* a session is,
and an LLM investigator explains the case and may **raise** risk — but code, not the model, makes the final call,
and nothing the attacker types can lower the floor.

![Verdict anatomy](docs/charts/4-1_verdict_anatomy_persuaded.png)

## Results

| Benchmark | Takeovers stopped (MFA or lock) | Takeovers locked | Legit users let through silently | Legit users locked |
|---|---|---|---|---|
| **Real logins** — RBA dataset, 87 takeover / 75,865 legit logins | **86.2%** | **50.6%** | **93.4%** | **0.21%** |
| **Synthetic scenarios** — 6 attack types, 6 legit look-alikes | 100% | 100% | 99.2% | 0% |
| **Red team** — 16 manipulation prompts × 9 cases, LLM investigator | verdict held in **144 / 144** | | | |

*Synthetic numbers are an upper bound: the rules were written knowing those scenario families. The real-data
numbers are the honest ones; lock thresholds there are calibrated without looking at labels.*

## How a verdict is made

```
events ─► per-user features ─► rules  ──────────────► FLOOR ─────────────┐
                            └► anomaly model (per-user, unsupervised) ──┼─► AI investigator ─► final = max(floor, AI) ─► policy (code)
support-chat text ─► injection check (PRISM guardrail + local) ─────────┘        │                                    allow / MFA / lock
                                                                                 └─► trace to PRISM
```

1. **Rules → floor.** Impossible travel, credential stuffing, recovery-then-money, session hijack, disposable email,
   threat-intel IPs, manipulation attempts… each sets a minimum risk.
2. **Anomaly model.** Isolation Forest over features relative to each user's own history plus population rarity.
   On its own it can only trigger MFA; with a corroborating rule it can lock (thresholds calibrated on unlabeled users).
3. **AI investigator** (Claude via the [Nicrron](https://nicrron.ai) gateway). Gets computed facts; user-typed text is
   escaped and fenced as `<untrusted_user_text>`. Returns strict JSON. May raise risk, **cannot go below the floor**
   (enforced in code). Falls back to an offline analyst if the model is unavailable — never to "allow".
4. **Policy engine** (plain code) picks the action. Within an open case, risk only goes **up**.
5. Every investigation is traced to **[PRISM by Block Convey](https://blockconvey.com/prism)** for observability.

## Quick start

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt        # macOS/Linux: .venv/bin/pip
.venv/Scripts/streamlit run app.py                    # synthesizes demo data on first load
```

Everything runs **offline with no keys**. To turn on the AI investigator and tracing, copy `.env.example` to `.env`
and fill in a Nicrron key and a PRISM project id + ingest key.

| Command | What it does |
|---|---|
| `python -m sentinel.data_gen` | Synthesize 300 users, 30 days of history, 12 labelled scenario types |
| `python -m sentinel.pipeline [--llm]` | Score the synthetic live window; print metrics by scenario |
| `python -m sentinel.redteam [--llm]` | Throw 16 manipulation prompts at flagged cases; check the verdict holds |
| `python -m sentinel.rba sample` / `eval` / `sweep` | Real-data benchmark on the RBA login dataset (see [data/README.md](data/README.md)) |
| `python -m sentinel.export_charts` | Re-export every chart to `docs/charts/` (PNG + interactive HTML) |

## Dashboard

| Tab | Shows |
|---|---|
| 📡 Live cases | Flagged sessions, timeline, rule hits, AI verdict and evidence |
| 💬 Attacker chat | Be the attacker; try to talk a locked account open (risk is monotonic) |
| 🧨 Red team | Every manipulation attempt and whether the verdict held |
| 🌍 Real-data benchmark | Headline metrics, lock-budget trade-off, every takeover login |
| 🔥 Visual insights | The demo in five acts: 12 charts with takeaway headlines and narration notes |
| 📊 Synthetic evaluation | Per-scenario outcomes |

## Visual insights — the demo in five acts

The dashboard's **🔥 Visual insights** tab tells the story in five acts. Each chart has a takeaway headline computed
from the data, a "how to read it" line, and a 🎤 *Say this in the demo* note. Interactive versions of every chart:
open `docs/charts/*.html` in a browser. Real-data charts use the public RBA login dataset (87 takeover and ~76k
legitimate successful logins from held-out users).

### ① The threat — what takeovers look like in real traffic

**1.1 Takeovers keep their own hours.** 14% land between midnight and 6 a.m. local time, vs. 8% of all logins.
![When heatmaps](docs/charts/1-1_when_heatmaps.png)

**1.2 Attacks concentrate.** One country accounts for 47 of 87 takeover logins from just 501 logins, 66% of them via
known-attacker IPs. Sentinel scores rarity per login instead of blocking a country.
![Country profile](docs/charts/1-2_country_profile.png)

### ② Detection — which signals separate attackers from customers

**2.1 Signal lift.** "New country" is 90× more common in takeovers; recent failed logins barely differ (1.1×).
![Signal lift](docs/charts/2-1_signal_lift.png)

**2.2 Score separation.** 93% of legitimate logins score under 30; half of takeovers score 70+.
![Risk separation](docs/charts/2-2_risk_separation.png)

**2.3 Takeover fingerprint.** One row per takeover, one column per signal. Locked attacks trip several signals; the
12 missed ones are nearly blank — at login they look exactly like the owner.
![Takeover fingerprint](docs/charts/2-3_takeover_fingerprint.png)

### ③ Decisions — what Sentinel does, and how little friction customers feel

**3.1 Triage funnel.** Only 6.6% of legitimate logins ever meet friction, while 75 of 87 takeovers do.
![Triage funnel](docs/charts/3-1_triage_funnel.png)

**3.2 Decision matrix.** Each row sums to 100%.
![Decision matrix](docs/charts/3-2_decision_matrix.png)

**3.3 Friction is a dial.** 0.11% → 0.69% of customers locked buys 26% → 63% of takeovers locked; thresholds are set
without labels.
![Trade-off](docs/charts/3-3_tradeoff_curve.png)

### ④ Holding the line — why the AI can't be talked into lowering risk

**4.1 Verdict anatomy.** `final = max(rule floor, AI risk)`. Here the AI is *simulated* as fully persuaded (risk 10):
the final score stays at the rule floor and the account stays locked. (In the dashboard, flip the toggle live.)
![Verdict anatomy](docs/charts/4-1_verdict_anatomy_persuaded.png)

**4.2 Red team.** 144/144 verdicts held. Blue = the AI read the message as a red flag and raised risk (37 attempts);
red = it was talked down; ▼ = down by 10+ points. On takeovers the AI never scored below 90; the only drops were
pressure messages on a legitimate account (12 → 0, decision unchanged). The floor never had to step in during this run.
![Red team](docs/charts/4-2_redteam_heatmap.png)

### ⑤ Scenario lab — the full playbook on labelled synthetic scenarios

**5.1 Which rule catches which attack.** Every takeover scenario trips several rules; no legitimate look-alike trips any.
![Scenario rules](docs/charts/5-1_scenario_rules.png)

**5.2 Risk ladder.** 60/60 synthetic takeovers caught; 56 of 60 look-alikes pass silently, and 4 travellers get an
MFA prompt.
![Risk ladder](docs/charts/5-2_risk_ladder.png)

## Honest limitations

- The 12 missed real takeovers look exactly like their owners at login (same country, device, network).
  Catching them needs post-login behaviour (resets, email changes, payouts) that the RBA dataset doesn't contain;
  the synthetic scenarios and session rules cover that part.
- The RBA dataset is synthesized from real behaviour; IPs and user agents are artificial. Its authors advise
  against tuning production systems on it.
- The device identity on real data is OS family + browser family + device type (no device id in the dataset).
- The red team never talked the AI down on a takeover, so the code-level floor is enforced but never had to
  step in during that run (the dashboard's "persuaded AI" toggle simulates it). A stronger, third-party red team is on
  the roadmap.

## Project layout

```
app.py                    Streamlit dashboard
sentinel/
  data_gen.py             synthetic users, history and labelled scenarios
  features.py             per-user profiles, population stats, session features
  rules.py                deterministic rules -> risk floor
  pipeline.py             anomaly model, policy engine, end-to-end scoring
  investigator.py         LLM investigator, quarantine, floor enforcement, offline analyst
  integrations.py         Nicrron gateway, PRISM tracing + guardrail, local manipulation detector
  redteam.py              manipulation harness
  rba.py                  real-data benchmark (sample, eval, label-free calibration, sweep)
  viz.py                  Altair charts + computed takeaways;  export_charts.py -> docs/charts/
data/                     benchmark outputs + RBA sample (see data/README.md)
docs/charts/              exported charts (PNG + HTML)
```

## Credits

Real-login data: *Login Data Set for Risk-Based Authentication* — Wiefling, Jørgensen, Thunem, Lo Iacono,
ACM TOPS 2022, doi:10.1145/3546069, CC BY 4.0. Sponsor tools: PRISM by Block Convey, Nicrron.
