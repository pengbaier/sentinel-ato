# 🛡️ Sentinel — AI account-takeover defense that can't be talked out of it

> Hackathon theme: **Trust & Risk — build the AI that holds the line.**
> It catches the bad cases, clears the good ones, and can't be talked out of it.

Sentinel scores every account session for takeover (ATO) risk with a layered pipeline:
deterministic rules set a **risk floor**, a per-user anomaly model measures how unlike *this user* a session is,
and an LLM investigator explains the case and may **raise** risk — but code, not the model, makes the final call,
and nothing the attacker types can lower the floor.

![Takeover fingerprint](docs/charts/2_takeover_fingerprint.png)

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
| 🔥 Visual insights | The charts below, interactive with hover details |
| 📊 Synthetic evaluation | Per-scenario outcomes |

## Visual insights

Interactive versions: open any `docs/charts/*.html` in a browser.

**Did the right people get stopped?** Each row sums to 100%.
![Decision matrix](docs/charts/1_decision_matrix.png)

**How far apart are the scores?** Legit logins pile up near zero; takeovers cluster at the lock line.
![Risk separation](docs/charts/3_risk_separation.png)

**When do takeovers happen?** All logins (blue) vs. takeover logins (orange), hour × weekday.
![When heatmaps](docs/charts/4_when_heatmaps.png)

**Country risk profile.** Romania: 47 of the 87 takeover logins from 501 logins, 66% from known-attacker IPs.
![Country profile](docs/charts/5_country_profile.png)

**The lock-budget trade-off.** How much legitimate friction buys how many locks.
![Trade-off](docs/charts/6_tradeoff_curve.png)

**Which rule catches which attack** — and legit look-alikes trigger nothing.
![Scenario rules](docs/charts/7_scenario_rules.png)

**Risk ladder.** Every synthetic case against the allow / MFA / lock bands.
![Risk ladder](docs/charts/8_risk_ladder.png)

**Could the attacker talk the AI down?** Red = the message lowered the AI's own risk (⛨ = by ≥10 points, floor held);
blue = the AI treated the message as a red flag.
![Red team](docs/charts/9_redteam_heatmap.png)

## Honest limitations

- The 12 missed real takeovers look exactly like their owners at login (same country, device, network).
  Catching them needs post-login behaviour (resets, email changes, payouts) that the RBA dataset doesn't contain;
  the synthetic scenarios and session rules cover that part.
- The RBA dataset is synthesized from real behaviour; IPs and user agents are artificial. Its authors advise
  against tuning production systems on it.
- The device identity on real data is OS family + browser family + device type (no device id in the dataset).

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
  viz.py                  Altair charts;  export_charts.py -> docs/charts/
data/                     benchmark outputs + RBA sample (see data/README.md)
docs/charts/              exported charts (PNG + HTML)
```

## Credits

Real-login data: *Login Data Set for Risk-Based Authentication* — Wiefling, Jørgensen, Thunem, Lo Iacono,
ACM TOPS 2022, doi:10.1145/3546069, CC BY 4.0. Sponsor tools: PRISM by Block Convey, Nicrron.
