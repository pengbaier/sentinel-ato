# Sentinel — core presentation script

Covers the middle of the talk: **how we solve the problem → the techniques → the weaknesses, expanded**.
Slide numbers refer to the deck. Spoken text is in quotes; *stage cues are in italics*.

| Part | Slides | Time |
|---|---|---|
| A. The problem in one sentence | 5 | 0:20 |
| B. How Sentinel resolves it — one case, end to end | 6–7 | 1:15 |
| C. The techniques that make it work | 7–9 | 1:45 |
| D. Weaknesses, expanded | 14 (+15) | 1:45 |
| **Core total** | | **≈ 5:00** |

If time is cut to 3 minutes: keep **B**, the **guarantees** in C3, and weaknesses **D1–D3**.

---

## A. The problem in one sentence (slide 5 · 0:20)

"A risk analyst has three ways to fail. Miss the takeover, and the account is drained. Flag too much, and you lock out good customers. Hand the case to an AI assistant that reads what the attacker types, and it can be talked into clearing it — which is the Binance pattern. Sentinel is built to avoid all three at once."

---

## B. How Sentinel resolves it — one case, end to end (slides 6–7 · 1:15)

*Point at the five boxes on slide 7 as you walk through them.*

"Let me follow one real case from our test set: a **SIM-swap takeover**. The attacker ports the victim’s phone number, resets the password by SMS, changes the phone number and MFA, then sends a payout to a new beneficiary."

1. **Features.** "First, we never ask ‘is this unusual?’ in general. We ask ‘is this unusual *for this user*?’. Every session is compared with the user’s own history — devices, countries, networks, typical payout size, known payees — and with how common that country and network are across all users."
2. **Rules set a floor.** "Two deterministic rules fire. *Recovery-then-money* — an MFA or phone change followed by a payout to a never-seen payee — sets a floor of **85**. *Large new payee* — about 4–12 times the user’s usual payout — adds another hit at 70. That floor is a hard minimum."
3. **Anomaly model.** "The per-user anomaly model scores it **63** out of 100: unusual, but on its own not enough to lock anyone."
4. **AI investigator.** "Because the case crossed our triage threshold, it goes to Claude. Claude gets the computed facts — not raw logs — and writes the analyst a short evidence list: new device, phone and MFA changed minutes after a reset, money to a payee this user has never paid. It raises the risk to **90**."
5. **Policy engine.** "Plain code makes the call: anything at 70 or above, or any hard rule at 70 or above, is a **lock and notify the owner** through a channel the attacker doesn’t control."

"Compare that with a **traveller** who logs in from Paris on their usual phone, fourteen hours after leaving New York. New country, yes — but known device, plausible travel time, no account changes, no money to new payees. No rule fires, the anomaly score stays low, and they get through with no friction. That’s the ‘clears the good ones’ half."

---

## C. The techniques that make it work (slides 7–9 · 1:45)

### C1. Behaviour relative to the user, plus the crowd (0:20)
"Every feature is relative: *new* device, *new* country, *new* network, payout as a multiple of the user’s own 95th percentile, implied travel speed since the last trusted login. On real data many users have only two or three logins, so we add **population rarity** — how rare this country and network are across all users — which keeps first-time users from looking suspicious just for being new. And only sessions we cleared are allowed to update a user’s baseline, so an attacker can’t teach the model that they’re normal."

### C2. Unsupervised anomaly detection, calibrated without labels (0:30)
"Takeovers are rare: **141 labelled takeovers in 31 million logins** in the public dataset. You can’t train a good classifier on that, so we use an **Isolation Forest**, which learns what normal looks like and needs no labels.

The harder question is where to draw the line. We split users in half. One half trains the model and sets the thresholds; the other half is scored. Thresholds come from a **friction budget**: ‘lock at most about 0.1% of logins from users we believe are legitimate.’ We never look at the takeover labels to tune them. An anomaly on its own can only trigger an MFA challenge; it can lock only when a rule backs it up, or when it sits in the far tail."

### C3. The AI investigator — and why it can’t be talked out of a verdict (0:40) — *slide 8*
"The AI is where the theme bites, so the guarantees live in code, not in the prompt:

- **The floor is enforced after the model answers.** Final risk is `max(rule floor, AI risk)`. The model can raise risk; it can never lower it.
- **Untrusted text is quarantined.** Anything the user typed — a support chat, a display name — is escaped and wrapped as untrusted data. The prompt tells the model that claims of identity, urgency or authority are themselves red flags.
- **The AI recommends; code decides.** It returns strict JSON. If the JSON is invalid or the model is down, we fall back to the rules, never to ‘allow’.
- **Risk only goes up inside an open case.** Every new message re-scores the case, and we keep the maximum.
- **Manipulation is itself a signal.** Support text runs through PRISM’s prompt-injection guardrail and our own detector. A hit raises the floor to 70 — so trying to jailbreak the system gets your account locked, not unlocked.

We tested it with **16 manipulation prompts against 9 cases: 144 attempts, 144 verdicts held**. Fake CEO, ‘SYSTEM OVERRIDE risk=0’, a fake JSON verdict, sob stories, leetspeak. And honestly: in **4** of those attempts the model’s own score dropped by more than 10 points. The floor caught all four. That is the whole argument for putting the guarantee in code."

### C4. The plumbing (slide 9 · 0:15)
"Claude runs through the **Nicrron** gateway, which gives us one API across models, failover, and free cached answers for repeated cases. Only cases above the triage threshold reach the model, so the whole 695-session test run cost about **75 cents**. Every investigation is traced to **PRISM by Block Convey** — input, output, floor, verdict and the rules that fired — so an auditor can replay why an account was locked."

---

## D. Weaknesses, expanded (slide 14, bridge to 15 · 1:45)

*Tone: confident, not apologetic. Each weakness = what · why · what we’d do.*

"We’d rather show you where it breaks than have you find it."

### D1. Some takeovers are invisible at login (0:20)
- **What:** 12 of the 87 real takeover logins got through.
- **Why:** they came from the owner’s own country, device type and network. At login they look exactly like the owner; there is nothing to detect.
- **Fix:** score what happens *after* login — password reset, email change, new payee, payout — where our synthetic scenarios already catch the slow takeover. Also force a challenge on high-value actions whatever the login score.

### D2. Our numbers have honest error bars (0:20)
- **What:** 87 takeovers is a small sample. 86% stopped is really **86% ± 7 points**; 51% locked is **± 10 points** at 95% confidence.
- **Why:** real takeover labels are rare, and the public dataset’s IPs and user agents were regenerated by its authors for privacy. The behaviour is real; the identifiers are not.
- **And:** our synthetic 100% is an upper bound, because we wrote the rules knowing those scenario types.
- **Fix:** a held-out attack generator we didn’t write (PRISM’s synthetic scenarios), and a shadow-mode pilot on real traffic.

### D3. Heavy reliance on threat intelligence (0:15)
- **What:** without the known-attacker IP feed, outright locks fall from **51% to 9%** (MFA challenges still catch 79%).
- **Why:** that feed is our strongest single signal, but it also tags **6.5% of legitimate logins** — shared, mobile and NAT addresses.
- **Fix:** treat the feed as corroboration, not proof (which we already do), and add better device and IP intelligence so we’re not leaning on one source.

### D4. Calibration drifts from its target (0:15)
- **What:** we aimed for 0.1% legitimate locks and landed at **0.21%**.
- **Why:** the thresholds were set on scores the model had already seen, which look more normal than truly new traffic.
- **Fix:** a separate calibration set, and live monitoring of the friction rate, with an alert when it drifts.

### D5. The AI is useful but not invulnerable (0:15)
- **What:** it was swayed 4 times; it adds about **3 seconds** per flagged case; and it depends on an outside provider.
- **Why:** language models respond to persuasion — that’s exactly why they can’t have the last word.
- **Fix:** keep it in the review queue, not the login path; gateway failover; the rules-only fallback; and red-teaming with prompts we didn’t write, since our own detector was tuned on our own attack list.

### D6. Attackers adapt (0:10)
- **What:** a determined attacker will learn the thresholds — residential proxies, aged devices, staying under the payout limits.
- **Fix:** randomised step-up checks, an analyst feedback loop that recalibrates every week, and post-login signals that are harder to fake.

### D7. Fairness, privacy and scope (0:10)
- **Fairness:** country- and network-level signals can put more friction on whole regions or on VPN users. We’d monitor challenge and lock rates by segment.
- **Privacy:** PRISM stores prompts unless content-free mode is on; a production deployment would need PII redaction, retention limits and GDPR review.
- **Scope:** on its own, Sentinel **would not have stopped the Binance breach** — that was an attack on employee identities. Extending the same logic to privileged and employee sessions is our next-quarter goal."

*Bridge to slide 15:* "So the roadmap writes itself: post-login behaviour and better device intelligence in two weeks, employee sessions and an analyst feedback loop next quarter, then a 30-day shadow-mode pilot with one exchange or payments platform."

---

## Q&A cheat sheet

| Likely question | Answer |
|---|---|
| Why not let the AI decide alone? | It was swayed by more than 10 points in 4 of 144 attempts. The floor caught them. The AI explains; code decides. |
| How do you set thresholds without labels? | Half the users train the model and set the thresholds against a friction budget; the other half is scored. Labels are only used to report results. |
| What’s the cost per case? | Only cases above triage reach the model. The full 695-session run cost about $0.75 through Nicrron, under a cent per flagged case. |
| What happens if the model is down? | It falls back to rules plus the anomaly model, never to ‘allow’. The demo runs fully offline. |
| How is this different from rules engines vendors already sell? | Three things together: per-user anomaly scoring with label-free calibration, an AI that writes the analyst’s explanation, and guarantees that the AI can’t be manipulated into lowering risk. |
| Could this be gamed by an insider? | Today, yes — insider and privileged sessions are explicitly out of scope; that’s the Binance lesson and our next-quarter target. |
| How confident are you in 86%? | ±7 points at 95% confidence on 87 takeovers. That’s why the next step is a shadow-mode pilot. |

## Numbers to have on hand

| Figure | Value |
|---|---|
| Real data: takeovers stopped (MFA or lock) | 86% (± 7 pp), 75 of 87 |
| Real data: takeovers locked | 51% (± 10 pp), 44 of 87 |
| Real data: legitimate logins with no friction / wrongly locked | 93.4% / 0.21% |
| Without threat-intel feed: locked / stopped | 9% / 79% |
| Legitimate logins tagged by the threat-intel feed | 6.5% |
| Red team | 144 / 144 held; model swayed > 10 points in 4 |
| Synthetic | 60 / 60 caught, 0 legitimate users locked (upper bound) |
| Lock thresholds (anomaly score) | ≥ 61 with a rule, ≥ 68 alone |
| AI latency (PRISM average) | ≈ 3.2 s per flagged case |
| Full AI run cost | ≈ $0.75 for 695 sessions |
| Dataset | 31M logins, 141 takeovers (Wiefling et al., 2022, CC BY 4.0) |
