# Sentinel — chart-by-chart script

One block per chart, in the order of the dashboard’s **🔥 Visual insights** acts (and `docs/charts/`).
Each block gives: **what it shows** · **the number to point at** · **the implication** · **what to say** (≈15–20 s).
Full walk-through ≈ 4 minutes; a 90-second cut is marked ⭐.

Real-data charts use the public RBA login dataset (Wiefling et al., 2022): 87 takeover and 75,865 legitimate
successful logins from held-out users. Synthetic charts use our labelled scenario generator.

---

## ① The threat — what takeovers look like in real traffic

### 1.1 When takeovers happen (two heat maps, hour × weekday)
- **Shows:** left, every login (blue); right, the 141 takeover logins (orange).
- **Point at:** the tidy daytime block on the left vs. the scattered orange cells on the right.
  **14%** of takeovers land between midnight and 6 a.m. local time, vs. **8%** of all logins.
- **Implication:** attackers don’t keep the customer’s hours, but timing alone is weak evidence (141 events,
  under 2× the base rate). It belongs in the score as context, never as a verdict — and an overnight risk team
  is still needed.
- **Say:** “Customers log in on an office-hours rhythm. Takeovers ignore it: the night share almost doubles.
  That’s a hint, not proof — so we use it as context, never as a reason to lock.”

### 1.2 Country risk profile (table heat map)
- **Shows:** the busiest countries plus every country with a takeover; each column shaded against its own maximum.
- **Point at:** **Romania — 47 of 87 takeovers from just 501 logins, 66% via known-attacker IPs.** Then the US row:
  23,823 login attempts, **zero** takeovers, but 46% of them get an MFA prompt (28% come from IPs on the
  threat feed).
- **Implication:** attacks concentrate, so country rarity is a strong signal. But friction concentrates too: for a
  Norwegian service, foreign customers carry most of the MFA prompts. That is a fairness cost a risk team must
  monitor by segment, and why we never block a country outright.
- **Say:** “Half the takeovers come from one country that’s a rounding error in traffic. Tempting to block it —
  we don’t. Look at the US: no takeovers, yet almost half its login attempts get challenged. Country is a signal for the
  score, not a rule, and we’d track friction by region in production.”

---

## ② Detection — which signals separate attackers from customers

### 2.1 Signal lift ⭐ (dumbbell chart)
- **Shows:** for each signal, the share of legitimate logins (blue dot) vs. takeovers (orange dot) that show it;
  the label is how many times more common it is in takeovers.
- **Point at:** **“New country” — 82% of takeovers vs. 0.9% of customers (90×).** At the bottom,
  **recent failed logins — 32% vs. 30% (1.1×).**
- **Implication:** “unusual *for this user*” beats generic rules. Failed-login counts — a staple of legacy rule
  engines — barely separate attackers from people who mistype passwords; they cause friction without catching much.
- **Say:** “This is why we compare each login with the customer’s own history. A new country shows up in four out
  of five takeovers and under one percent of real logins. Failed logins, which many systems lean on, are almost
  useless on their own.”

### 2.2 Score separation (two histograms)
- **Shows:** the final risk score for legitimate logins (top) and takeovers (bottom), each scaled to 100%.
- **Point at:** **93.4% of customers score under 30.** Takeovers bunch at the lock line — **51% score 70+** — and
  another **36%** sit in the 30–69 MFA band.
- **Implication:** the middle band is deliberate. Where scores overlap we challenge instead of lock, so a mistake
  costs a customer one MFA prompt, not their account.
- **Say:** “Customers pile up near zero; takeovers pile up at the lock line. The overlap in the middle is exactly
  where we ask for a second factor instead of locking.”

### 2.3 Takeover fingerprint ⭐ (heat map, one row per takeover)
- **Shows:** every real takeover as a row, every signal as a column; the first column is Sentinel’s decision.
- **Point at:** the **44 locked** rows at the top light up on several signals at once; the **31 challenged** rows
  on fewer; the **12 missed** rows at the bottom are almost blank.
- **Implication:** our detection is explainable — each lock has a visible evidence trail. The misses aren’t a
  tuning problem: those attackers used the owner’s country, device type and network, so **nothing at login can
  catch them.** The fix is post-login behaviour (resets, email changes, payouts).
- **Say:** “Read it top to bottom. Locked attacks trip several independent signals. The twelve at the bottom are
  blank — they look exactly like the owner. That’s our honest limit, and it tells us exactly what to build next.”

---

## ③ Decisions — what Sentinel does, and how little friction customers feel

### 3.1 Triage funnel ⭐ (two bar charts)
- **Shows:** how traffic narrows at each stage — legitimate logins (log scale, left) and takeovers kept (right).
- **Point at:** **75,865 → 7,072 triaged → 5,001 challenged → 162 locked** customers, while
  **75 of 87** takeovers are stopped and **44** locked.
- **Implication:** this is the B2B value. Only **6.6%** of real customers ever see friction, and an analyst queue
  holds a few percent of traffic instead of all of it — with 86% of takeovers already in it.
- **Say:** “Out of nearly 76,000 real logins, about 5,000 get an MFA prompt and 162 are locked. Of 87 takeovers,
  75 are stopped. Analysts look at a few percent of traffic instead of all of it.”

### 3.2 Decision matrix (3 × 3 grid, each row sums to 100%)
- **Shows:** what really happened (rows) against Sentinel’s decision (columns).
- **Point at:** takeovers — **50.6% locked, 35.6% MFA, 13.8% missed**; customers — **93.4% allowed, 6.4% MFA,
  0.2% locked**; failed attempts — mostly challenged or locked.
- **Implication:** one honest picture of both error types. The 0.2% false-lock rate is the number a risk team
  cares about most, because a wrongly locked customer becomes a support ticket and a churn risk.
- **Say:** “Half the takeovers locked outright, another third challenged, and only two in a thousand real
  customers locked by mistake.”

### 3.3 Friction dial (trade-off curve)
- **Shows:** each point is a lock budget, from strict to permissive; x = customers locked, y = takeovers locked.
  The orange diamond is the default with the threat-intel feed switched off.
- **Point at:** **0.11% → 0.69% of customers locked buys 26% → 63% of takeovers locked.** Without threat
  intelligence, locks drop to **9%** (while 79% of takeovers are still challenged).
- **Implication:** the risk team, not the vendor, chooses its friction budget — and thresholds are set from
  unlabelled traffic, so a new client can start without a labelled history. The diamond exposes our biggest
  dependency: a good threat-intel feed.
- **Say:** “Friction is a dial the client sets. Pick how many customers you’re willing to challenge; Sentinel
  sets the thresholds without needing labelled data. And the diamond shows what we depend on most.”

---

## ④ Holding the line — why the AI can’t be talked into lowering risk

### 4.1 Verdict anatomy ⭐ (four bars; live toggle in the dashboard)
- **Shows:** one case’s three opinions — rule floor, anomaly model, AI investigator — and the final score,
  against the allow / MFA / lock bands.
- **Point at:** a low-and-slow takeover: rules **85**, anomaly **55**. *Flip “Simulate a persuaded AI”*: the AI
  drops to **10**, the final stays at **85**, the account stays **locked**.
- **Implication:** the guarantee lives in code (`final = max(floor, AI)`), not in a prompt. Even a fully fooled
  model can’t unlock an account the rules have flagged. (This chart is a simulation; see 4.2 for the real test.)
- **Say:** “Suppose an attacker completely convinces the AI this is safe. Watch: AI says 10, the final score
  doesn’t move, the account stays locked. The model can be fooled; the verdict can’t.”

### 4.2 Red-team heat map (attack prompts × cases)
- **Shows:** 16 manipulation prompts against 9 cases; each cell is how far the AI’s own score moved because of
  the message. Blue = raised, red = lowered, ▼ = down 10+ points.
- **Point at:** **144 / 144 verdicts held.** On takeover cases the AI never went below **90** and raised risk in
  **37** attempts. The only red cells: **4** pressure messages lowered a *legitimate* customer’s score from 12 to 0.
- **Implication:** the model mostly treats manipulation as a red flag, but it *is* persuadable. The floor never had
  to step in during this run — it’s the insurance for the attack we haven’t tried yet, and a stronger
  third-party red team is on the roadmap.
- **Say:** “Fake CEO, ‘system override’, sob stories — every verdict held, and on takeovers the AI actually raised
  risk. But four sob stories did soften it on a real customer. Harmless there; proof the model listens to
  persuasion, and exactly why code, not the model, has the last word.”

---

## ⑤ Scenario lab — the full playbook on labelled synthetic scenarios

### 5.1 Which rule catches which attack (scenario × rule heat map)
- **Shows:** % of cases in each scenario where each rule fired; the Truth column marks takeovers (orange) and
  legitimate look-alikes (blue).
- **Point at:** every takeover type trips **several independent rules**; **0 of 60** look-alikes (travellers,
  new phones, VPN users, big payments) trip **any** rule.
- **Implication:** defence in depth — evading one rule isn’t enough. And because legitimate edge cases trip
  nothing, the rules don’t punish normal behaviour. These scenarios cover what the real dataset can’t: resets,
  email changes and payouts.
- **Say:** “The real data only has logins. Here we test the whole playbook — SIM swaps, phishing drains, session
  hijacks. Each one trips several rules; travellers and new phones trip none.”

### 5.2 Risk ladder (dot plot over the policy bands)
- **Shows:** every synthetic case’s final risk, by scenario, over the allow / MFA / lock bands.
- **Point at:** **60 / 60** takeovers in the lock band; **56 of 60** look-alikes allowed silently; **4 travellers**
  get one MFA prompt.
- **Implication:** two clean clusters — but synthetic data is an upper bound, because we wrote the rules knowing
  these scenarios. The real-data charts in acts ②–③ are the honest numbers.
- **Say:** “Takeovers in the red band, customers hugging zero, and the only friction is a travel MFA prompt. It’s
  synthetic, so treat it as the best case — the real-data charts are the ones to trust.”

---

## 90-second version (⭐ charts only)
1. **2.1 Signal lift** — “New country is 90× more common in takeovers; failed logins barely matter.”
2. **2.3 Fingerprint** — “Locks have an evidence trail; the 12 misses look exactly like the owner.”
3. **3.1 Funnel** — “6.6% of customers see friction; 75 of 87 takeovers are stopped.”
4. **4.1 Verdict anatomy** — flip the toggle: “The model can be fooled; the verdict can’t.”

## Numbers to have on hand
| Chart | Figure |
|---|---|
| 1.1 | 14% of takeovers at night vs. 8% of logins (141 takeovers) |
| 1.2 | RO: 47 of 87 takeovers, 501 attempts, 66% threat-intel IPs · US: 0 takeovers, 46% of attempts MFA |
| 2.1 | New country 82% vs 0.9% (90×) · failed logins 32% vs 30% (1.1×) |
| 2.2 | 93.4% of customers < 30 · 51% of takeovers ≥ 70 · 36% in 30–69 |
| 2.3 | 44 locked · 31 challenged · 12 missed |
| 3.1 | 75,865 → 7,072 → 5,001 → 162 customers · 87 → 77 → 75 → 44 takeovers |
| 3.2 | Takeovers 50.6 / 35.6 / 13.8% · customers 93.4 / 6.4 / 0.2% |
| 3.3 | 0.11% → 0.69% locked buys 26% → 63% · no threat intel: 9% locked |
| 4.1 | Floor 85 · anomaly 55 · persuaded AI 10 · final 85 → lock |
| 4.2 | 144/144 held · takeovers never below 90 · raised in 37 · 4 drops on a legit account (12 → 0) |
| 5.1 | Every attack trips several rules · 0/60 look-alikes trip any |
| 5.2 | 60/60 caught · 56/60 look-alikes allowed · 4 travellers MFA |
