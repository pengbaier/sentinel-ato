# Data

| File | What | Regenerate |
|---|---|---|
| `rba_sample.csv.gz` | 268,618 logins from 67,461 users (every user with a takeover + ~1/64 random users) sampled from the RBA dataset | `python -m sentinel.rba sample` (needs `raw/rba-dataset.zip`) |
| `rba_scored.csv.gz` | Sentinel's score and decision for each evaluated real login | `python -m sentinel.rba eval` |
| `rba_metrics*.json`, `rba_takeovers*.json`, `rba_sweep.json` | Real-data metrics, per-takeover decisions, lock-budget trade-off | `python -m sentinel.rba eval` / `sweep` |
| `redteam.json`, `redteam_llm.json` | Manipulation attempts against the offline analyst / the LLM investigator | `python -m sentinel.redteam [--llm]` |
| *(not committed)* `events.jsonl`, `cases.json`, `users.json`, `results.json` | Synthetic scenario data and scores | `python -m sentinel.data_gen && python -m sentinel.pipeline` |

## Raw dataset

```bash
mkdir -p data/raw
curl -L -o data/raw/rba-dataset.zip https://github.com/das-group/rba-dataset/releases/download/v1.0.0/rba-dataset.zip   # 1.02 GB
```

## Attribution (CC BY 4.0)

`rba_sample.csv.gz` and the files derived from it come from the **Login Data Set for Risk-Based Authentication**
by Stephan Wiefling, Paul René Jørgensen, Sigurd Thunem and Luigi Lo Iacono, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The sample keeps a subset of the original rows and columns, unmodified.

> Stephan Wiefling, Paul René Jørgensen, Sigurd Thunem, and Luigi Lo Iacono: *Pump Up Password Security!
> Evaluating and Enhancing Risk-Based Authentication on a Real-World Large-Scale Online Service.*
> ACM Transactions on Privacy and Security (2022). doi: [10.1145/3546069](https://doi.org/10.1145/3546069)

The dataset was synthesized by its authors from real login behaviour; IP addresses, user agents and round-trip
times are artificial. The authors advise against using it to tune production systems.
