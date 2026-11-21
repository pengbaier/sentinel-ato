"""Sponsor integrations, each optional (the system runs fully offline without keys).

* Nicrron  - OpenAI-compatible gateway; the investigator's LLM calls go through it.
* PRISM    - Block Convey observability: every investigation is sent as a trace,
             and support-chat text is checked by PRISM's Prompt Injection guardrail.
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

import requests

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:  # dotenv optional
    pass

NICRRON_KEY = os.getenv("NICRRON_API_KEY", "")
NICRRON_BASE = os.getenv("NICRRON_BASE_URL", "https://api.nicrron.ai/v1")
NICRRON_MODEL = os.getenv("NICRRON_MODEL", "anthropic/claude-sonnet-5-5")
NICRRON_DEEP_MODEL = os.getenv("NICRRON_DEEP_MODEL", "anthropic/claude-opus-5-5")

PRISM_HOST = os.getenv("PRISMTRACE_HOST", "https://api.prism.blockconvey.com")
PRISM_PROJECT = os.getenv("PRISMTRACE_PROJECT_ID", "")
PRISM_KEY = os.getenv("PRISMTRACE_API_KEY", "")


def llm_enabled() -> bool:
    return bool(NICRRON_KEY)


def prism_enabled() -> bool:
    return bool(PRISM_KEY and PRISM_PROJECT)


_client = None


def llm_chat(messages: list[dict], model: str | None = None, max_tokens: int = 700) -> str:
    """One chat completion through the Nicrron gateway. temperature 0 => gateway cache eligible."""
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(api_key=NICRRON_KEY, base_url=NICRRON_BASE, timeout=60)
    r = _client.chat.completions.create(model=model or NICRRON_MODEL, messages=messages,
                                        temperature=0, max_tokens=max_tokens)
    return r.choices[0].message.content or ""


def llm_list_models() -> list[str]:
    from openai import OpenAI
    c = OpenAI(api_key=NICRRON_KEY, base_url=NICRRON_BASE)
    return [m.id for m in c.models.list().data]


# ------------------------------------------------------------------ PRISM
def _prism_headers():
    return {"Content-Type": "application/json", "X-PRISMtrace-Key": PRISM_KEY}


def prism_trace(*, case_id: str, user_id: str, input_text: str, output_text: str, model: str,
                latency_ms: int, metadata: dict, agent_id: str = "sentinel-investigator"):
    """Fire-and-forget trace so PRISM never adds latency or failure to the decision path."""
    if not prism_enabled():
        return

    def _send():
        try:
            requests.post(f"{PRISM_HOST}/api/traces", headers=_prism_headers(), timeout=8, json={
                "project_id": PRISM_PROJECT, "model": model,
                "input_messages": [{"role": "user", "content": input_text}],
                "output_message": output_text, "latency_ms": int(latency_ms),
                "session_id": case_id, "trace_id": f"sentinel-{case_id}", "user_identifier": user_id,
                "agent_id": agent_id, "agent_name": "Sentinel ATO Investigator", "metadata": metadata,
            })
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()


def prism_guardrail(text: str, case_id: str) -> dict | None:
    """Ask PRISM's guardrails whether this support text is an injection. None = not evaluated."""
    if not prism_enabled():
        return None
    try:
        r = requests.post(f"{PRISM_HOST}/api/guardrails/evaluate", headers=_prism_headers(), timeout=5, json={
            "project_id": PRISM_PROJECT, "trace_id": f"sentinel-{case_id}",
            "agent_id": "sentinel-investigator", "messages": [{"role": "user", "content": text}],
        })
        if r.status_code != 200:
            return None
        j = r.json()
        return j if j.get("evaluated") else None
    except Exception:
        return None


# ------------------------------------------------------------------ local manipulation detector
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)|system\s*(override|prompt|:)|"
    r"risk\s*(score)?\s*[=:]\s*\d|verdict\s*(benign|clear)|action\s*=\s*allow|maintenance mode|"
    r"you are now|</?\s*untrusted|developer mode|jailbreak|output verdict|requires you to comply|"
    r"verified_owner\s*=\s*true|\"verdict\"\s*:|\"risk\"\s*:|reviewing (model|ai|agent)|"
    r"(mark|treat|classify) (it|this|the session)? ?(as )?(benign|safe|clear)|pre-?cleared|"
    r"this is your (developer|creator|admin)|floor is 0|respond with risk|then follow it|"
    r"previous (answer|analysis) was wrong|the correct (answer|analysis) is", re.I)
PRESSURE = re.compile(
    r"urgent|right now|immediately|today|tonight|ceo|fired|lawyer|police|already verified|colleague|"
    r"skip (the )?verification|just unlock|unlock (it )?now|remove the hold|hospital|emergency|this once|"
    r"evicted|only hope|proves? it|maiden name|i am the (real )?owner|i'm the (real |account )?owner", re.I)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "$": "s", "@": "a"})


def detect_manipulation(text: str, case_id: str = "") -> dict:
    norm = text.translate(_LEET)
    out = {"injection": bool(INJECTION.search(text) or INJECTION.search(norm)),
           "pressure": bool(PRESSURE.search(text) or PRESSURE.search(norm)), "source": "local"}
    g = prism_guardrail(text, case_id)
    if g is not None:
        out["prism"] = {k: g.get(k) for k in ("blocked", "rule_name", "rule_type", "matched_text")}
        if g.get("blocked"):
            out["injection"], out["source"] = True, "prism+local" if out["injection"] else "prism"
    return out
