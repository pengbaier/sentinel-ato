"""Deterministic rules -> a risk FLOOR that nothing downstream can lower.

The AI investigator may raise risk above the floor, or explain it, but the
final score is always max(floor, ai_risk). These rules are the part of the
system that "can't be talked out of it".
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Hit:
    code: str
    floor: int
    why: str


def evaluate(f: dict, events: list[dict], manipulation: dict | None = None) -> list[Hit]:
    hits: list[Hit] = []
    sens_types = {e["type"] for e in events}
    has_payout = "payout" in sens_types
    account_change = sens_types & {"email_change", "phone_change", "mfa_change"}

    if f["speed_kmh"] > 900:
        if f["new_device"]:
            hits.append(Hit("IMPOSSIBLE_TRAVEL_NEW_DEVICE", 75,
                            f"{f['km_from_last']} km in {f['hours_since_last']} h ({f['speed_kmh']} km/h) on an unseen device"))
        else:
            hits.append(Hit("IMPOSSIBLE_TRAVEL", 30,
                            f"{f['speed_kmh']} km/h implied travel on a known device (VPN?)"))

    if f["fail_then_success"]:
        # A new ISP alone is common (mobile data, router change), so it only challenges.
        # Locking needs a foreign country, a datacenter IP, or automation.
        if f["new_country"] or f["hosting_unusual"] or f["bot_ua"]:
            hits.append(Hit("CREDENTIAL_STUFFING", 80,
                            f"{f['failed_logins']} failed logins then success from a new country/datacenter/automation"))
        elif f["new_device"] or f["new_asn"]:
            hits.append(Hit("FAILS_THEN_NEW_SOURCE", 45,
                            f"{f['failed_logins']} failed logins then success on a new device or network in the home country"))

    if (f["n_sensitive"] and f["new_device"] and 0 <= f["mins_login_to_sensitive"] <= 30
            and (f["new_country"] or f["hosting_unusual"])):
        hits.append(Hit("RAPID_ACCOUNT_CHANGE", 85,
                        f"credential/contact change {f['mins_login_to_sensitive']} min after login from new device in new location"))

    if account_change and has_payout and f["new_beneficiary"]:
        floor = 85 if f["new_device"] else 60
        hits.append(Hit("RECOVERY_THEN_MONEY", floor,
                        f"{', '.join(sorted(account_change))} followed by payout to a never-seen beneficiary"))

    if f["session_geo_jump"] and (f["hosting_ip"] or f["new_country"]):
        hits.append(Hit("SESSION_HIJACK", 80, "same session/device fingerprint jumped network and country mid-session"))

    if f["payout_ratio"] >= 3 and f["new_beneficiary"]:
        hits.append(Hit("LARGE_NEW_PAYEE", 70 if f["new_device"] else 55,
                        f"payout {f['payout_ratio']}x the user's p95 to a new beneficiary"))

    if f.get("threat_ip"):
        # Threat feeds are noisy (shared/NAT IPs): alone they only challenge; with a new device AND country they lock.
        strong = f["new_device"] and f["new_country"] and f["profile_maturity"] >= 1
        hits.append(Hit("THREAT_INTEL_IP", 70 if strong else 45,
                        "source IP is on a known-attacker list" + (" from an unseen device and country" if strong else "")))

    if f["new_device"] and f["new_country"] and f["new_asn"] and f["profile_maturity"] >= 3:
        hits.append(Hit("NEW_DEVICE_COUNTRY_NETWORK", 40,
                        "first time on this device, from this country, and on this network"))

    if f["bot_ua"]:
        hits.append(Hit("AUTOMATION_UA", 50, "scripted/headless user agent"))

    if f["email_to_disposable"]:
        hits.append(Hit("DISPOSABLE_EMAIL", 75 if f["new_device"] else 55,
                        "email moved to a privacy/disposable mailbox"))

    if manipulation and manipulation.get("injection"):
        hits.append(Hit("MANIPULATION_ATTEMPT", 70,
                        "support text tries to instruct the risk system (" + manipulation.get("source", "local") + ")"))
    elif manipulation and manipulation.get("pressure") and f["new_device"] and account_change:
        hits.append(Hit("SOCIAL_ENGINEERING", 60,
                        "urgency/authority pressure tied to an account change from an unknown device"))
    return hits


def floor_of(hits: list[Hit]) -> int:
    return max((h.floor for h in hits), default=0)
