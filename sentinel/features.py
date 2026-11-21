"""Per-user behavioural profiles and session feature extraction.

Every feature is *relative to the user's own history before the session*,
so a VPN user or a frequent traveller is compared to themselves, not to
the population.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

SENSITIVE = {"password_reset", "email_change", "phone_change", "mfa_change"}
DISPOSABLE_DOMAINS = ("mailinator.com", "proton.me", "tutanota.com", "guerrillamail", "10minutemail")
BOT_UA = re.compile(r"python-requests|curl|headless|phantomjs|selenium", re.I)


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    p = math.pi / 180
    a = (math.sin((lat2 - lat1) * p / 2) ** 2
         + math.cos(lat1 * p) * math.cos(lat2 * p) * math.sin((lon2 - lon1) * p / 2) ** 2)
    return 12742 * math.asin(math.sqrt(a))


@dataclass
class Profile:
    user_id: str
    devices: set = field(default_factory=set)
    countries: set = field(default_factory=set)
    asns: set = field(default_factory=set)
    beneficiaries: set = field(default_factory=set)
    hosting_seen: int = 0
    sessions: int = 0
    payouts: list = field(default_factory=list)
    hours: list = field(default_factory=list)
    last_ts: float | None = None
    last_lat: float | None = None
    last_lon: float | None = None
    recent_fails: deque = field(default_factory=lambda: deque(maxlen=50))

    @property
    def payout_p95(self) -> float:
        if not self.payouts:
            return 0.0
        s = sorted(self.payouts)
        return s[min(len(s) - 1, int(0.95 * len(s)))]

    def update(self, events: list[dict]):
        """Absorb a session the system trusted (cleared)."""
        self.sessions += 1
        for e in events:
            if e["type"] == "login" and not e["success"]:
                self.recent_fails.append(e["ts"])
                continue
            self.devices.add(e["device_id"])
            self.countries.add(e["country"])
            self.asns.add(e["asn"])
            if e["hosting"]:
                self.hosting_seen += 1
            if e["type"] == "payout":
                self.payouts.append(e["amount"])
                self.beneficiaries.add(e["beneficiary"])
            self.hours.append(((e["ts"] % 86400) / 3600))
            self.last_ts, self.last_lat, self.last_lon = e["ts"], e.get("lat"), e.get("lon")


class GlobalStats:
    """Population-level frequencies of trusted logins (helps users with little history:
    a first login from the country/network most users use is less suspicious than a rare one)."""

    def __init__(self):
        self.country, self.asn, self.total = Counter(), Counter(), 0

    def rarity(self, counter: Counter, key) -> float:
        return round(-math.log10((counter[key] + 1) / (self.total + 1)), 2) if self.total else 0.0

    def add(self, events):
        for e in events:
            if e["type"] == "login" and not e["success"]:
                continue
            self.country[e["country"]] += 1
            self.asn[e["asn"]] += 1
            self.total += 1


class ProfileStore:
    def __init__(self):
        self._p: dict[str, Profile] = {}
        self.glob = GlobalStats()

    def get(self, uid: str) -> Profile:
        if uid not in self._p:
            self._p[uid] = Profile(uid)
        return self._p[uid]

    def learn(self, uid: str, events: list[dict]):
        """Absorb a trusted session into the user's profile and the population stats."""
        self.get(uid).update(events)
        self.glob.add(events)


FEATURE_NAMES = [
    "new_device", "new_country", "new_asn", "hosting_ip", "hosting_unusual", "bot_ua",
    "failed_logins", "fail_then_success", "speed_kmh", "km_from_last", "hours_since_last",
    "n_sensitive", "mins_login_to_sensitive", "email_to_disposable", "payout_ratio",
    "new_beneficiary", "session_geo_jump", "hour_dev", "has_chat", "profile_maturity", "threat_ip",
    "country_rarity", "asn_rarity",
]


def session_features(events: list[dict], prof: Profile, glob: GlobalStats | None = None) -> dict:
    """Compute features for one session against the profile *before* it."""
    first = events[0]
    good = [e for e in events if not (e["type"] == "login" and not e["success"])] or events
    f: dict = {}
    devs = {e["device_id"] for e in good}
    f["new_device"] = int(any(d not in prof.devices for d in devs))
    f["new_country"] = int(any(e["country"] not in prof.countries for e in good))
    f["new_asn"] = int(any(e["asn"] not in prof.asns for e in good))
    f["hosting_ip"] = int(any(e["hosting"] for e in events))
    f["hosting_unusual"] = int(f["hosting_ip"] and prof.hosting_seen < 2)
    f["bot_ua"] = int(any(BOT_UA.search(e.get("ua", "")) or e.get("device_type") == "bot" for e in events))
    f["threat_ip"] = int(any(e.get("attack_ip") for e in events))  # threat-intel feed hit
    fails = [e for e in events if e["type"] == "login" and not e["success"]]
    recent = sum(1 for t in prof.recent_fails if 0 <= first["ts"] - t <= 3600)
    f["failed_logins"] = len(fails) + recent
    f["fail_then_success"] = int(f["failed_logins"] >= 3 and any(e["type"] == "login" and e["success"] for e in events))

    # geo-velocity vs last trusted activity (skipped when the source has no coordinates)
    if prof.last_ts is not None and good[0].get("lat") is not None and prof.last_lat is not None:
        km = haversine_km(prof.last_lat, prof.last_lon, good[0]["lat"], good[0]["lon"])
        hrs = max((good[0]["ts"] - prof.last_ts) / 3600, 1 / 60)
        f["km_from_last"], f["hours_since_last"] = round(km), round(hrs, 2)
        f["speed_kmh"] = round(km / hrs) if km > 50 else 0
    else:
        hrs = (good[0]["ts"] - prof.last_ts) / 3600 if prof.last_ts is not None else 999
        f["km_from_last"], f["hours_since_last"], f["speed_kmh"] = 0, round(min(hrs, 999), 2), 0

    sens = [e for e in events if e["type"] in SENSITIVE]
    f["n_sensitive"] = len(sens)
    f["mins_login_to_sensitive"] = round((sens[0]["ts"] - first["ts"]) / 60, 1) if sens else -1
    f["email_to_disposable"] = int(any(e["type"] == "email_change" and
                                       any(d in e.get("new_value", "") for d in DISPOSABLE_DOMAINS)
                                       for e in events))
    pays = [e for e in events if e["type"] == "payout"]
    base = max(prof.payout_p95, 50.0)
    f["payout_ratio"] = round(max((p["amount"] for p in pays), default=0) / base, 2)
    f["new_beneficiary"] = int(any(p["beneficiary"] not in prof.beneficiaries for p in pays))
    # session continuity: same session, different network/country
    f["session_geo_jump"] = int(len({(e["country"], e["asn"]) for e in good}) > 1
                                and len({e["device_id"] for e in good}) == 1)
    if prof.hours:
        mean_h = sum(prof.hours) / len(prof.hours)
        h = (first["ts"] % 86400) / 3600
        f["hour_dev"] = round(min(abs(h - mean_h), 24 - abs(h - mean_h)), 1)
    else:
        f["hour_dev"] = 0
    f["has_chat"] = int(any(e["type"] == "support_chat" for e in events))
    f["country_rarity"] = glob.rarity(glob.country, good[0]["country"]) if glob else 0.0
    f["asn_rarity"] = glob.rarity(glob.asn, good[0]["asn"]) if glob else 0.0
    f["profile_maturity"] = min(prof.sessions, 30)
    return f


def vector(f: dict) -> list[float]:
    v = []
    for k in FEATURE_NAMES:
        x = float(f[k])
        if k in ("speed_kmh", "km_from_last"):
            x = math.log1p(x)
        elif k == "hours_since_last":
            x = math.log1p(min(x, 999))
        elif k == "mins_login_to_sensitive":
            x = -1 if x < 0 else math.log1p(x)
        v.append(x)
    return v


def group_sessions(events: list[dict]) -> dict[str, list[dict]]:
    g = defaultdict(list)
    for e in events:
        g[e["session_id"]].append(e)
    return g
