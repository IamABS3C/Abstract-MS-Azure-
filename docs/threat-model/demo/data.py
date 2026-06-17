"""
Synthetic but realistic dataset for the demo. One Qakbot-style campaign woven
across email → firewall/WildFire → EDR → identity → cloud, plus historical and
predictive victims, non-user (NHI) and agent identities, and a large floor of
benign noise so the reduction metric is honest.

Derived from the shapes in ../samples.md. Deterministic (seeded).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from pipeline import IOCSet

random.seed(42)

# Incident moment; history runs before it, predictive catch just after.
INCIDENT_START = datetime(2026, 6, 16, 14, 32, 0)
T = INCIDENT_START


def at(**kw) -> datetime:
    return INCIDENT_START + timedelta(**kw)


# WildFire report → IOC bundle (samples.md §1.3). Note 91.219.236.12 is C2 AND the Okta login IP.
SHA = "dca86121cc7427e375fd24fe5871d727a4604532c4f3a567b3c956a3b6b6e0c4"
IOCS = IOCSet(
    domains={"cdn.evil-delivery.com", "api.telemetry-sync.net"},
    ips={"185.220.101.45", "91.219.236.12"},
    urls={"http://cdn.evil-delivery.com/inv/invoice_8841.exe"},
    hashes={SHA},
)

BENIGN_HOSTS = [f"ACME-LT-{n:04d}" for n in range(1000, 1040)]
BENIGN_USERS = [f"user{n}@acme.com" for n in range(1, 40)]
BENIGN_DOMAINS = ["office.com", "windowsupdate.com", "slack.com", "github.com",
                  "salesforce.com", "zoom.us", "google.com", "okta.com"]
BENIGN_IPS = [f"52.{random.randint(1,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
              for _ in range(60)]


def events() -> list:
    ev = []

    # ── benign floor: ~5,000 events over 14 days across the estate ──────────────
    for i in range(5000):
        ts = at(days=-random.randint(0, 14), minutes=-random.randint(0, 1440))
        roll = random.random()
        if roll < 0.5:
            ev.append({"_t": "benign_traffic", "ts": ts,
                       "host": random.choice(BENIGN_HOSTS), "dst": random.choice(BENIGN_IPS),
                       "bytes": random.randint(2000, 900000)})
        elif roll < 0.85:
            ev.append({"_t": "benign_dns", "ts": ts,
                       "host": random.choice(BENIGN_HOSTS), "query": random.choice(BENIGN_DOMAINS)})
        else:
            ev.append({"_t": "benign_auth", "ts": ts,
                       "account": "okta:" + random.choice(BENIGN_USERS),
                       "src_ip": random.choice(BENIGN_IPS)})

    # ── HISTORICAL victim (pre-verdict): host B resolved a C2 domain 9 days ago ──
    ev.append({"_t": "dns", "ts": at(days=-9, hours=3),
               "host": "ACME-LT-2210", "user": "bchen@acme.com",
               "query": "api.telemetry-sync.net", "resp": "91.219.236.12", "sev": "informational"})
    ev.append({"_t": "pan_traffic", "ts": at(days=-9, hours=3, minutes=1),
               "host": "ACME-LT-2210", "dst": "91.219.236.12", "bytes": 1100})

    # ── REAL-TIME incident chain (patient zero: jsmith / host A) ────────────────
    ev.append({"_t": "email", "ts": at(minutes=-6),
               "to": "okta:jsmith@acme.com", "sha256": SHA,
               "url": "http://cdn.evil-delivery.com/inv/invoice_8841.exe", "verdict": "malicious"})
    ev.append({"_t": "dns", "ts": at(minutes=-4),
               "host": "ACME-LT-4471", "user": "jsmith@acme.com",
               "query": "cdn.evil-delivery.com", "resp": "185.220.101.45", "sev": "high"})
    ev.append({"_t": "pan_wildfire", "ts": at(seconds=0),
               "host": "ACME-LT-4471", "user": "jsmith@acme.com", "dst": "185.220.101.45",
               "url": "http://cdn.evil-delivery.com/inv/invoice_8841.exe", "sha256": SHA})
    ev.append({"_t": "edr", "ts": at(seconds=20),
               "host": "ACME-LT-4471", "user": "jsmith@acme.com",
               "sha256": SHA, "proc": "ACME-LT-4471:2210:powershell.exe"})
    # beacon to C2 (periodic, low volume)
    for k in range(6):
        ev.append({"_t": "pan_traffic", "ts": at(seconds=60 + k * 60),
                   "host": "ACME-LT-4471", "dst": "91.219.236.12", "bytes": 480 + k * 5})
    # ATO: jsmith logs in from the C2 IP (impossible travel / new ASN)
    ev.append({"_t": "okta", "ts": at(minutes=9),
               "account": "okta:jsmith@acme.com", "user": "jsmith@acme.com",
               "src_ip": "91.219.236.12", "sev": "high"})
    # post-ATO cloud action from same IP
    ev.append({"_t": "cloudtrail", "ts": at(minutes=12),
               "account": "aws:jsmith", "src_ip": "91.219.236.12", "sev": "high"})

    # ── PREDICTIVE catch: host C contacts C2 AFTER the verdict, no local conviction ─
    ev.append({"_t": "pan_traffic", "ts": at(minutes=18),
               "host": "ACME-LT-8802", "dst": "185.220.101.45", "bytes": 2300})
    ev.append({"_t": "dns", "ts": at(minutes=17),
               "host": "ACME-LT-8802", "user": "mraj@acme.com",
               "query": "cdn.evil-delivery.com", "resp": "185.220.101.45", "sev": "high"})

    # ── NON-USER / NHI: CI service token used from the C2 ASN ───────────────────
    ev.append({"_t": "nhi", "ts": at(minutes=22),
               "nhi": "svc-ci-pipeline", "src_ip": "91.219.236.12", "sev": "high"})

    # ── AGENTIC: an AI/MCP agent identity beacons to C2 (agentic exposure) ───────
    ev.append({"_t": "agent", "ts": at(minutes=25),
               "agent": "agent-soc-autobot", "src_ip": "10.20.0.9",
               "dst": "185.220.101.45", "sev": "high"})

    ev.sort(key=lambda e: e["ts"])
    return ev
