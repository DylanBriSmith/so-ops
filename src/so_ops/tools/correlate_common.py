"""Shared helpers for correlate: rule categories, IP checks, verdict ranking."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

# ── Rule category helpers ─────────────────────────────────────────────────────

CATEGORY_MAP: list[tuple[str, str]] = [
    ("ET EXPLOIT", "exploit"),
    ("ET TROJAN", "trojan"),
    ("ET MALWARE", "malware"),
    ("ET SHELLCODE", "shellcode"),
    ("ET ATTACK", "attack"),
    ("ET SCAN", "scan"),
    ("ET DOS", "dos"),
    ("ET WEB_SERVER", "web_server"),
    ("ET WEB_CLIENT", "web_client"),
    ("ET INFO", "info"),
    ("ET POLICY", "policy"),
    ("GPL EXPLOIT", "exploit"),
    ("GPL SHELLCODE", "shellcode"),
    ("GPL ATTACK", "attack"),
    ("GPL SCAN", "scan"),
]

HIGH_SEVERITY_CATS = frozenset(["exploit", "trojan", "malware", "shellcode", "attack"])
SCAN_CATS = frozenset(["scan"])
ATTACK_CATS = HIGH_SEVERITY_CATS | SCAN_CATS | frozenset(["dos", "web_server", "web_client"])

CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

# Unique category names in CATEGORY_MAP definition order, plus "other" for unmapped rules.
_REPORT_CATS: list[str] = []
for _cat in (c for _, c in CATEGORY_MAP):
    if _cat not in _REPORT_CATS:
        _REPORT_CATS.append(_cat)
if "other" not in _REPORT_CATS:
    _REPORT_CATS.append("other")
REPORT_CATEGORY_ORDER: tuple[str, ...] = tuple(_REPORT_CATS)
del _cat, _REPORT_CATS


def rule_category(rule_name: str) -> str:
    for prefix, cat in CATEGORY_MAP:
        if rule_name.startswith(prefix):
            return cat
    return "other"


def is_exploit_rule(rule_name: str) -> bool:
    return rule_category(rule_name) in HIGH_SEVERITY_CATS


def is_internal(ip: str, internal_prefixes: list[str]) -> bool:
    return any(ip.startswith(p) for p in internal_prefixes)


def verdict_rank(v: str) -> int:
    return {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(v, 1)


def confidence_rank(confidence: str) -> int:
    return CONFIDENCE_RANK.get(confidence, 9)


def max_verdict(*verdicts: str) -> str:
    return max(verdicts, key=verdict_rank)


def parse_alert_timestamp(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def load_triage_entries(
    jsonl_path: Path,
    cutoff: datetime,
) -> tuple[list[dict], dict[str, int]]:
    """Load triage.jsonl rows in the time window, deduped by alert_id.

    Skips NOISE, rows without alert_id, and rows without a valid alert_timestamp.
    When duplicate alert_ids exist (dry-run re-logging), keeps the newest triaged_at.
    """
    total = skipped_old = skipped_noise = skipped_invalid = skipped_no_id = 0
    by_id: dict[str, dict] = {}

    if not jsonl_path.exists():
        return [], {
            "total": 0,
            "in_window": 0,
            "skipped_old": 0,
            "skipped_noise": 0,
            "skipped_invalid": 0,
            "skipped_no_id": 0,
        }

    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                skipped_invalid += 1
                continue
            total += 1

            if e.get("verdict") == "NOISE":
                skipped_noise += 1
                continue

            ts = parse_alert_timestamp(e.get("alert_timestamp", ""))
            if ts is None:
                skipped_invalid += 1
                continue
            if ts < cutoff:
                skipped_old += 1
                continue

            alert_id = e.get("alert_id")
            if not alert_id:
                skipped_no_id += 1
                continue

            existing = by_id.get(alert_id)
            if existing is None:
                by_id[alert_id] = e
            else:
                new_at = e.get("triaged_at", "")
                old_at = existing.get("triaged_at", "")
                if new_at >= old_at:
                    by_id[alert_id] = e

    entries = list(by_id.values())
    return entries, {
        "total": total,
        "in_window": len(entries),
        "skipped_old": skipped_old,
        "skipped_noise": skipped_noise,
        "skipped_invalid": skipped_invalid,
        "skipped_no_id": skipped_no_id,
    }

