"""Shared helpers for correlate: rule categories, IP checks, verdict ranking."""

from __future__ import annotations

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


def rule_category(rule_name: str) -> str:
    for prefix, cat in CATEGORY_MAP:
        if rule_name.startswith(prefix):
            return cat
    return "other"


def is_internal(ip: str, internal_prefixes: list[str]) -> bool:
    return any(ip.startswith(p) for p in internal_prefixes)


def verdict_rank(v: str) -> int:
    return {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(v, 1)


def max_verdict(*verdicts: str) -> str:
    return max(verdicts, key=verdict_rank)

