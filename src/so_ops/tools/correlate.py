"""Alert correlation engine: alert×alert patterns + alert×vulnscan cross-reference.

Pass 1: pure rule-based pattern detection (always runs, no LLM).
Pass 2: alert × vulnscan cross-reference (optional, needs scan data).
Pass 3: LLM brief — HIGH+MEDIUM findings sent to LLM for prioritised analyst summary.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import defusedxml.ElementTree as ET  # type: ignore[import]
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]

from so_ops.clients import make_llm_client
from so_ops.clients.notify import notify_all
from so_ops.config import Config
from so_ops.log import setup_logging
from so_ops.state import ToolState

# ── Rule category helpers ─────────────────────────────────────────────────────

_CATEGORY_MAP: list[tuple[str, str]] = [
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

_HIGH_SEVERITY_CATS = frozenset(["exploit", "trojan", "malware", "shellcode", "attack"])
_SCAN_CATS = frozenset(["scan"])
_ATTACK_CATS = _HIGH_SEVERITY_CATS | _SCAN_CATS | frozenset(["dos", "web_server", "web_client"])


def _rule_category(rule_name: str) -> str:
    for prefix, cat in _CATEGORY_MAP:
        if rule_name.startswith(prefix):
            return cat
    return "other"


def _is_internal(ip: str, internal_prefixes: list[str]) -> bool:
    return any(ip.startswith(p) for p in internal_prefixes)


def _verdict_rank(v: str) -> int:
    return {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(v, 1)


def _max_verdict(*verdicts: str) -> str:
    return max(verdicts, key=_verdict_rank)


# ── Alert × Alert pattern detection ──────────────────────────────────────────

# Thresholds
_LATERAL_DEST_MIN = 4  # distinct internal dest_ips from one src = lateral movement
_PORT_SWEEP_MIN = 3  # same port on N distinct hosts = port sweep
_MULTI_RULE_PAIR_MIN = 4  # distinct rules on same src->dest pair = sustained attack
_HIGH_VOL_MIN = 30  # alerts from one src = high-volume flag
_C2_RULE_MIN = 3  # distinct TROJAN/MALWARE rules on same pair = C2 pattern
_INBOUND_SWEEP_MIN = 4  # external src reaching N internal hosts
_BRUTE_FORCE_MIN = 10  # alerts on auth port from same src->dest pair
_SINGLE_RULE_FLOOD_MIN = 100  # same src fires same rule N times
_PIVOT_SRC_CAT_MIN = 3  # distinct non-INFO categories for src_ip_pivot
_PIVOT_SRC_ALERT_MIN = 5  # min alerts for src_ip_pivot
_PIVOT_DEST_RULE_MIN = 5  # distinct rules for dest_ip_pivot
_PIVOT_DEST_SRC_MIN = 2  # distinct src_ips for dest_ip_pivot
_PIVOT_PORT_SRC_MIN = 3  # distinct src_ips for dest_port_pivot
_PIVOT_PORT_ALERT_MIN = 5  # min alerts for dest_port_pivot

_AUTH_PORTS = {21, 22, 23, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 5984, 5985, 5986}


def _build_pattern(
    pattern_type: str,
    confidence: str,
    pivot_ip: str,
    pivot_role: str,
    reason: str,
    recommended_verdict: str,
    rule_names: list[str],
    categories: list[str],
    alert_count: int,
    time_first: str = "",
    time_last: str = "",
    dest_ips: list[str] | None = None,
    dest_port: str = "",
    peer_ip: str = "",
    community_ids: list[str] | None = None,
) -> dict:
    return {
        "correlated_at": datetime.now(timezone.utc).isoformat(),
        "source": "alert_pattern",
        "pattern_type": pattern_type,
        "confidence": confidence,
        "pivot_ip": pivot_ip,
        "pivot_role": pivot_role,
        "peer_ip": peer_ip,
        "dest_ips": dest_ips or [],
        "dest_port": dest_port,
        "rule_names": sorted(set(rule_names))[:20],
        "categories": sorted(set(categories)),
        "alert_count": alert_count,
        "time_first": time_first,
        "time_last": time_last,
        "recommended_verdict": recommended_verdict,
        "confidence_rank": {"high": 0, "medium": 1, "low": 2}.get(confidence, 9),
        "verdict_rank": _verdict_rank(recommended_verdict),
        "reason": reason,
        "community_ids": sorted(set(community_ids or []))[:10],
    }


def _correlate_alert_patterns(
    entries: list[dict],
    internal_prefixes: list[str],
    log,
) -> list[dict]:
    """Detect behavioural patterns purely within the triage alert log."""

    # Index structures
    by_src: dict[str, list[dict]] = defaultdict(list)
    by_dest: dict[str, list[dict]] = defaultdict(list)
    by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for e in entries:
        src = e.get("source_ip", "")
        dst = e.get("dest_ip", "")
        if src and src != "?":
            by_src[src].append(e)
        if dst and dst != "?":
            by_dest[dst].append(e)
        if src and dst and src != "?" and dst != "?":
            by_pair[(src, dst)].append(e)

    patterns: list[dict] = []

    # ── Pattern 1: scan→exploit from same src ──────────────────────────
    # src_ip fires scan-category rules AND exploit/trojan/malware/attack rules
    for src_ip, src_entries in by_src.items():
        cats = {_rule_category(e["rule_name"]) for e in src_entries}
        has_scan = bool(cats & _SCAN_CATS)
        has_high = bool(cats & _HIGH_SEVERITY_CATS)
        if not (has_scan and has_high):
            continue

        scan_rules = [
            e["rule_name"] for e in src_entries if _rule_category(e["rule_name"]) in _SCAN_CATS
        ]
        exploit_rules = [
            e["rule_name"]
            for e in src_entries
            if _rule_category(e["rule_name"]) in _HIGH_SEVERITY_CATS
        ]
        times = sorted(e["alert_timestamp"] for e in src_entries if e.get("alert_timestamp"))
        dest_ips = sorted(
            {e["dest_ip"] for e in src_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )

        reason = (
            f"{src_ip} fired SCAN rules ({len(set(scan_rules))} distinct) "
            f"AND high-severity rules ({len(set(exploit_rules))} distinct: "
            f"{', '.join(sorted(set(exploit_rules))[:3])}...) — classic attack chain"
        )
        log.info(
            "  SCAN->EXPLOIT [src=%s]: %d scan + %d exploit rules, %d targets",
            src_ip,
            len(set(scan_rules)),
            len(set(exploit_rules)),
            len(dest_ips),
        )
        patterns.append(
            _build_pattern(
                pattern_type="scan_to_exploit",
                confidence="high",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="HIGH",
                rule_names=scan_rules + exploit_rules,
                categories=sorted(cats & (_SCAN_CATS | _HIGH_SEVERITY_CATS)),
                alert_count=len(src_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=dest_ips,
                community_ids=[
                    e.get("community_id", "") for e in src_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 2: targeted host — same dest hit by scan + exploit ─────
    for dest_ip, dest_entries in by_dest.items():
        cats = {_rule_category(e["rule_name"]) for e in dest_entries}
        has_scan = bool(cats & _SCAN_CATS)
        has_high = bool(cats & _HIGH_SEVERITY_CATS)
        if not (has_scan and has_high):
            continue

        src_ips = sorted(
            {e["source_ip"] for e in dest_entries if e.get("source_ip") and e["source_ip"] != "?"}
        )
        rule_names = [e["rule_name"] for e in dest_entries]
        times = sorted(e["alert_timestamp"] for e in dest_entries if e.get("alert_timestamp"))

        reason = (
            f"{dest_ip} was targeted by both SCAN and high-severity rules "
            f"from {len(src_ips)} source(s) — host is being actively probed and attacked"
        )
        log.info("  TARGETED HOST [dest=%s]: scan+exploit from %d sources", dest_ip, len(src_ips))
        patterns.append(
            _build_pattern(
                pattern_type="targeted_host",
                confidence="high",
                pivot_ip=dest_ip,
                pivot_role="dest",
                reason=reason,
                recommended_verdict="HIGH",
                rule_names=rule_names,
                categories=sorted(cats & (_SCAN_CATS | _HIGH_SEVERITY_CATS)),
                alert_count=len(dest_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=[dest_ip],
                community_ids=[
                    e.get("community_id", "") for e in dest_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 3: lateral movement — src reaching many internal dests ─
    for src_ip, src_entries in by_src.items():
        internal_dests = {
            e["dest_ip"]
            for e in src_entries
            if e.get("dest_ip")
            and e["dest_ip"] != "?"
            and _is_internal(e["dest_ip"], internal_prefixes)
        }
        if len(internal_dests) < _LATERAL_DEST_MIN:
            continue

        rule_names = [e["rule_name"] for e in src_entries]
        cats = {_rule_category(r) for r in rule_names}
        times = sorted(e["alert_timestamp"] for e in src_entries if e.get("alert_timestamp"))
        src_internal = _is_internal(src_ip, internal_prefixes)
        role_note = "internal source" if src_internal else "external source"

        reason = (
            f"{src_ip} ({role_note}) reached {len(internal_dests)} distinct internal hosts — "
            f"possible {'lateral movement' if src_internal else 'external scan of internal network'}"
        )
        log.info("  LATERAL MOVEMENT [src=%s]: %d internal dests", src_ip, len(internal_dests))
        patterns.append(
            _build_pattern(
                pattern_type="lateral_movement",
                confidence="medium",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="MEDIUM",
                rule_names=rule_names,
                categories=sorted(cats),
                alert_count=len(src_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=sorted(internal_dests),
                community_ids=[
                    e.get("community_id", "") for e in src_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 4: port sweep — same src, same port, many hosts ────────
    # Group by (src_ip, dest_port) and count distinct dests
    by_src_port: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in entries:
        src = e.get("source_ip", "")
        port = str(e.get("dest_port", ""))
        if src and src != "?" and port and port != "?":
            by_src_port[(src, port)].append(e)

    for (src_ip, port), port_entries in by_src_port.items():
        distinct_dests = {
            e["dest_ip"] for e in port_entries if e.get("dest_ip") and e["dest_ip"] != "?"
        }
        if len(distinct_dests) < _PORT_SWEEP_MIN:
            continue

        rule_names = [e["rule_name"] for e in port_entries]
        cats = {_rule_category(r) for r in rule_names}
        times = sorted(e["alert_timestamp"] for e in port_entries if e.get("alert_timestamp"))

        reason = (
            f"{src_ip} hit port {port} on {len(distinct_dests)} distinct hosts "
            f"({', '.join(sorted(distinct_dests)[:5])}{'...' if len(distinct_dests) > 5 else ''}) "
            f"— service-specific sweep"
        )
        log.info("  PORT SWEEP [src=%s port=%s]: %d hosts", src_ip, port, len(distinct_dests))
        patterns.append(
            _build_pattern(
                pattern_type="port_sweep",
                confidence="medium",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="MEDIUM",
                rule_names=rule_names,
                categories=sorted(cats),
                alert_count=len(port_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=sorted(distinct_dests),
                dest_port=port,
                community_ids=[
                    e.get("community_id", "") for e in port_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 5: sustained multi-rule attack on same pair ─────────────
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        distinct_rules = {e["rule_name"] for e in pair_entries}
        if len(distinct_rules) < _MULTI_RULE_PAIR_MIN:
            continue

        cats = {_rule_category(r) for r in distinct_rules}
        times = sorted(e["alert_timestamp"] for e in pair_entries if e.get("alert_timestamp"))

        reason = (
            f"{src_ip} → {dest_ip}: {len(distinct_rules)} distinct rules fired "
            f"across {len(pair_entries)} alerts — sustained, varied activity on this connection"
        )
        log.info(
            "  MULTI-RULE PAIR [%s->%s]: %d distinct rules", src_ip, dest_ip, len(distinct_rules)
        )
        patterns.append(
            _build_pattern(
                pattern_type="multi_rule_pair",
                confidence="medium",
                pivot_ip=src_ip,
                pivot_role="src",
                peer_ip=dest_ip,
                reason=reason,
                recommended_verdict=_max_verdict(
                    "MEDIUM", *[e.get("verdict", "LOW") for e in pair_entries]
                ),
                rule_names=sorted(distinct_rules),
                categories=sorted(cats),
                alert_count=len(pair_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=[dest_ip],
                community_ids=[
                    e.get("community_id", "") for e in pair_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 6: C2 / beaconing — TROJAN/MALWARE rules on same pair ──
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        c2_entries = [
            e for e in pair_entries if _rule_category(e["rule_name"]) in ("trojan", "malware")
        ]
        distinct_c2_rules = {e["rule_name"] for e in c2_entries}
        if len(distinct_c2_rules) < _C2_RULE_MIN:
            continue

        times = sorted(e["alert_timestamp"] for e in c2_entries if e.get("alert_timestamp"))
        cats = {_rule_category(e["rule_name"]) for e in c2_entries}

        reason = (
            f"{src_ip} → {dest_ip}: {len(distinct_c2_rules)} distinct TROJAN/MALWARE rules "
            f"across {len(c2_entries)} alerts — possible C2 channel or infected host"
        )
        log.info(
            "  C2 BEACON [%s->%s]: %d trojan/malware rules", src_ip, dest_ip, len(distinct_c2_rules)
        )
        patterns.append(
            _build_pattern(
                pattern_type="c2_beacon",
                confidence="high",
                pivot_ip=src_ip,
                pivot_role="src",
                peer_ip=dest_ip,
                reason=reason,
                recommended_verdict="HIGH",
                rule_names=sorted(distinct_c2_rules),
                categories=sorted(cats),
                alert_count=len(c2_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=[dest_ip],
                community_ids=[
                    e.get("community_id", "") for e in c2_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 7: high-volume single source ───────────────────────────
    for src_ip, src_entries in by_src.items():
        if len(src_entries) < _HIGH_VOL_MIN:
            continue

        distinct_rules = {e["rule_name"] for e in src_entries}
        cats = {_rule_category(r) for r in distinct_rules}
        # Skip if already caught by scan→exploit or lateral movement
        already_flagged = any(
            p["pivot_ip"] == src_ip and p["pattern_type"] in ("scan_to_exploit", "lateral_movement")
            for p in patterns
        )
        if already_flagged:
            continue

        times = sorted(e["alert_timestamp"] for e in src_entries if e.get("alert_timestamp"))
        has_attack_cat = bool(cats & _ATTACK_CATS)

        reason = (
            f"{src_ip} generated {len(src_entries)} alerts with {len(distinct_rules)} distinct rules "
            f"— {'includes attack-category rules' if has_attack_cat else 'high volume, review for false positives'}"
        )
        log.info(
            "  HIGH VOLUME [src=%s]: %d alerts, %d rules",
            src_ip,
            len(src_entries),
            len(distinct_rules),
        )
        patterns.append(
            _build_pattern(
                pattern_type="high_volume_src",
                confidence="medium" if has_attack_cat else "low",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="MEDIUM" if has_attack_cat else "LOW",
                rule_names=sorted(distinct_rules)[:20],
                categories=sorted(cats),
                alert_count=len(src_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                community_ids=[
                    e.get("community_id", "") for e in src_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 8: inbound sweep — external src → many internal dests ─────
    for src_ip, src_entries in by_src.items():
        if _is_internal(src_ip, internal_prefixes):
            continue
        if any(
            p["pivot_ip"] == src_ip and p["pattern_type"] == "scan_to_exploit" for p in patterns
        ):
            continue

        internal_dests = {
            e["dest_ip"]
            for e in src_entries
            if e.get("dest_ip")
            and e["dest_ip"] != "?"
            and _is_internal(e["dest_ip"], internal_prefixes)
        }
        if len(internal_dests) < _INBOUND_SWEEP_MIN:
            continue

        rule_names = [e["rule_name"] for e in src_entries]
        cats = {_rule_category(r) for r in rule_names}
        times = sorted(e["alert_timestamp"] for e in src_entries if e.get("alert_timestamp"))
        reason = (
            f"External IP {src_ip} reached {len(internal_dests)} distinct internal hosts "
            f"({', '.join(sorted(internal_dests)[:6])}{'...' if len(internal_dests) > 6 else ''}) "
            f"— internet-originated sweep of internal network segment"
        )
        log.info("  INBOUND SWEEP [src=%s]: %d internal targets", src_ip, len(internal_dests))
        patterns.append(
            _build_pattern(
                pattern_type="inbound_sweep",
                confidence="high",
                pivot_ip=src_ip,
                pivot_role="src (external)",
                reason=reason,
                recommended_verdict="HIGH",
                rule_names=rule_names,
                categories=sorted(cats),
                alert_count=len(src_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=sorted(internal_dests),
                community_ids=[
                    e.get("community_id", "") for e in src_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 9: brute force — repeated alerts on auth ports same pair ──
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        auth_entries = [e for e in pair_entries if int(e.get("dest_port", 0) or 0) in _AUTH_PORTS]
        if len(auth_entries) < _BRUTE_FORCE_MIN:
            continue

        ports_hit = sorted(
            {str(e.get("dest_port", "")) for e in auth_entries if e.get("dest_port")}
        )
        rule_names = [e["rule_name"] for e in auth_entries]
        cats = {_rule_category(r) for r in rule_names}
        times = sorted(e["alert_timestamp"] for e in auth_entries if e.get("alert_timestamp"))
        reason = (
            f"{src_ip} -> {dest_ip}: {len(auth_entries)} alerts on auth port(s) "
            f"{', '.join(ports_hit)} — repeated authentication attempts "
            f"(brute force / credential stuffing)"
        )
        log.info(
            "  BRUTE FORCE [%s->%s]: %d alerts on auth ports %s",
            src_ip,
            dest_ip,
            len(auth_entries),
            ports_hit,
        )
        patterns.append(
            _build_pattern(
                pattern_type="brute_force",
                confidence="medium",
                pivot_ip=src_ip,
                pivot_role="src",
                peer_ip=dest_ip,
                reason=reason,
                recommended_verdict="MEDIUM",
                rule_names=rule_names,
                categories=sorted(cats),
                alert_count=len(auth_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=[dest_ip],
                dest_port=ports_hit[0] if len(ports_hit) == 1 else ", ".join(ports_hit),
                community_ids=[
                    e.get("community_id", "") for e in auth_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 10: single rule flood — same src fires same rule 100+ × ──
    by_src_rule: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in entries:
        src = e.get("source_ip", "")
        rule = e.get("rule_name", "")
        if src and src != "?" and rule:
            by_src_rule[(src, rule)].append(e)

    for (src_ip, rule_name), flood_entries in by_src_rule.items():
        if len(flood_entries) < _SINGLE_RULE_FLOOD_MIN:
            continue

        dest_ips = sorted(
            {e["dest_ip"] for e in flood_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )
        dest_ports = sorted(
            {str(e.get("dest_port", "")) for e in flood_entries if e.get("dest_port")}
        )
        times = sorted(e["alert_timestamp"] for e in flood_entries if e.get("alert_timestamp"))
        cat = _rule_category(rule_name)
        reason = (
            f"{src_ip} fired '{rule_name}' {len(flood_entries)} times "
            f"against {len(dest_ips)} host(s) — repeated identical rule: "
            f"possible worm, DDoS probe, or misconfigured device"
        )
        log.info(
            "  SINGLE RULE FLOOD [src=%s rule=%.40s]: %d alerts",
            src_ip,
            rule_name,
            len(flood_entries),
        )
        patterns.append(
            _build_pattern(
                pattern_type="single_rule_flood",
                confidence="medium" if cat in _ATTACK_CATS else "low",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="MEDIUM" if cat in _ATTACK_CATS else "LOW",
                rule_names=[rule_name],
                categories=[cat],
                alert_count=len(flood_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=dest_ips,
                dest_port=dest_ports[0] if len(dest_ports) == 1 else "",
                community_ids=[
                    e.get("community_id", "") for e in flood_entries if e.get("community_id")
                ],
            )
        )

    # ── Pattern 11: internal→internal exploit ─────────────────────────────
    flagged_pairs = {
        (p["pivot_ip"], p["peer_ip"])
        for p in patterns
        if p.get("peer_ip") and p["pattern_type"] in ("c2_beacon", "multi_rule_pair")
    }
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        if not _is_internal(src_ip, internal_prefixes):
            continue
        if not _is_internal(dest_ip, internal_prefixes):
            continue
        if (src_ip, dest_ip) in flagged_pairs:
            continue

        exploit_entries = [
            e for e in pair_entries if _rule_category(e["rule_name"]) in _HIGH_SEVERITY_CATS
        ]
        if not exploit_entries:
            continue

        rule_names = [e["rule_name"] for e in exploit_entries]
        cats = {_rule_category(r) for r in rule_names}
        times = sorted(e["alert_timestamp"] for e in exploit_entries if e.get("alert_timestamp"))
        distinct_rules = set(rule_names)
        reason = (
            f"Internal host {src_ip} fired {len(distinct_rules)} high-severity rule(s) "
            f"against internal {dest_ip} ({len(exploit_entries)} alerts) "
            f"— lateral exploitation attempt within the network"
        )
        log.info(
            "  INTERNAL EXPLOIT [%s->%s]: %d high-sev rules",
            src_ip,
            dest_ip,
            len(distinct_rules),
        )
        patterns.append(
            _build_pattern(
                pattern_type="internal_exploit",
                confidence="high",
                pivot_ip=src_ip,
                pivot_role="src (internal)",
                peer_ip=dest_ip,
                reason=reason,
                recommended_verdict="HIGH",
                rule_names=rule_names,
                categories=sorted(cats),
                alert_count=len(exploit_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=[dest_ip],
                community_ids=[
                    e.get("community_id", "") for e in exploit_entries if e.get("community_id")
                ],
            )
        )

    # ── Field pivot: src_ip — shared source across diverse rules ──────────
    already_pivoted_src = {
        p["pivot_ip"]
        for p in patterns
        if p["pivot_role"] in ("src", "src (external)", "src (internal)")
    }
    for src_ip, src_entries in by_src.items():
        if src_ip in already_pivoted_src:
            continue
        if len(src_entries) < _PIVOT_SRC_ALERT_MIN:
            continue

        non_info_cats = {_rule_category(e["rule_name"]) for e in src_entries} - {"info", "policy"}
        if len(non_info_cats) < _PIVOT_SRC_CAT_MIN:
            continue

        dest_ips = sorted(
            {e["dest_ip"] for e in src_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )
        rule_names = sorted({e["rule_name"] for e in src_entries})
        all_cats = {_rule_category(e["rule_name"]) for e in src_entries}
        times = sorted(e["alert_timestamp"] for e in src_entries if e.get("alert_timestamp"))
        reason = (
            f"{src_ip} is the source IP across {len(src_entries)} alerts "
            f"spanning {len(rule_names)} rules in {len(non_info_cats)} non-INFO categories "
            f"({', '.join(sorted(non_info_cats))}) targeting {len(dest_ips)} host(s)"
        )
        log.info(
            "  SRC PIVOT [src=%s]: %d alerts, %d categories",
            src_ip,
            len(src_entries),
            len(non_info_cats),
        )
        patterns.append(
            _build_pattern(
                pattern_type="src_ip_pivot",
                confidence="low",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="LOW",
                rule_names=rule_names[:20],
                categories=sorted(all_cats),
                alert_count=len(src_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=dest_ips,
                community_ids=[
                    e.get("community_id", "") for e in src_entries if e.get("community_id")
                ],
            )
        )

    # ── Field pivot: dest_ip — shared dest targeted by many rules/sources ─
    already_pivoted_dest = {p["pivot_ip"] for p in patterns if p["pivot_role"] == "dest"}
    for dest_ip, dest_entries in by_dest.items():
        if dest_ip in already_pivoted_dest:
            continue

        distinct_rules = {e["rule_name"] for e in dest_entries}
        distinct_srcs = {
            e["source_ip"] for e in dest_entries if e.get("source_ip") and e["source_ip"] != "?"
        }
        if len(distinct_rules) < _PIVOT_DEST_RULE_MIN or len(distinct_srcs) < _PIVOT_DEST_SRC_MIN:
            continue

        cats = {_rule_category(r) for r in distinct_rules}
        times = sorted(e["alert_timestamp"] for e in dest_entries if e.get("alert_timestamp"))
        reason = (
            f"{dest_ip} is the destination across {len(dest_entries)} alerts "
            f"spanning {len(distinct_rules)} distinct rules from {len(distinct_srcs)} source(s) "
            f"— this host is being targeted from multiple angles"
        )
        log.info(
            "  DEST PIVOT [dest=%s]: %d rules from %d sources",
            dest_ip,
            len(distinct_rules),
            len(distinct_srcs),
        )
        patterns.append(
            _build_pattern(
                pattern_type="dest_ip_pivot",
                confidence="low",
                pivot_ip=dest_ip,
                pivot_role="dest",
                reason=reason,
                recommended_verdict="LOW",
                rule_names=sorted(distinct_rules)[:20],
                categories=sorted(cats),
                alert_count=len(dest_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=[dest_ip],
                community_ids=[
                    e.get("community_id", "") for e in dest_entries if e.get("community_id")
                ],
            )
        )

    # ── Field pivot: dest_port — same port targeted by many sources ────────
    by_dest_port: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        port = str(e.get("dest_port", ""))
        if port and port != "?":
            by_dest_port[port].append(e)

    already_swept_ports = {p["dest_port"] for p in patterns if p["pattern_type"] == "port_sweep"}
    for port, port_entries in by_dest_port.items():
        if port in already_swept_ports:
            continue

        distinct_srcs = {
            e["source_ip"] for e in port_entries if e.get("source_ip") and e["source_ip"] != "?"
        }
        if len(distinct_srcs) < _PIVOT_PORT_SRC_MIN or len(port_entries) < _PIVOT_PORT_ALERT_MIN:
            continue

        non_info = [
            e for e in port_entries if _rule_category(e["rule_name"]) not in ("info", "policy")
        ]
        if not non_info:
            continue

        dest_ips = sorted(
            {e["dest_ip"] for e in port_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )
        rule_names = sorted({e["rule_name"] for e in port_entries})
        cats = {_rule_category(r) for r in rule_names}
        times = sorted(e["alert_timestamp"] for e in port_entries if e.get("alert_timestamp"))
        reason = (
            f"Port {port} is the destination port across {len(port_entries)} alerts "
            f"from {len(distinct_srcs)} distinct source(s) targeting {len(dest_ips)} host(s) "
            f"— possible service-specific attack or coordinated scan"
        )
        log.info(
            "  PORT PIVOT [port=%s]: %d alerts from %d sources",
            port,
            len(port_entries),
            len(distinct_srcs),
        )
        patterns.append(
            _build_pattern(
                pattern_type="dest_port_pivot",
                confidence="low",
                pivot_ip="",
                pivot_role="port",
                reason=reason,
                recommended_verdict="LOW",
                rule_names=rule_names[:20],
                categories=sorted(cats),
                alert_count=len(port_entries),
                time_first=times[0] if times else "",
                time_last=times[-1] if times else "",
                dest_ips=dest_ips,
                dest_port=port,
                community_ids=[
                    e.get("community_id", "") for e in port_entries if e.get("community_id")
                ],
            )
        )

    # Sort: high confidence first, then by verdict rank
    patterns.sort(key=lambda p: (p["confidence_rank"], p["verdict_rank"]))
    log.info("Alert patterns found: %d", len(patterns))
    return patterns


# ── Vulnscan data loading ─────────────────────────────────────────────────────

_SERVICE_KEYWORDS: list[tuple[str, list[str]]] = [
    ("apache", ["Apache", "HTTP", "Log4j", "Tomcat", "Struts"]),
    ("openssh", ["SSH", "OpenSSH"]),
    ("microsoft-ds", ["SMB", "MS17-010", "EternalBlue", "SAMBA"]),
    ("netbios", ["SMB", "NetBIOS", "NTLM"]),
    ("rdp", ["RDP", "Remote Desktop", "MS-RDP"]),
    ("ms-sql", ["SQL", "MSSQL", "Microsoft SQL"]),
    ("mysql", ["MySQL", "SQL"]),
    ("postgresql", ["PostgreSQL", "Postgres"]),
    ("ftp", ["FTP"]),
    ("telnet", ["Telnet"]),
    ("smtp", ["SMTP", "Mail"]),
    ("iis", ["IIS", "HTTP"]),
    ("nginx", ["nginx", "HTTP"]),
    ("samba", ["Samba", "SMB"]),
    ("vnc", ["VNC"]),
    ("elasticsearch", ["Elasticsearch"]),
    ("redis", ["Redis"]),
    ("mongodb", ["MongoDB"]),
]

_EXPLOIT_RULE_PREFIXES = (
    "ET EXPLOIT",
    "ET TROJAN",
    "ET MALWARE",
    "ET ATTACK",
    "ET SHELLCODE",
    "GPL EXPLOIT",
    "GPL SHELLCODE",
    "GPL ATTACK",
)

MATCH_EXACT_CVE = "exact_cve"
MATCH_NUCLEI_CVE = "nuclei_cve"
MATCH_SERVICE_KEYWORD = "service_keyword"
MATCH_TARGETED_HOST = "targeted_host"

_VULN_CONFIDENCE = {
    MATCH_EXACT_CVE: "high",
    MATCH_NUCLEI_CVE: "high",
    MATCH_SERVICE_KEYWORD: "medium",
    MATCH_TARGETED_HOST: "low",
}
_VULN_UPGRADES = {
    MATCH_EXACT_CVE: "HIGH",
    MATCH_NUCLEI_CVE: "HIGH",
    MATCH_SERVICE_KEYWORD: "MEDIUM",
    MATCH_TARGETED_HOST: "MEDIUM",
}


def _find_latest_file(directory: Path, glob: str) -> Path | None:
    matches = sorted(directory.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _load_nmap_index(xml_path: Path, log) -> dict[str, dict]:
    index: dict[str, dict] = {}
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        log.error("Failed to parse nmap XML %s: %s", xml_path, exc)
        return index

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")

        hostname = ""
        hn_elem = host_elem.find("hostnames/hostname")
        if hn_elem is not None:
            hostname = hn_elem.get("name", "")

        cves: list[dict] = []
        services: list[str] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            port_id = port_elem.get("portid", "?")
            protocol = port_elem.get("protocol", "tcp")
            svc = port_elem.find("service")
            svc_name = svc.get("name", "") if svc is not None else ""
            product = (
                f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                if svc is not None
                else ""
            )
            services.append(f"{port_id}/{protocol} {svc_name} {product}".strip())

            for script in port_elem.findall("script"):
                if script.get("id") != "vulners":
                    continue
                for line in script.get("output", "").split("\n"):
                    m = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.?\d*)", line.strip())
                    if m:
                        cves.append(
                            {
                                "cve": m.group(1),
                                "cvss": float(m.group(2)),
                                "port": f"{port_id}/{protocol}",
                                "service": product or svc_name,
                            }
                        )

        cves.sort(key=lambda v: v["cvss"], reverse=True)
        index[ip] = {"hostname": hostname, "cves": cves, "services": services}

    log.info("nmap index: %d hosts from %s", len(index), xml_path.name)
    return index


def _load_nuclei_index(jsonl_path: Path, log) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    try:
        lines = jsonl_path.read_text(encoding="utf-8").strip().split("\n")
    except OSError as exc:
        log.error("Failed to read nuclei JSONL %s: %s", jsonl_path, exc)
        return index

    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", entry.get("host", ""))
        if not m:
            continue
        ip = m.group(1)
        cve_ids = entry.get("info", {}).get("classification", {}).get("cve-id", []) or []
        index.setdefault(ip, []).append(
            {
                "template_id": entry.get("template-id", ""),
                "name": entry.get("info", {}).get("name", ""),
                "severity": entry.get("info", {}).get("severity", ""),
                "matched_at": entry.get("matched-at", ""),
                "cve_ids": cve_ids,
            }
        )

    log.info("nuclei index: %d hosts from %s", len(index), jsonl_path.name)
    return index


# ── Alert × Vulnscan correlation ─────────────────────────────────────────────


def _cves_in_rule(rule_name: str) -> list[str]:
    return re.findall(r"CVE-\d{4}-\d+", rule_name, re.IGNORECASE)


def _is_exploit_rule(rule_name: str) -> bool:
    return any(rule_name.startswith(p) for p in _EXPLOIT_RULE_PREFIXES)


def _svc_keywords_match(rule_name: str, services: list[str]) -> list[str]:
    matches = []
    svcs_lower = " ".join(services).lower()
    rule_lower = rule_name.lower()
    for svc_key, terms in _SERVICE_KEYWORDS:
        if svc_key not in svcs_lower:
            continue
        for term in terms:
            if term.lower() in rule_lower:
                for svc in services:
                    if svc_key in svc.lower() and svc not in matches:
                        matches.append(svc)
                        break
    return matches


def _vuln_recommend(match_type: str, current: str) -> str:
    target = _VULN_UPGRADES.get(match_type, current)
    return target if _verdict_rank(target) > _verdict_rank(current) else current


def _build_vuln_finding(
    entry: dict,
    matched_ip: str,
    direction: str,
    host_info: dict | None,
    match_type: str,
    reason: str,
    matched_cves: list[str] | None = None,
    matched_services: list[str] | None = None,
    scan_cve_detail: dict | None = None,
    nuclei_finding: dict | None = None,
) -> dict:
    current = entry.get("verdict", "LOW")
    recommended = _vuln_recommend(match_type, current)
    return {
        "correlated_at": datetime.now(timezone.utc).isoformat(),
        "source": "vuln_correlation",
        "alert_id": entry.get("alert_id", ""),
        "alert_timestamp": entry.get("alert_timestamp", ""),
        "rule_name": entry.get("rule_name", ""),
        "source_ip": entry.get("source_ip", ""),
        "dest_ip": entry.get("dest_ip", ""),
        "dest_port": entry.get("dest_port", ""),
        "matched_ip": matched_ip,
        "direction": direction,
        "triage_verdict": current,
        "triage_method": entry.get("method", ""),
        "match_type": match_type,
        "confidence": _VULN_CONFIDENCE[match_type],
        "recommended_verdict": recommended,
        "verdict_changed": recommended != current,
        "reason": reason,
        "matched_cves": matched_cves or [],
        "matched_services": matched_services or [],
        "scan_cve_detail": scan_cve_detail,
        "nuclei_finding": nuclei_finding,
        "host_hostname": host_info.get("hostname", "") if host_info else "",
        "host_cve_count": len(host_info["cves"]) if host_info else 0,
        "host_top_cvss": host_info["cves"][0]["cvss"] if host_info and host_info["cves"] else 0.0,
        "community_id": entry.get("community_id", ""),
    }


def _correlate_one_ip_vuln(
    entry: dict,
    ip: str,
    direction: str,
    nmap_index: dict[str, dict],
    nuclei_index: dict[str, list[dict]],
    log,
) -> list[dict]:
    rule_name = entry.get("rule_name", "")
    host_info = nmap_index.get(ip)
    nuclei_findings = nuclei_index.get(ip, [])
    if not host_info and not nuclei_findings:
        return []

    role = "source host" if direction == "outbound" else "destination host"
    rule_cves = _cves_in_rule(rule_name)
    host_cves = {c["cve"].upper(): c for c in (host_info["cves"] if host_info else [])}
    host_services = host_info["services"] if host_info else []
    matched = False
    results: list[dict] = []

    for cve in rule_cves:
        if cve.upper() in host_cves:
            sc = host_cves[cve.upper()]
            reason = (
                f"Rule references {cve} confirmed by vulnscan on "
                f"{ip}:{sc['port']} ({sc['service']}, CVSS {sc['cvss']}) [{role}]"
            )
            results.append(
                _build_vuln_finding(
                    entry,
                    ip,
                    direction,
                    host_info,
                    MATCH_EXACT_CVE,
                    reason,
                    matched_cves=[cve],
                    scan_cve_detail=sc,
                )
            )
            matched = True
            log.info(
                "  EXACT CVE [%s]: %s -> %s on %s (CVSS %.1f)",
                direction,
                rule_name[:50],
                cve,
                ip,
                sc["cvss"],
            )

    for nf in nuclei_findings:
        overlap = set(c.upper() for c in rule_cves) & set(c.upper() for c in nf["cve_ids"])
        if overlap:
            reason = (
                f"Rule references {', '.join(overlap)} and nuclei confirmed "
                f"'{nf['name']}' at {nf['matched_at']} ({nf['severity']}) [{role}]"
            )
            results.append(
                _build_vuln_finding(
                    entry,
                    ip,
                    direction,
                    host_info,
                    MATCH_NUCLEI_CVE,
                    reason,
                    matched_cves=list(overlap),
                    nuclei_finding=nf,
                )
            )
            matched = True
            continue
        if nf["severity"] in ("critical", "high") and not matched and _is_exploit_rule(rule_name):
            reason = (
                f"Exploit rule involving {ip} where nuclei confirmed "
                f"'{nf['name']}' ({nf['severity']}) at {nf['matched_at']} [{role}]"
            )
            results.append(
                _build_vuln_finding(
                    entry,
                    ip,
                    direction,
                    host_info,
                    MATCH_NUCLEI_CVE,
                    reason,
                    nuclei_finding=nf,
                )
            )
            matched = True

    if not matched and host_services:
        svc_matches = _svc_keywords_match(rule_name, host_services)
        if svc_matches:
            reason = (
                f"Rule mentions product found open on {ip} ({role}): {', '.join(svc_matches[:3])}"
            )
            results.append(
                _build_vuln_finding(
                    entry,
                    ip,
                    direction,
                    host_info,
                    MATCH_SERVICE_KEYWORD,
                    reason,
                    matched_services=svc_matches,
                )
            )
            matched = True

    if not matched and host_info and host_info["cves"] and _is_exploit_rule(rule_name):
        top = host_info["cves"][0]
        reason = (
            f"Exploit rule involving {ip} ({role}) which has {len(host_info['cves'])} known CVEs "
            f"(highest: {top['cve']} CVSS {top['cvss']})"
        )
        results.append(
            _build_vuln_finding(
                entry,
                ip,
                direction,
                host_info,
                MATCH_TARGETED_HOST,
                reason,
            )
        )

    return results


def _correlate_vuln(
    entries: list[dict],
    nmap_index: dict[str, dict],
    nuclei_index: dict[str, list[dict]],
    log,
) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple] = set()

    for entry in entries:
        src = entry.get("source_ip", "")
        dst = entry.get("dest_ip", "")

        if dst and dst != "?":
            for f in _correlate_one_ip_vuln(entry, dst, "inbound", nmap_index, nuclei_index, log):
                key = (f["alert_id"], dst, f["match_type"])
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        if src and src != "?" and src != dst:
            for f in _correlate_one_ip_vuln(entry, src, "outbound", nmap_index, nuclei_index, log):
                key = (f["alert_id"], src, f["match_type"])
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

    order_conf = {"high": 0, "medium": 1, "low": 2}
    findings.sort(
        key=lambda f: (
            order_conf.get(f["confidence"], 9),
            -_verdict_rank(f["recommended_verdict"]),
        )
    )
    return findings


# ── Report ────────────────────────────────────────────────────────────────────


def _build_report(
    patterns: list[dict],
    vuln_findings: list[dict],
    triage_count: int,
    nmap_hosts: int,
    nuclei_hosts: int,
    lookback_hours: str,
    nmap_file: str,
    nuclei_file: str,
    run_time: str,
    llm_brief: str | None = None,
) -> str:
    high_p = [p for p in patterns if p["confidence"] == "high"]
    med_p = [p for p in patterns if p["confidence"] == "medium"]
    low_p = [p for p in patterns if p["confidence"] == "low"]
    high_v = [f for f in vuln_findings if f["confidence"] == "high"]
    med_v = [f for f in vuln_findings if f["confidence"] == "medium"]
    low_v = [f for f in vuln_findings if f["confidence"] == "low"]
    verdict_changes = [f for f in vuln_findings if f["verdict_changed"]]

    lines = [
        "# Alert Correlation Report",
        f"**Run:** {run_time}",
        f"**Triage alerts:** {triage_count} (last {lookback_hours})",
        f"**Vulnscan hosts:** {nmap_hosts} nmap / {nuclei_hosts} nuclei",
        f"**Nmap source:** {nmap_file}  |  **Nuclei source:** {nuclei_file}",
        "",
    ]

    if llm_brief:
        lines += [
            "---",
            "# Analyst Brief (AI)",
            "",
            llm_brief.strip(),
            "",
        ]

    lines += [
        "## Summary",
        "",
        f"### Alert Patterns (alert x alert) -- {len(patterns)} patterns",
        f"  - High confidence: {len(high_p)}",
        f"  - Medium confidence: {len(med_p)}",
        f"  - Low confidence: {len(low_p)}",
        "",
        f"### Vuln Correlations (alert x scan) -- {len(vuln_findings)} findings",
        f"  - High confidence: {len(high_v)}",
        f"  - Medium confidence: {len(med_v)}",
        f"  - Low confidence: {len(low_v)}",
        f"  - Verdict upgrades recommended: {len(verdict_changes)}",
        "",
    ]

    # ── Alert patterns ─────────────────────────────────────────────────
    if patterns:
        lines += ["---", "# Alert Behaviour Patterns", ""]
        _pattern_labels = {
            "scan_to_exploit": "SCAN→EXPLOIT chain",
            "targeted_host": "Host targeted (scan + exploit)",
            "lateral_movement": "Lateral movement / internal sweep",
            "port_sweep": "Port sweep (same port, many hosts)",
            "multi_rule_pair": "Sustained multi-rule attack (same pair)",
            "c2_beacon": "C2 / beaconing (TROJAN/MALWARE rules)",
            "high_volume_src": "High-volume source",
            "inbound_sweep": "Inbound sweep (external → many internal hosts)",
            "brute_force": "Brute force / credential attack",
            "single_rule_flood": "Single-rule flood (repeated identical alert)",
            "internal_exploit": "Internal→internal exploitation",
            "src_ip_pivot": "Source IP pivot (shared origin across rules)",
            "dest_ip_pivot": "Destination IP pivot (shared target across sources)",
            "dest_port_pivot": "Destination port pivot (shared port across sources)",
        }

        for p in high_p + med_p + low_p:
            label = _pattern_labels.get(p["pattern_type"], p["pattern_type"])
            lines.append(f"## [{p['confidence'].upper()}] {label}")
            if p["pivot_ip"] and p["pivot_role"] != "port":
                lines.append(f"- **Pivot IP:** `{p['pivot_ip']}` (as {p['pivot_role']})")
            if p["peer_ip"]:
                lines.append(f"- **Peer IP:** `{p['peer_ip']}`")
            if p["dest_port"] and p["pivot_role"] == "port":
                lines.append(f"- **Pivot port:** `{p['dest_port']}`")
            if p["dest_ips"] and p["dest_ips"] != [p["pivot_ip"]]:
                shown = p["dest_ips"][:12]
                more = f" +{len(p['dest_ips']) - 12} more" if len(p["dest_ips"]) > 12 else ""
                host_label = "Source IPs" if p["pivot_role"] == "port" else "Involved hosts"
                lines.append(
                    f"- **{host_label} ({len(p['dest_ips'])}):** {', '.join(f'`{ip}`' for ip in shown)}{more}"
                )
            if p["dest_port"] and p["pivot_role"] != "port":
                lines.append(f"- **Target port:** `{p['dest_port']}`")
            lines.append(f"- **Recommended verdict:** {p['recommended_verdict']}")
            lines.append(f"- **Alert count:** {p['alert_count']}")
            if p["time_first"] and p["time_last"]:
                lines.append(
                    f"- **Window:** `{p['time_first'][:19]}` to `{p['time_last'][:19]} UTC`"
                )
            lines.append(f"- **Rule categories seen:** {', '.join(p['categories'])}")
            lines.append(f"- **Why this matched:** {p['reason']}")
            lines.append("")

            # Break down rules by category for clarity
            rule_names = p["rule_names"]
            by_cat: dict[str, list[str]] = {}
            for r in rule_names:
                cat = _rule_category(r)
                by_cat.setdefault(cat, []).append(r)

            cat_order = [
                "exploit",
                "trojan",
                "malware",
                "shellcode",
                "attack",
                "scan",
                "dos",
                "web_server",
                "web_client",
                "info",
                "policy",
                "other",
            ]
            for cat in cat_order:
                rs = by_cat.get(cat, [])
                if not rs:
                    continue
                lines.append(f"  **{cat.upper()} rules ({len(rs)}):**")
                for r in rs[:15]:
                    lines.append(f"  - `{r}`")
                if len(rs) > 15:
                    lines.append(f"  - *(+{len(rs) - 15} more)*")
            lines.append("")

    # ── Vuln correlations ──────────────────────────────────────────────
    if vuln_findings:
        lines += ["---", "# Vulnerability Correlations", ""]

        if verdict_changes:
            lines += ["## Recommended Verdict Upgrades", ""]
            for f in verdict_changes:
                lines.append(
                    f"- **{f['rule_name'][:70]}**  "
                    f"`{f['triage_verdict']} → {f['recommended_verdict']}`  "
                    f"[{f['confidence']}]"
                )
                lines.append(f"  - `{f['matched_ip']}` ({f['direction']}) | `{f['match_type']}`")
                lines.append(f"  - {f['reason']}")
                lines.append("")

        for conf_label, conf_list in [("High", high_v), ("Medium", med_v), ("Low", low_v)]:
            if not conf_list:
                continue
            lines += [f"## {conf_label} Confidence Vuln Correlations", ""]
            for f in conf_list:
                hn = f" ({f['host_hostname']})" if f["host_hostname"] else ""
                lines.append(f"### {f['rule_name'][:80]}")
                lines.append(
                    f"- **Alert:** `{f['alert_timestamp'][:19]}` | {f['source_ip']} → {f['dest_ip']}:{f['dest_port']}"
                )
                lines.append(f"- **Matched host:** `{f['matched_ip']}`{hn} ({f['direction']})")
                lines.append(
                    f"- **Verdict:** {f['triage_verdict']} → **{f['recommended_verdict']}** ({f['match_type']})"
                )
                lines.append(f"- {f['reason']}")
                if f["matched_cves"]:
                    lines.append(f"- **CVEs:** {', '.join(f['matched_cves'])}")
                if f["scan_cve_detail"]:
                    d = f["scan_cve_detail"]
                    lines.append(
                        f"- **Scan:** {d['cve']} CVSS {d['cvss']} on {f['matched_ip']}:{d['port']} ({d['service']})"
                    )
                if f["nuclei_finding"]:
                    nf = f["nuclei_finding"]
                    lines.append(
                        f"- **Nuclei:** {nf['name']} ({nf['severity']}) at {nf['matched_at']}"
                    )
                lines.append("")

    if not patterns and not vuln_findings:
        lines += [
            "No correlations found.",
            "",
            "Possible reasons:",
            "  - Alert IPs do not overlap with scanned hosts",
            "  - No attack-chain patterns in the alert window",
            "  - All alerts are single-category INFO traffic",
        ]

    return "\n".join(lines)


# ── Entry point ───────────────────────────────────────────────────────────────


def _summarize_with_llm(
    patterns: list[dict],
    vuln_findings: list[dict],
    cfg: Config,
    log,
) -> str | None:
    """Send HIGH+MEDIUM findings to LLM and get a prioritised analyst brief.

    Returns the LLM response text, or None if LLM is unavailable or no findings.
    IPs are scrubbed before sending to the cloud LLM.
    """
    high_med_patterns = [p for p in patterns if p["confidence"] in ("high", "medium")]
    high_med_vulns = [f for f in vuln_findings if f["confidence"] in ("high", "medium")]

    if not high_med_patterns and not high_med_vulns:
        log.info("LLM brief: no HIGH/MEDIUM findings — skipping")
        return None

    # Build IP scrubbing map
    all_ips: set[str] = set()
    for p in high_med_patterns:
        if p.get("pivot_ip"):
            all_ips.add(p["pivot_ip"])
        if p.get("peer_ip"):
            all_ips.add(p["peer_ip"])
        all_ips.update(p.get("dest_ips", []))
    for f in high_med_vulns:
        for field in ("source_ip", "dest_ip", "matched_ip"):
            if f.get(field):
                all_ips.add(f[field])

    internal_prefixes = cfg.network.internal_prefixes
    scrub = getattr(getattr(cfg, "triage", None), "scrub_ips", True)

    ip_map: dict[str, str] = {}
    if scrub:
        int_n = ext_n = 0
        for ip in sorted(all_ips):
            if any(ip.startswith(px) for px in internal_prefixes):
                int_n += 1
                ip_map[ip] = f"INT-{int_n:03d}"
            else:
                ext_n += 1
                ip_map[ip] = f"EXT-{ext_n:03d}"

    def _s(text: str) -> str:
        for real, token in ip_map.items():
            text = text.replace(real, token)
        return text

    # Build prompt
    prompt_lines = [
        "You are a Security Operations Center analyst reviewing automated correlation findings.",
        "Below are HIGH and MEDIUM confidence security patterns detected in the last 48 hours.",
        "",
        "Your tasks:",
        "1. Identify the top 3-5 most urgent findings that need immediate investigation.",
        "   For each: state WHY it is urgent and WHAT the analyst should do first.",
        "2. If multiple findings share an IP, call that out — it may be one coordinated attacker.",
        "3. Summarize the remaining findings in 2-3 sentences.",
        "4. End with a one-line overall risk level: LOW / MEDIUM / HIGH / CRITICAL.",
        "",
        "Be concise and actionable. Focus on what needs to happen RIGHT NOW.",
        "",
        "--- FINDINGS ---",
        "",
    ]

    for i, p in enumerate(high_med_patterns, 1):
        pivot = _s(p.get("pivot_ip", ""))
        peer = _s(p.get("peer_ip", ""))
        dest_shown = [_s(ip) for ip in p.get("dest_ips", [])[:8]]
        more_dest = f" (+{len(p['dest_ips']) - 8} more)" if len(p.get("dest_ips", [])) > 8 else ""
        prompt_lines.append(
            f"[P{i}] {p['pattern_type'].upper()} | {p['confidence'].upper()} confidence"
            f" | recommended={p['recommended_verdict']}"
        )
        if pivot:
            prompt_lines.append(
                f"  Pivot: {pivot} (as {p['pivot_role']})" + (f" | Peer: {peer}" if peer else "")
            )
        if dest_shown:
            prompt_lines.append(f"  Hosts: {', '.join(dest_shown)}{more_dest}")
        if p.get("dest_port"):
            prompt_lines.append(f"  Port: {p['dest_port']}")
        prompt_lines.append(
            f"  Alerts: {p['alert_count']}"
            f" | Window: {p.get('time_first', '')[:16]} to {p.get('time_last', '')[:16]}"
        )
        prompt_lines.append(f"  Reason: {_s(p['reason'])}")
        if p.get("rule_names"):
            rule_preview = ", ".join(p["rule_names"][:5])
            extra = f" (+{len(p['rule_names']) - 5} more)" if len(p["rule_names"]) > 5 else ""
            prompt_lines.append(f"  Rules: {rule_preview}{extra}")
        prompt_lines.append("")

    for i, f in enumerate(high_med_vulns, 1):
        prompt_lines.append(
            f"[V{i}] VULN CORRELATION | {f['confidence'].upper()} confidence"
            f" | {f['triage_verdict']} -> {f['recommended_verdict']}"
        )
        prompt_lines.append(f"  Alert: {f['rule_name'][:70]}")
        prompt_lines.append(
            f"  Traffic: {_s(f.get('source_ip', '?'))} -> {_s(f.get('dest_ip', '?'))}:{f.get('dest_port', '?')}"
            f" | matched host: {_s(f.get('matched_ip', '?'))} ({f.get('direction', '?')})"
        )
        prompt_lines.append(f"  Match: {f['match_type']} | {_s(f['reason'])}")
        if f.get("matched_cves"):
            prompt_lines.append(f"  CVEs: {', '.join(f['matched_cves'][:5])}")
        prompt_lines.append("")

    prompt = "\n".join(prompt_lines)
    log.info(
        "LLM brief: sending %d patterns + %d vuln findings (%d chars)",
        len(high_med_patterns),
        len(high_med_vulns),
        len(prompt),
    )

    try:
        llm = make_llm_client(cfg)
        brief = llm.generate(prompt, temperature=0.3)
        log.info("LLM brief: received %d chars", len(brief))
        return brief
    except Exception as exc:
        log.warning("LLM brief failed (%s) — report will proceed without it", exc)
        return None


def run_correlate(cfg: Config, lookback_hours: int = 48, lookback_minutes: int | None = None):
    # lookback_minutes overrides lookback_hours when provided
    if lookback_minutes is not None:
        _lookback = timedelta(minutes=lookback_minutes)
        _lookback_label = f"{lookback_minutes}m"
    else:
        _lookback = timedelta(hours=lookback_hours)
        _lookback_label = f"{lookback_hours}h"

    data_dir = cfg.paths.data_dir
    log_dir = data_dir / "logs"
    state_dir = data_dir / "state"
    scan_dir = data_dir / "output" / "vulnscan"
    correlate_dir = data_dir / "output" / "correlate"
    correlate_dir.mkdir(parents=True, exist_ok=True)

    log = setup_logging("correlate", log_dir)
    state = ToolState("correlate", state_dir)
    state.start_run()

    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log.info("=== Starting correlation run: %s ===", run_time)
    log.info("Triage lookback: %s", _lookback_label)

    # ── Load triage log ───────────────────────────────────────────────
    triage_jsonl = log_dir / "triage.jsonl"
    entries: list[dict] = []
    cutoff = datetime.now(timezone.utc) - _lookback

    if not triage_jsonl.exists():
        log.warning("No triage log at %s — run 'so-ops triage' first", triage_jsonl)
        print(f"No triage log found. Run 'so-ops triage' first.\nExpected: {triage_jsonl}")
        state.finish_run(correlations=0)
        return

    total = skipped = 0
    for line in triage_jsonl.read_text(encoding="utf-8").strip().split("\n"):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        ts_str = e.get("alert_timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts < cutoff:
                skipped += 1
                continue
        except (ValueError, TypeError):
            pass
        entries.append(e)

    log.info("Triage log: %d total, %d in window, %d skipped", total, len(entries), skipped)

    if not entries:
        log.warning("No alerts in last %s", _lookback_label)
        print(f"No triage alerts in the last {_lookback_label}.")
        state.finish_run(correlations=0)
        return

    # ── Pass 1: alert × alert patterns ───────────────────────────────
    log.info("=== Pass 1: alert pattern detection (%d alerts) ===", len(entries))
    patterns = _correlate_alert_patterns(entries, cfg.network.internal_prefixes, log)
    log.info(
        "Patterns: %d total (%d high, %d medium, %d low)",
        len(patterns),
        sum(1 for p in patterns if p["confidence"] == "high"),
        sum(1 for p in patterns if p["confidence"] == "medium"),
        sum(1 for p in patterns if p["confidence"] == "low"),
    )

    # ── Pass 2: alert × vulnscan ──────────────────────────────────────
    nmap_index: dict[str, dict] = {}
    nuclei_index: dict[str, list[dict]] = {}
    nmap_xml = nuclei_jsonl = None

    if scan_dir.exists():
        nmap_xml = _find_latest_file(scan_dir, "nmap_*.xml")
        nuclei_jsonl = _find_latest_file(scan_dir, "nuclei_*.jsonl")
        if nmap_xml:
            nmap_index = _load_nmap_index(nmap_xml, log)
        if nuclei_jsonl:
            nuclei_index = _load_nuclei_index(nuclei_jsonl, log)
    else:
        log.info("No vulnscan output dir — skipping vuln correlation (run 'so-ops scan' first)")

    vuln_findings: list[dict] = []
    if nmap_index or nuclei_index:
        log.info(
            "=== Pass 2: vuln correlation (%d nmap, %d nuclei hosts) ===",
            len(nmap_index),
            len(nuclei_index),
        )
        vuln_findings = _correlate_vuln(entries, nmap_index, nuclei_index, log)
        log.info(
            "Vuln findings: %d total (%d high, %d medium, %d low)",
            len(vuln_findings),
            sum(1 for f in vuln_findings if f["confidence"] == "high"),
            sum(1 for f in vuln_findings if f["confidence"] == "medium"),
            sum(1 for f in vuln_findings if f["confidence"] == "low"),
        )
    else:
        log.info("Pass 2 skipped — no scan data available")

    # ── Write JSONL log ───────────────────────────────────────────────
    findings_log = log_dir / "correlate_findings.jsonl"
    all_findings = patterns + vuln_findings
    for item in all_findings:
        with open(findings_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(item) + "\n")
    log.info("Wrote %d findings to %s", len(all_findings), findings_log)

    # ── Pass 3: LLM analyst brief ─────────────────────────────────────
    log.info("=== Pass 3: LLM analyst brief ===")
    llm_brief = _summarize_with_llm(patterns, vuln_findings, cfg, log)

    # ── Build report ──────────────────────────────────────────────────
    report = _build_report(
        patterns=patterns,
        vuln_findings=vuln_findings,
        triage_count=len(entries),
        nmap_hosts=len(nmap_index),
        nuclei_hosts=len(nuclei_index),
        lookback_hours=_lookback_label,
        nmap_file=nmap_xml.name if nmap_xml else "none",
        nuclei_file=nuclei_jsonl.name if nuclei_jsonl else "none",
        run_time=run_time,
        llm_brief=llm_brief,
    )
    report_path = correlate_dir / f"report_{timestamp}.md"
    report_path.write_text(report, encoding="utf-8")
    log.info("Report: %s", report_path)

    state.finish_run(correlations=len(all_findings))

    # ── Notify ────────────────────────────────────────────────────────
    high_count = sum(1 for p in patterns if p["confidence"] == "high")
    med_count = sum(1 for p in patterns if p["confidence"] == "medium")
    changes = [f for f in vuln_findings if f["verdict_changed"]]

    if high_count or med_count or changes:
        notify_title = f"[so-ops] Correlation: {high_count} high / {med_count} medium patterns"

        # Pattern detail block appended after the AI brief
        detail_lines: list[str] = []
        for p in patterns:
            if p["confidence"] not in ("high", "medium"):
                continue
            detail_lines.append(
                f"[{p['confidence'].upper()}] {p['pattern_type'].upper()}"
                f" | {p['alert_count']} alerts"
                f" | {p['time_first'][:16]} - {p['time_last'][:16]}"
            )
            if p.get("pivot_ip"):
                detail_lines.append(f"  Pivot: {p['pivot_ip']} ({p.get('pivot_role', '?')})")
            if p.get("peer_ip"):
                detail_lines.append(f"  Peer: {p['peer_ip']}")
            if p.get("dest_ips"):
                detail_lines.append(f"  Targets: {', '.join(p['dest_ips'][:5])}")
            if p.get("dest_port"):
                detail_lines.append(f"  Port: {p['dest_port']}")
            for rule in p.get("rule_names", [])[:5]:
                detail_lines.append(f"  Rule: {rule}")
            detail_lines.append(f"  Reason: {p.get('reason', '')}")
            detail_lines.append("")

        detail_block = "\n".join(detail_lines).strip()
        notify_body = (
            (llm_brief.strip() + "\n\n---\n\n" + detail_block) if llm_brief else detail_block
        )
        notify_all(cfg.notifications, notify_title, notify_body)
        log.info("Notification sent")

    # ── Console summary ───────────────────────────────────────────────
    high_p = [p for p in patterns if p["confidence"] == "high"]

    print("\n" + "=" * 60)
    print("CORRELATION COMPLETE")
    print("=" * 60)
    print(f"Alerts analysed:  {len(entries)} (last {_lookback_label})")
    print(
        f"Alert patterns:   {len(patterns)} "
        f"({high_count} high / {med_count} medium / "
        f"{sum(1 for p in patterns if p['confidence'] == 'low')} low)"
    )
    print(
        f"Vuln findings:    {len(vuln_findings)} "
        f"({sum(1 for f in vuln_findings if f['confidence'] == 'high')} high / "
        f"{sum(1 for f in vuln_findings if f['confidence'] == 'medium')} medium / "
        f"{sum(1 for f in vuln_findings if f['confidence'] == 'low')} low)"
    )
    print(f"Verdict upgrades: {len(changes)}")

    _con_labels = {
        "scan_to_exploit": "SCAN->EXPLOIT",
        "targeted_host": "TARGETED HOST",
        "c2_beacon": "C2 BEACON",
        "inbound_sweep": "INBOUND SWEEP",
        "internal_exploit": "INTERNAL EXPLOIT",
        "brute_force": "BRUTE FORCE",
        "single_rule_flood": "RULE FLOOD",
        "lateral_movement": "LATERAL MOVEMENT",
        "port_sweep": "PORT SWEEP",
        "multi_rule_pair": "MULTI-RULE PAIR",
        "high_volume_src": "HIGH VOLUME",
        "src_ip_pivot": "SRC PIVOT",
        "dest_ip_pivot": "DEST PIVOT",
        "dest_port_pivot": "PORT PIVOT",
    }

    if high_p:
        print("\nHIGH CONFIDENCE PATTERNS:")
        for p in high_p:
            label = _con_labels.get(p["pattern_type"], p["pattern_type"].upper())
            peer = f" -> {p['peer_ip']}" if p["peer_ip"] else ""
            print(f"  [{p['recommended_verdict']}] {label}: {p['pivot_ip']}{peer}")
            print(f"        {p['reason'][:90]}")

    if changes:
        print("\nVULN VERDICT UPGRADES:")
        for f in changes:
            print(
                f"  {f['triage_verdict']:6s} -> {f['recommended_verdict']:6s}  {f['rule_name'][:55]}"
            )

    if llm_brief:
        print("\n" + "-" * 60)
        print("ANALYST BRIEF (AI):")
        print("-" * 60)
        print(llm_brief.strip())

    print(f"\nReport: {report_path}")
    print(f"Log:    {findings_log}")
