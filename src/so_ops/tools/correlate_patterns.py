"""Pass 1: alert x alert behavioural pattern detection (no LLM)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from so_ops.tools.correlate_common import (
    ATTACK_CATS,
    HIGH_SEVERITY_CATS,
    SCAN_CATS,
    confidence_rank,
    is_internal,
    max_verdict,
    rule_category,
    verdict_rank,
)

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


def _port_int(value) -> int:
    """Coerce a dest_port value to int, treating non-numeric placeholders
    (e.g. "?" for portless protocols like ICMP) as 0 instead of raising.
    """
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


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
        "confidence_rank": confidence_rank(confidence),
        "verdict_rank": verdict_rank(recommended_verdict),
        "reason": reason,
        "community_ids": sorted(set(community_ids or []))[:10],
    }


def _cids(entries: list[dict]) -> list[str]:
    return [e.get("community_id", "") for e in entries if e.get("community_id")]


def _time_range(entries: list[dict]) -> tuple[str, str]:
    times = sorted(e["alert_timestamp"] for e in entries if e.get("alert_timestamp"))
    return (times[0] if times else ""), (times[-1] if times else "")


def correlate_alert_patterns(
    entries: list[dict],
    internal_prefixes: list[str],
    log,
    window_minutes: float = 2880,
) -> list[dict]:
    """Detect behavioural patterns purely within the triage alert log.

    window_minutes is used to scale volume-based thresholds so short lookbacks
    (e.g. 20 min) don't require the same raw counts as a 48h window.
    """
    # Scale volume thresholds proportionally; floor prevents them going to zero
    _window_hours = window_minutes / 60
    high_vol_min = max(10, int(_HIGH_VOL_MIN * _window_hours / 48))
    flood_min = max(20, int(_SINGLE_RULE_FLOOD_MIN * _window_hours / 48))
    log.info(
        "Threshold scaling (%.0fm window): high_vol_min=%d, flood_min=%d",
        window_minutes,
        high_vol_min,
        flood_min,
    )

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
        cats = {rule_category(e["rule_name"]) for e in src_entries}
        has_scan = bool(cats & SCAN_CATS)
        has_high = bool(cats & HIGH_SEVERITY_CATS)
        if not (has_scan and has_high):
            continue

        scan_rules = [
            e["rule_name"] for e in src_entries if rule_category(e["rule_name"]) in SCAN_CATS
        ]
        exploit_rules = [
            e["rule_name"]
            for e in src_entries
            if rule_category(e["rule_name"]) in HIGH_SEVERITY_CATS
        ]
        time_first, time_last = _time_range(src_entries)
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
                categories=sorted(cats & (SCAN_CATS | HIGH_SEVERITY_CATS)),
                alert_count=len(src_entries),
                time_first=time_first,
                time_last=time_last,
                dest_ips=dest_ips,
                community_ids=_cids(src_entries),
            )
        )

    # ── Pattern 2: targeted host — same dest hit by scan + exploit ─────
    for dest_ip, dest_entries in by_dest.items():
        cats = {rule_category(e["rule_name"]) for e in dest_entries}
        has_scan = bool(cats & SCAN_CATS)
        has_high = bool(cats & HIGH_SEVERITY_CATS)
        if not (has_scan and has_high):
            continue

        src_ips = sorted(
            {e["source_ip"] for e in dest_entries if e.get("source_ip") and e["source_ip"] != "?"}
        )
        rule_names = [e["rule_name"] for e in dest_entries]
        time_first, time_last = _time_range(dest_entries)

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
                categories=sorted(cats & (SCAN_CATS | HIGH_SEVERITY_CATS)),
                alert_count=len(dest_entries),
                time_first=time_first,
                time_last=time_last,
                dest_ips=[dest_ip],
                community_ids=_cids(dest_entries),
            )
        )

    # ── Pattern 3: lateral movement — src reaching many internal dests ─
    for src_ip, src_entries in by_src.items():
        internal_dests = {
            e["dest_ip"]
            for e in src_entries
            if e.get("dest_ip")
            and e["dest_ip"] != "?"
            and is_internal(e["dest_ip"], internal_prefixes)
        }
        if len(internal_dests) < _LATERAL_DEST_MIN:
            continue

        rule_names = [e["rule_name"] for e in src_entries]
        cats = {rule_category(r) for r in rule_names}
        time_first, time_last = _time_range(src_entries)
        src_internal = is_internal(src_ip, internal_prefixes)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=sorted(internal_dests),
                community_ids=_cids(src_entries),
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
        cats = {rule_category(r) for r in rule_names}
        time_first, time_last = _time_range(port_entries)

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
                time_first=time_first,
                time_last=time_last,
                dest_ips=sorted(distinct_dests),
                dest_port=port,
                community_ids=_cids(port_entries),
            )
        )

    # ── Pattern 5: sustained multi-rule attack on same pair ─────────────
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        distinct_rules = {e["rule_name"] for e in pair_entries}
        if len(distinct_rules) < _MULTI_RULE_PAIR_MIN:
            continue

        cats = {rule_category(r) for r in distinct_rules}
        time_first, time_last = _time_range(pair_entries)

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
                recommended_verdict=max_verdict(
                    "MEDIUM", *[e.get("verdict", "LOW") for e in pair_entries]
                ),
                rule_names=sorted(distinct_rules),
                categories=sorted(cats),
                alert_count=len(pair_entries),
                time_first=time_first,
                time_last=time_last,
                dest_ips=[dest_ip],
                community_ids=_cids(pair_entries),
            )
        )

    # ── Pattern 6: C2 / beaconing — TROJAN/MALWARE rules on same pair ──
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        c2_entries = [
            e for e in pair_entries if rule_category(e["rule_name"]) in ("trojan", "malware")
        ]
        distinct_c2_rules = {e["rule_name"] for e in c2_entries}
        if len(distinct_c2_rules) < _C2_RULE_MIN:
            continue

        time_first, time_last = _time_range(c2_entries)
        cats = {rule_category(e["rule_name"]) for e in c2_entries}

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
                time_first=time_first,
                time_last=time_last,
                dest_ips=[dest_ip],
                community_ids=_cids(c2_entries),
            )
        )

    # ── Pattern 7: high-volume single source ───────────────────────────
    _flagged_srcs = {
        p["pivot_ip"]
        for p in patterns
        if p["pattern_type"] in ("scan_to_exploit", "lateral_movement")
    }
    _scan_exploit_srcs = {p["pivot_ip"] for p in patterns if p["pattern_type"] == "scan_to_exploit"}
    for src_ip, src_entries in by_src.items():
        if len(src_entries) < high_vol_min:
            continue

        distinct_rules = {e["rule_name"] for e in src_entries}
        cats = {rule_category(r) for r in distinct_rules}
        # Skip if already caught by scan→exploit or lateral movement
        if src_ip in _flagged_srcs:
            continue

        time_first, time_last = _time_range(src_entries)
        has_attack_cat = bool(cats & ATTACK_CATS)

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
                time_first=time_first,
                time_last=time_last,
                community_ids=_cids(src_entries),
            )
        )

    # ── Pattern 8: inbound sweep — external src → many internal dests ─────
    for src_ip, src_entries in by_src.items():
        if is_internal(src_ip, internal_prefixes):
            continue
        if src_ip in _scan_exploit_srcs:
            continue

        internal_dests = {
            e["dest_ip"]
            for e in src_entries
            if e.get("dest_ip")
            and e["dest_ip"] != "?"
            and is_internal(e["dest_ip"], internal_prefixes)
        }
        if len(internal_dests) < _INBOUND_SWEEP_MIN:
            continue

        rule_names = [e["rule_name"] for e in src_entries]
        cats = {rule_category(r) for r in rule_names}
        time_first, time_last = _time_range(src_entries)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=sorted(internal_dests),
                community_ids=_cids(src_entries),
            )
        )

    # ── Pattern 9: brute force — repeated alerts on auth ports same pair ──
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        auth_entries = [e for e in pair_entries if _port_int(e.get("dest_port")) in _AUTH_PORTS]
        if len(auth_entries) < _BRUTE_FORCE_MIN:
            continue

        ports_hit = sorted(
            {str(e.get("dest_port", "")) for e in auth_entries if e.get("dest_port")}
        )
        rule_names = [e["rule_name"] for e in auth_entries]
        cats = {rule_category(r) for r in rule_names}
        time_first, time_last = _time_range(auth_entries)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=[dest_ip],
                dest_port=ports_hit[0] if len(ports_hit) == 1 else ", ".join(ports_hit),
                community_ids=_cids(auth_entries),
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
        if len(flood_entries) < flood_min:
            continue

        dest_ips = sorted(
            {e["dest_ip"] for e in flood_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )
        dest_ports = sorted(
            {str(e.get("dest_port", "")) for e in flood_entries if e.get("dest_port")}
        )
        time_first, time_last = _time_range(flood_entries)
        cat = rule_category(rule_name)
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
                confidence="medium" if cat in ATTACK_CATS else "low",
                pivot_ip=src_ip,
                pivot_role="src",
                reason=reason,
                recommended_verdict="MEDIUM" if cat in ATTACK_CATS else "LOW",
                rule_names=[rule_name],
                categories=[cat],
                alert_count=len(flood_entries),
                time_first=time_first,
                time_last=time_last,
                dest_ips=dest_ips,
                dest_port=dest_ports[0] if len(dest_ports) == 1 else "",
                community_ids=_cids(flood_entries),
            )
        )

    # ── Pattern 11: internal→internal exploit ─────────────────────────────
    flagged_pairs = {
        (p["pivot_ip"], p["peer_ip"])
        for p in patterns
        if p.get("peer_ip") and p["pattern_type"] in ("c2_beacon", "multi_rule_pair")
    }
    for (src_ip, dest_ip), pair_entries in by_pair.items():
        if not is_internal(src_ip, internal_prefixes):
            continue
        if not is_internal(dest_ip, internal_prefixes):
            continue
        if (src_ip, dest_ip) in flagged_pairs:
            continue

        exploit_entries = [
            e for e in pair_entries if rule_category(e["rule_name"]) in HIGH_SEVERITY_CATS
        ]
        if not exploit_entries:
            continue

        rule_names = [e["rule_name"] for e in exploit_entries]
        cats = {rule_category(r) for r in rule_names}
        time_first, time_last = _time_range(exploit_entries)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=[dest_ip],
                community_ids=_cids(exploit_entries),
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

        non_info_cats = {rule_category(e["rule_name"]) for e in src_entries} - {"info", "policy"}
        if len(non_info_cats) < _PIVOT_SRC_CAT_MIN:
            continue

        dest_ips = sorted(
            {e["dest_ip"] for e in src_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )
        rule_names = sorted({e["rule_name"] for e in src_entries})
        all_cats = {rule_category(e["rule_name"]) for e in src_entries}
        time_first, time_last = _time_range(src_entries)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=dest_ips,
                community_ids=_cids(src_entries),
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

        cats = {rule_category(r) for r in distinct_rules}
        time_first, time_last = _time_range(dest_entries)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=[dest_ip],
                community_ids=_cids(dest_entries),
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
            e for e in port_entries if rule_category(e["rule_name"]) not in ("info", "policy")
        ]
        if not non_info:
            continue

        dest_ips = sorted(
            {e["dest_ip"] for e in port_entries if e.get("dest_ip") and e["dest_ip"] != "?"}
        )
        rule_names = sorted({e["rule_name"] for e in port_entries})
        cats = {rule_category(r) for r in rule_names}
        time_first, time_last = _time_range(port_entries)
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
                time_first=time_first,
                time_last=time_last,
                dest_ips=dest_ips,
                dest_port=port,
                community_ids=_cids(port_entries),
            )
        )

    # Sort: high confidence first, then by verdict rank
    patterns.sort(key=lambda p: (p["confidence_rank"], p["verdict_rank"]))
    log.info("Alert patterns found: %d", len(patterns))
    return patterns
