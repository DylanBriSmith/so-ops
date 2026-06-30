"""Alert triage: query Suricata alerts, classify with LLM, notify on HIGH."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from so_ops.clients import make_llm_client
from so_ops.clients.base import LLMClient
from so_ops.clients.elasticsearch import SOElasticClient
from so_ops.clients.notify import notify_all
from so_ops.config import Config
from so_ops.log import setup_logging
from so_ops.state import ToolState


def _flow_key(alert: dict) -> tuple:
    """Return a stable key for the network flow an alert belongs to."""
    cid = alert.get("community_id") or ""
    if cid:
        return ("cid", cid)
    return (
        "5tuple",
        alert["source_ip"],
        alert["dest_ip"],
        alert["source_port"],
        alert["dest_port"],
        alert.get("protocol", "?"),
    )


def _group_alerts_by_flow(alerts: list) -> dict[tuple, list]:
    """Group alerts that share the same network flow."""
    groups: dict[tuple, list] = defaultdict(list)
    for alert in alerts:
        groups[_flow_key(alert)].append(alert)
    return dict(groups)


def _correlated_rule_names(alert: dict, flow_groups: dict[tuple, list]) -> list[str]:
    """Other rule names that fired on the same flow as this alert."""
    siblings = flow_groups.get(_flow_key(alert), [])
    return sorted({a["rule_name"] for a in siblings if a["id"] != alert["id"]})


def _correlated_rules_for_group(group_alerts: list, flow_groups: dict[tuple, list]) -> list[str]:
    """Union of correlated rule names across all alerts in a triage group."""
    names: set[str] = set()
    for alert in group_alerts:
        names.update(_correlated_rule_names(alert, flow_groups))
    return sorted(names)


def _correlated_escalation(
    correlated_rules: list[str], verdict: str, min_medium: list[str], min_high: list[str]
) -> tuple[str, str]:
    """Check if correlated rules on the same flow warrant escalation.
    Returns (new_verdict, escalation_reason) or (verdict, '') if no change."""
    severity_order = {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    current = severity_order.get(verdict, 1)
    for corr_rule in correlated_rules:
        for pattern in min_high:
            if pattern in corr_rule and current < 3:
                return "HIGH", f"correlated flow also triggered {corr_rule!r} (HIGH pattern)"
        for pattern in min_medium:
            if (corr_rule.startswith(pattern) or pattern in corr_rule) and current < 2:
                return "MEDIUM", f"correlated flow also triggered {corr_rule!r} (MEDIUM pattern)"
    return verdict, ""


def _extract_alert_summary(hit: dict) -> dict:
    """Extract key fields from an ES alert hit into a concise dict."""
    src = hit["_source"]
    rule = src.get("rule", {})
    source = src.get("source", {})
    dest = src.get("destination", {})

    alert_info = {}
    try:
        msg = json.loads(src.get("message", "{}"))
        alert_info = msg.get("alert", {})
    except (json.JSONDecodeError, TypeError):
        pass

    sig_sev = rule.get("metadata", {}).get("signature_severity", "Unknown")
    if isinstance(sig_sev, list):
        sig_sev = sig_sev[0] if sig_sev else "Unknown"

    return {
        "id": hit["_id"],
        "timestamp": src.get("@timestamp", ""),
        "rule_name": rule.get("name", alert_info.get("signature", "Unknown")),
        "rule_severity": rule.get("severity", "?"),
        "sig_severity": sig_sev,
        "category": alert_info.get("category", rule.get("category", "Unknown")),
        "source_ip": source.get("ip", "?"),
        "source_port": source.get("port", "?"),
        "dest_ip": dest.get("ip", "?"),
        "dest_port": dest.get("port", "?"),
        "protocol": src.get("network", {}).get("transport", "?"),
        "community_id": src.get("network", {}).get("community_id", ""),
        "ruleset": rule.get("ruleset", ""),
        "action": rule.get("action", alert_info.get("action", "")),
    }


def _classify_auto_noise(alerts: list, noise_sigs: set) -> tuple[list, list]:
    """Separate known-noise alerts from those needing LLM review."""
    noise, needs_review = [], []
    for alert in alerts:
        if alert["rule_name"] in noise_sigs:
            alert["triage_verdict"] = "NOISE"
            alert["triage_reason"] = "Auto-classified: known benign signature"
            alert["triage_method"] = "auto"
            noise.append(alert)
        else:
            needs_review.append(alert)
    return noise, needs_review


def _group_alerts(alerts: list) -> dict[str, list]:
    """Group alerts by signature + source_ip."""
    groups: dict[str, list] = defaultdict(list)
    for alert in alerts:
        key = f"{alert['rule_name']}|{alert['source_ip']}"
        groups[key].append(alert)
    return dict(groups)


def _build_zone_context(zones, scrub_zones: bool = True) -> str:
    """Build network context string from configured zones."""
    if not zones:
        return (
            "- No specific network zones configured\n"
            "- Treat RFC1918 addresses as internal, everything else as external"
        )
    lines = []
    for i, z in enumerate(zones, 1):
        cidr = f"INT-NET-{i:03d}" if scrub_zones else z.cidr
        lines.append(f"- {cidr} = {z.name} ({z.description})")
    return "\n".join(lines)


def _scrub_ips(alerts: list, internal_prefixes: list[str]) -> tuple[list, dict]:
    """Replace real IPs with anonymized tokens. Returns scrubbed alerts and the mapping."""
    mapping: dict[str, str] = {}
    int_counter, ext_counter = 0, 0

    def token(ip: str) -> str:
        nonlocal int_counter, ext_counter
        if ip in mapping:
            return mapping[ip]
        if any(ip.startswith(p) for p in internal_prefixes):
            int_counter += 1
            tok = f"INT-{int_counter:03d}"
        else:
            ext_counter += 1
            tok = f"EXT-{ext_counter:03d}"
        mapping[ip] = tok
        return tok

    scrubbed = []
    for a in alerts:
        s = dict(a)
        s["source_ip"] = (
            token(a["source_ip"])
            if a.get("source_ip") and a["source_ip"] != "?"
            else a["source_ip"]
        )
        s["dest_ip"] = (
            token(a["dest_ip"]) if a.get("dest_ip") and a["dest_ip"] != "?" else a["dest_ip"]
        )
        scrubbed.append(s)

    return scrubbed, {v: k for k, v in mapping.items()}


def _build_triage_prompt(
    alerts: list,
    max_batch: int,
    zones,
    scrub_ips: bool = True,
    scrub_zones: bool = True,
    internal_prefixes: list[str] | None = None,
    correlated_rules: list[str] | None = None,
) -> tuple[str, dict]:
    """Build an LLM prompt for triaging a group of similar alerts.
    Returns (prompt, ip_map) where ip_map is token->real_ip (empty if not scrubbing)."""
    ip_map: dict[str, str] = {}

    if scrub_ips and internal_prefixes:
        alerts, ip_map = _scrub_ips(alerts, internal_prefixes)

    rule_name = alerts[0]["rule_name"]
    source_ip = alerts[0]["source_ip"]

    dests = set()
    for a in alerts[:max_batch]:
        dests.add(f"{a['dest_ip']}:{a['dest_port']}")

    times = [a["timestamp"] for a in alerts]
    time_range = f"{min(times)} to {max(times)}" if len(times) > 1 else times[0]
    sample = alerts[0]

    zone_context = _build_zone_context(zones, scrub_zones=scrub_zones)
    ip_legend = (
        "\n- INT-* = internal network addresses, EXT-* = external/internet addresses"
        if scrub_ips and internal_prefixes
        else ""
    )
    correlated_line = (
        f"- Other rules on same flow: {', '.join(correlated_rules[:10])}\n"
        if correlated_rules
        else ""
    )

    prompt = f"""You are a Security Operations Center analyst triaging IDS alerts from a home/small business network.

Network context:
{zone_context}
- External IPs = internet traffic
- This is a home lab / small business, not an enterprise{ip_legend}

Alert group to triage:
- Rule: {rule_name}
- Ruleset: {sample["ruleset"]}
- Signature severity: {sample["sig_severity"]}
- Rule severity: {sample["rule_severity"]}
- Category: {sample["category"]}
- Source IP: {source_ip}
- Destinations: {", ".join(list(dests)[:10])}
- Alert count: {len(alerts)}
- Time range: {time_range}
- Action: {sample["action"]}
{correlated_line}
Classify this alert group into ONE of these categories:
- NOISE: Expected/benign traffic for this network type. No action needed.
- LOW: Minor finding, FYI only. Log and move on.
- MEDIUM: Worth investigating when convenient. Not urgent but notable.
- HIGH: Investigate immediately. Possible security incident.

Important classification guidelines:
- Any scanning activity (SSH, port scans) from EXTERNAL IPs = at least MEDIUM
- Any CVE-related signature = at least MEDIUM
- NTLM authentication on internal network in a small environment = LOW (expected)
- SNMP with default community strings = MEDIUM (misconfiguration risk)
- Be conservative: when in doubt, classify higher rather than lower

Respond in this exact JSON format (no other text):
{{"verdict": "NOISE|LOW|MEDIUM|HIGH", "reason": "Brief explanation (1-2 sentences)", "recommendation": "What to do about it (1 sentence)"}}
"""
    return prompt, ip_map


def _enforce_minimum_severity(
    rule_name: str, verdict: str, min_medium: list[str], min_high: list[str]
) -> str:
    """Enforce minimum severity based on rule name patterns."""
    severity_order = {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    current = severity_order.get(verdict, 1)

    for pattern in min_high:
        if pattern in rule_name:
            return "HIGH" if current < 3 else verdict

    for pattern in min_medium:
        if rule_name.startswith(pattern) or pattern in rule_name:
            return "MEDIUM" if current < 2 else verdict

    return verdict


def _triage_with_llm(
    alerts: list,
    llm: LLMClient,
    cfg_triage,
    zones,
    log,
    llm_log_path: Path | None = None,
    internal_prefixes: list[str] | None = None,
    flow_groups: dict | None = None,
) -> dict:
    """Send alert group to LLM for triage classification."""
    correlated_rules = _correlated_rules_for_group(alerts, flow_groups) if flow_groups else []
    prompt, ip_map = _build_triage_prompt(
        alerts,
        cfg_triage.max_batch_size,
        zones,
        scrub_ips=cfg_triage.scrub_ips,
        scrub_zones=cfg_triage.scrub_zones,
        internal_prefixes=internal_prefixes,
        correlated_rules=correlated_rules,
    )
    raw_response = None
    verdict_info = {
        "verdict": "LOW",
        "reason": "LLM classification failed, defaulting to LOW",
        "recommendation": "Manual review recommended",
    }
    try:
        raw_response = llm.generate(prompt, temperature=cfg_triage.llm_temperature)
        start = raw_response.find("{")
        end = raw_response.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(raw_response[start:end])
            verdict = result.get("verdict", "LOW").upper()
            if verdict not in ("NOISE", "LOW", "MEDIUM", "HIGH"):
                verdict = "LOW"

            rule_name = alerts[0]["rule_name"]
            original_verdict = verdict
            verdict = _enforce_minimum_severity(
                rule_name,
                verdict,
                cfg_triage.escalation.minimum_medium,
                cfg_triage.escalation.minimum_high,
            )
            reason = result.get("reason", "")
            if verdict != original_verdict:
                reason += f" [Escalated from {original_verdict} due to rule pattern]"

            verdict_info = {
                "verdict": verdict,
                "reason": reason,
                "recommendation": result.get("recommendation", ""),
            }
    except Exception as exc:
        log.warning("LLM triage failed for %s: %s", alerts[0]["rule_name"], exc)

    if llm_log_path is not None:
        entry = {
            "called_at": datetime.now(timezone.utc).isoformat(),
            "rule_name": alerts[0]["rule_name"],
            "source_ip": alerts[0]["source_ip"],
            "alert_count": len(alerts),
            "scrub_ips": cfg_triage.scrub_ips,
            "ip_map": ip_map,
            "prompt_chars": len(prompt),
            "prompt": prompt,
            "raw_response": raw_response,
            "verdict": verdict_info["verdict"],
            "reason": verdict_info["reason"],
        }
        with open(llm_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    return verdict_info


def _log_triage_result(alert: dict, verdict_info: dict, jsonl_path: Path) -> dict:
    """Append a triage result to the JSONL log. Returns the entry."""
    entry = {
        "triaged_at": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert["id"],
        "alert_timestamp": alert["timestamp"],
        "rule_name": alert["rule_name"],
        "source_ip": alert["source_ip"],
        "dest_ip": alert["dest_ip"],
        "dest_port": alert["dest_port"],
        "rule_severity": alert["rule_severity"],
        "sig_severity": alert["sig_severity"],
        "verdict": verdict_info.get("verdict", alert.get("triage_verdict", "?")),
        "reason": verdict_info.get("reason", alert.get("triage_reason", "")),
        "recommendation": verdict_info.get("recommendation", ""),
        "method": verdict_info.get("method", alert.get("triage_method", "llm")),
    }
    with open(jsonl_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _generate_summary(
    results: list,
    detection_alerts: list,
    run_time: float,
    summary_dir: Path,
    dry_run: bool = False,
) -> tuple[Path, str]:
    """Generate a human-readable triage summary markdown."""
    now = datetime.now(timezone.utc)
    prefix = "dryrun_" if dry_run else "triage_"
    summary_file = summary_dir / f"{prefix}{now.strftime('%Y%m%d_%H%M%S')}.md"

    verdict_counts: dict[str, int] = defaultdict(int)
    verdict_groups: dict[str, list] = defaultdict(list)
    for r in results:
        v = r["verdict"]
        verdict_counts[v] += 1
        verdict_groups[v].append(r)

    title = (
        "# SO Alert Triage DRY RUN (rule-based, no LLM)" if dry_run else "# SO Alert Triage Summary"
    )
    lines = [
        title,
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Processing time:** {run_time:.1f}s",
        f"**Alerts processed:** {len(results)}",
        *(
            [
                "**Note:** Verdicts based on Suricata severity + escalation rules only — LLM not called",
                "",
            ]
            if dry_run
            else [""]
        ),
        "## Verdict Breakdown",
    ]
    for v in ("HIGH", "MEDIUM", "LOW", "NOISE"):
        count = verdict_counts.get(v, 0)
        pct = (count / len(results) * 100) if results else 0
        bar = "#" * int(pct / 2)
        lines.append(f"- **{v}**: {count} ({pct:.1f}%) {bar}")
    lines.append("")

    def _fmt_alert_group(r_list: list) -> list[str]:
        """Return detail lines for a group of alerts sharing a rule_name."""
        out = []
        by_rule: dict[str, list] = defaultdict(list)
        for r in r_list:
            by_rule[r["rule_name"]].append(r)
        for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1])):
            src_ips = sorted(
                {r["source_ip"] for r in items if r.get("source_ip") and r["source_ip"] != "?"}
            )
            dst_ips = sorted(
                {r["dest_ip"] for r in items if r.get("dest_ip") and r["dest_ip"] != "?"}
            )
            dst_ports = sorted(
                {
                    str(r["dest_port"])
                    for r in items
                    if r.get("dest_port") and str(r["dest_port"]) != "?"
                }
            )
            method = items[0].get("method", "?")
            reason = items[0].get("reason", "")
            rec = items[0].get("recommendation", "")
            out.append(f"### {rule}")
            out.append(f"- **Alerts:** {len(items)}  |  **Method:** {method}")
            out.append(
                f"- **Sources:** {', '.join(src_ips[:10])}{'...' if len(src_ips) > 10 else ''}"
            )
            out.append(
                f"- **Targets:** {', '.join(dst_ips[:10])}{'...' if len(dst_ips) > 10 else ''}"
                + (f"  port(s): {', '.join(dst_ports[:5])}" if dst_ports else "")
            )
            out.append(f"- **Classification:** {reason}")
            if rec and rec != "Dry run — no action taken":
                out.append(f"- **Action:** {rec}")
            out.append("")
        return out

    if verdict_groups.get("HIGH"):
        lines.append("## HIGH Priority - Investigate Immediately")
        lines.append("")
        lines += _fmt_alert_group(verdict_groups["HIGH"])

    if verdict_groups.get("MEDIUM"):
        lines.append("## MEDIUM Priority - Investigate When Convenient")
        lines.append("")
        lines += _fmt_alert_group(verdict_groups["MEDIUM"])

    if verdict_groups.get("LOW"):
        lines.append("## LOW Priority - FYI")
        lines.append("")
        low_by_rule: dict[str, list] = defaultdict(list)
        for r in verdict_groups["LOW"]:
            low_by_rule[r["rule_name"]].append(r)
        for rule, items in sorted(low_by_rule.items(), key=lambda x: -len(x[1])):
            src_ips = sorted(
                {r["source_ip"] for r in items if r.get("source_ip") and r["source_ip"] != "?"}
            )
            dst_ips = sorted(
                {r["dest_ip"] for r in items if r.get("dest_ip") and r["dest_ip"] != "?"}
            )
            lines.append(f"- **{rule}** ({len(items)} alerts)")
            lines.append(
                f"  - Sources: {', '.join(src_ips[:8])}{'...' if len(src_ips) > 8 else ''}"
            )
            lines.append(
                f"  - Targets: {', '.join(dst_ips[:8])}{'...' if len(dst_ips) > 8 else ''}"
            )
            if items[0].get("reason"):
                lines.append(f"  - {items[0]['reason']}")
        lines.append("")

    if verdict_groups.get("NOISE"):
        lines.append("## NOISE - Auto-Cleared")
        noise_by_rule: dict[str, int] = defaultdict(int)
        for r in verdict_groups["NOISE"]:
            noise_by_rule[r["rule_name"]] += 1
        for rule, count in sorted(noise_by_rule.items(), key=lambda x: -x[1]):
            lines.append(f"- {rule}: {count} alerts")
        lines.append("")

    if detection_alerts:
        lines.append("## Sigma Detection Alerts")
        for da in detection_alerts:
            src = da["_source"]
            rule = src.get("rule", {})
            lines.append(
                f"- **{rule.get('name', 'Unknown')}** (severity: {src.get('sigma_level', '?')})"
            )
            lines.append(f"  - Time: {src.get('@timestamp', '?')}")
        lines.append("")

    summary_text = "\n".join(lines)
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_file.write_text(summary_text)
    return summary_file, summary_text


def run_triage(cfg: Config, dry_run: bool = False):
    """Main triage entry point."""
    data_dir = cfg.paths.data_dir
    log_dir = data_dir / "logs"
    state_dir = data_dir / "state"
    summary_dir = data_dir / "output" / "triage" / "summaries"
    jsonl_path = log_dir / "triage.jsonl"
    llm_log_path = log_dir / "triage_llm_calls.jsonl"

    log = setup_logging("triage", log_dir)
    state = ToolState("triage", state_dir)
    state.start_run()

    es = SOElasticClient(cfg.elasticsearch)
    llm = make_llm_client(cfg)
    indices = cfg.elasticsearch.indices
    zones = cfg.network.zones

    noise_sigs = set(cfg.triage.auto_noise.signatures)
    start_time = time.time()

    # Determine starting point
    default_since = (
        datetime.now(timezone.utc) - timedelta(hours=cfg.triage.lookback_hours)
    ).isoformat()
    since = state.get_cursor("last_timestamp", default_since)
    log.info("=" * 60)
    log.info("SO Alert Triage starting (dry_run=%s)", dry_run)
    log.info("Processing alerts since: %s", since)

    all_results = []
    all_detection_alerts = []

    while True:
        log.info("Fetching Suricata alerts (since %s)...", since)
        hits, total_available = es.fetch_suricata_alerts(
            since, cfg.triage.max_alerts_per_query, index=indices.suricata
        )
        log.info("Fetched %d alerts (total available: %d)", len(hits), total_available)

        if not hits:
            break

        # Fetch detection alerts only on first iteration
        if not all_detection_alerts:
            all_detection_alerts = es.fetch_detection_alerts(
                state.get_cursor("last_timestamp", default_since),
                index=indices.detections,
            )
            if all_detection_alerts:
                log.info("Also found %d Sigma detection alerts", len(all_detection_alerts))

        alerts = [_extract_alert_summary(hit) for hit in hits]
        flow_groups = _group_alerts_by_flow(alerts)
        auto_noise, needs_review = _classify_auto_noise(alerts, noise_sigs)
        log.info(
            "Auto-classified %d as NOISE, %d need LLM review", len(auto_noise), len(needs_review)
        )

        # Log auto-noise results
        for alert in auto_noise:
            entry = _log_triage_result(
                alert,
                {
                    "verdict": "NOISE",
                    "reason": alert["triage_reason"],
                    "recommendation": "No action needed",
                    "method": "auto",
                },
                jsonl_path,
            )
            all_results.append(entry)

        # Group remaining alerts for LLM triage
        if needs_review and not dry_run:
            groups = _group_alerts(needs_review)
            log.info("Grouped into %d unique signature+source combinations", len(groups))

            for i, (group_key, group_alerts_list) in enumerate(groups.items()):
                rule_name = group_alerts_list[0]["rule_name"]
                log.info(
                    "  [%d/%d] Triaging: %s (%d alerts)",
                    i + 1,
                    len(groups),
                    rule_name,
                    len(group_alerts_list),
                )

                verdict_info = _triage_with_llm(
                    group_alerts_list,
                    llm,
                    cfg.triage,
                    zones,
                    log,
                    llm_log_path,
                    internal_prefixes=cfg.network.internal_prefixes,
                    flow_groups=flow_groups,
                )
                verdict_info["method"] = "llm"
                log.info("    -> %s: %s", verdict_info["verdict"], verdict_info["reason"][:80])

                for alert in group_alerts_list:
                    entry = _log_triage_result(alert, verdict_info, jsonl_path)
                    all_results.append(entry)
        elif needs_review and dry_run:
            groups = _group_alerts(needs_review)
            log.info(
                "DRY RUN: rule-based classification for %d groups (%d alerts)",
                len(groups),
                len(needs_review),
            )
            sev_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
            for group_alerts_list in groups.values():
                rule_name = group_alerts_list[0]["rule_name"]
                raw_sev = group_alerts_list[0].get("rule_severity", "?")
                try:
                    base_verdict = sev_map.get(int(raw_sev), "LOW")
                except (ValueError, TypeError):
                    base_verdict = "LOW"

                verdict = _enforce_minimum_severity(
                    rule_name,
                    base_verdict,
                    cfg.triage.escalation.minimum_medium,
                    cfg.triage.escalation.minimum_high,
                )

                # Check if correlated flows warrant further escalation
                correlated = _correlated_rules_for_group(group_alerts_list, flow_groups)
                corr_verdict, corr_reason = _correlated_escalation(
                    correlated,
                    verdict,
                    cfg.triage.escalation.minimum_medium,
                    cfg.triage.escalation.minimum_high,
                )

                if corr_verdict != verdict:
                    reason = (
                        f"Suricata severity {raw_sev} ({base_verdict}), "
                        f"escalated to {corr_verdict}: {corr_reason}"
                    )
                    method = "rule-correlated"
                    verdict = corr_verdict
                elif verdict != base_verdict:
                    reason = (
                        f"Suricata severity {raw_sev} ({base_verdict}) "
                        f"escalated to {verdict} by rule pattern"
                    )
                    method = "rule-escalated"
                elif base_verdict in ("HIGH", "MEDIUM"):
                    reason = f"Suricata severity {raw_sev} — would need LLM to confirm"
                    method = "rule-severity"
                else:
                    reason = f"Suricata severity {raw_sev} — would need LLM to confirm or downgrade to NOISE"
                    method = "needs-llm"

                corr_note = f" [correlated: {', '.join(correlated[:3])}]" if correlated else ""
                verdict_info = {
                    "verdict": verdict,
                    "reason": reason + corr_note,
                    "recommendation": "Dry run — no action taken",
                    "method": method,
                }
                for alert in group_alerts_list:
                    entry = _log_triage_result(alert, verdict_info, jsonl_path)
                    all_results.append(entry)

        # Update cursor only on live runs so dry run can be repeated
        if not dry_run:
            since = hits[-1]["_source"]["@timestamp"]
            state.set_cursor("last_timestamp", since)
        else:
            since = hits[-1]["_source"]["@timestamp"]

        if len(hits) < cfg.triage.max_alerts_per_query:
            break

    if not all_results:
        log.info("No new alerts to process.")
        run_time = time.time() - start_time
        state.finish_run(alerts=0)
        if dry_run:
            print("\nDRY RUN: no alerts found — try resetting the cursor first:")
            print("  Remove-Item C:\\CBFiles\\so-ops-data\\state\\triage.json -Force")
        return

    run_time = time.time() - start_time
    summary_file, summary_text = _generate_summary(
        all_results, all_detection_alerts, run_time, summary_dir, dry_run=dry_run
    )
    log.info("Processed %d alerts in %.1fs", len(all_results), run_time)
    log.info("Summary: %s", summary_file)

    high_count = sum(1 for r in all_results if r["verdict"] == "HIGH")

    notify_log_path = log_dir / "triage_notifications.jsonl"

    def _log_notification(subject: str, alerts_sent: list, providers: dict[str, bool]):
        """Append a structured record of a dispatched notification."""
        entry = {
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "subject": subject,
            "alert_count": len(alerts_sent),
            "alerts": [
                {
                    "rule_name": a.get(
                        "rule_name", a.get("_source", {}).get("rule", {}).get("name", "?")
                    ),
                    "source_ip": a.get("source_ip", "?"),
                    "dest_ip": a.get("dest_ip", "?"),
                    "dest_port": a.get("dest_port", "?"),
                    "verdict": a.get("verdict", "?"),
                    "reason": a.get("reason", ""),
                }
                for a in alerts_sent
            ],
            "providers": providers,
        }
        with open(notify_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    # Send notifications for HIGH severity alerts
    if not dry_run:
        high_alerts = [r for r in all_results if r["verdict"] == "HIGH"]
        if high_alerts:
            log.info("HIGH alerts detected (%d) — sending notifications...", len(high_alerts))
            alert_lines = [f"HIGH SEVERITY ALERT - {len(high_alerts)} alert(s) detected\n"]
            for a in high_alerts:
                alert_lines.append(f"  Rule: {a['rule_name']}")
                alert_lines.append(f"  Source: {a['source_ip']} -> {a['dest_ip']}:{a['dest_port']}")
                alert_lines.append(f"  Reason: {a['reason']}")
                alert_lines.append(f"  Recommendation: {a['recommendation']}")
                alert_lines.append("")
            alert_lines.append(f"Full summary:\n{summary_text}")

            sms_lines = [f"SO ALERT: {len(high_alerts)} HIGH severity"]
            seen_rules: set[str] = set()
            for a in high_alerts:
                if a["rule_name"] not in seen_rules:
                    sms_lines.append(f"- {a['rule_name']}")
                    sms_lines.append(f"  {a['source_ip']} -> {a['dest_ip']}")
                    seen_rules.add(a["rule_name"])

            subject = f"[SO ALERT] HIGH severity - {high_alerts[0]['rule_name']}"
            providers = notify_all(
                cfg.notifications,
                subject,
                "\n".join(alert_lines),
                short="\n".join(sms_lines),
            )
            _log_notification(subject, high_alerts, providers)

        # Notify for high-severity Sigma detections
        if all_detection_alerts:
            high_sigma = [
                d
                for d in all_detection_alerts
                if d["_source"].get("sigma_level") in ("high", "critical")
            ]
            if high_sigma:
                log.info("Sigma detections (%d) — sending notifications...", len(high_sigma))
                det_rules: dict[str, int] = defaultdict(int)
                for d in high_sigma:
                    name = d["_source"].get("rule", {}).get("name", "Unknown")
                    det_rules[name] += 1
                det_lines = [f"SO SIGMA: {len(high_sigma)} detection(s)"]
                for rule, count in sorted(det_rules.items(), key=lambda x: -x[1]):
                    det_lines.append(f"- {rule} (x{count})")
                subject = f"[SO SIGMA] {len(high_sigma)} detection(s)"
                providers = notify_all(
                    cfg.notifications,
                    subject,
                    "\n".join(det_lines),
                )
                _log_notification(subject, high_sigma, providers)

    state.finish_run(alerts=len(all_results), high=high_count)
    print("\n" + summary_text)
