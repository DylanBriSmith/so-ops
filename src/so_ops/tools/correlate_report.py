"""Pass 3 support: markdown report and LLM analyst brief."""

from __future__ import annotations

from so_ops.clients import make_llm_client
from so_ops.config import Config
from so_ops.tools.correlate_common import REPORT_CATEGORY_ORDER, rule_category

# ── Report ────────────────────────────────────────────────────────────────────

# (markdown_label, console_label) — keep in sync with pattern_type in correlate_patterns.py
PATTERN_LABELS: dict[str, tuple[str, str]] = {
    "scan_to_exploit": ("SCAN→EXPLOIT chain", "SCAN->EXPLOIT"),
    "targeted_host": ("Host targeted (scan + exploit)", "TARGETED HOST"),
    "lateral_movement": ("Lateral movement / internal sweep", "LATERAL MOVEMENT"),
    "port_sweep": ("Port sweep (same port, many hosts)", "PORT SWEEP"),
    "multi_rule_pair": ("Sustained multi-rule attack (same pair)", "MULTI-RULE PAIR"),
    "c2_beacon": ("C2 / beaconing (TROJAN/MALWARE rules)", "C2 BEACON"),
    "high_volume_src": ("High-volume source", "HIGH VOLUME"),
    "inbound_sweep": ("Inbound sweep (external → many internal hosts)", "INBOUND SWEEP"),
    "brute_force": ("Brute force / credential attack", "BRUTE FORCE"),
    "single_rule_flood": ("Single-rule flood (repeated identical alert)", "RULE FLOOD"),
    "internal_exploit": ("Internal→internal exploitation", "INTERNAL EXPLOIT"),
    "src_ip_pivot": ("Source IP pivot (shared origin across rules)", "SRC PIVOT"),
    "dest_ip_pivot": ("Destination IP pivot (shared target across sources)", "DEST PIVOT"),
    "dest_port_pivot": ("Destination port pivot (shared port across sources)", "PORT PIVOT"),
}

CONSOLE_PATTERN_LABELS = {k: labels[1] for k, labels in PATTERN_LABELS.items()}


def build_report(
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
        for p in high_p + med_p + low_p:
            label = PATTERN_LABELS.get(p["pattern_type"], (p["pattern_type"],))[0]
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
                cat = rule_category(r)
                by_cat.setdefault(cat, []).append(r)

            for cat in REPORT_CATEGORY_ORDER:
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


def summarize_with_llm(
    patterns: list[dict],
    vuln_findings: list[dict],
    cfg: Config,
    log,
    lookback_label: str = "48h",
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
        f"Below are HIGH and MEDIUM confidence security patterns detected in the last {lookback_label}.",
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
