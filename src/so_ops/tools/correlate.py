"""Alert correlation orchestrator.

Reads triage.jsonl and runs four passes:
  1. correlate_patterns  — behavioural pattern detection (no LLM)
  2. correlate_vuln      — cross-reference with nmap/nuclei scans
  3. correlate_report    — markdown report + LLM brief on rule patterns
  4. correlate_triage_llm — independent LLM review of grouped triage (T-1 + T-0)

Implementation lives in correlate_*.py modules alongside this file.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from so_ops.clients.notify import notify_all
from so_ops.config import Config
from so_ops.log import setup_logging
from so_ops.state import ToolState
from so_ops.tools.correlate_common import load_triage_entries
from so_ops.tools.correlate_patterns import correlate_alert_patterns
from so_ops.tools.correlate_report import CONSOLE_PATTERN_LABELS, build_report, summarize_with_llm
from so_ops.tools.correlate_triage_llm import (
    format_triage_digest_detail,
    run_triage_llm_review,
)
from so_ops.tools.correlate_vuln import (
    correlate_vuln,
    find_latest_file,
    load_nmap_index,
    load_nuclei_index,
)


def run_correlate(
    cfg: Config,
    lookback_hours: int = 48,
    lookback_minutes: int | None = None,
    skip_vuln: bool = False,
):
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
    log.info("Triage lookback (rules): %s", _lookback_label)

    # ── Load triage log (rule window) ─────────────────────────────────
    triage_jsonl = log_dir / "triage.jsonl"
    cutoff = datetime.now(timezone.utc) - _lookback

    if not triage_jsonl.exists():
        log.warning("No triage log at %s — run 'so-ops triage' first", triage_jsonl)
        print(f"No triage log found. Run 'so-ops triage' first.\nExpected: {triage_jsonl}")
        state.finish_run(correlations=0)
        return

    entries, load_stats = load_triage_entries(triage_jsonl, cutoff)
    log.info(
        "Rule window: %d total lines, %d unique alerts, %d skipped (outside window), "
        "%d skipped (noise), %d skipped (invalid), %d skipped (no alert_id)",
        load_stats["total"],
        load_stats["in_window"],
        load_stats["skipped_old"],
        load_stats["skipped_noise"],
        load_stats["skipped_invalid"],
        load_stats["skipped_no_id"],
    )

    if not entries:
        log.warning("No alerts in rule window (%s) — Pass 1-3 will be empty", _lookback_label)
        print(f"No triage alerts in rule window ({_lookback_label}). Pass 4 may still run.")

    # ── Pass 1: alert × alert patterns ───────────────────────────────
    log.info("=== Pass 1: alert pattern detection (%d alerts) ===", len(entries))
    patterns = correlate_alert_patterns(
        entries, cfg.network.internal_prefixes, log, window_minutes=_lookback.total_seconds() / 60
    )
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
    vuln_findings: list[dict] = []

    if skip_vuln:
        log.info("Pass 2 skipped — --skip-vuln")
    elif scan_dir.exists():
        nmap_xml = find_latest_file(scan_dir, "nmap_*.xml")
        nuclei_jsonl = find_latest_file(scan_dir, "nuclei_*.jsonl")
        if nmap_xml:
            nmap_index = load_nmap_index(nmap_xml, log)
        if nuclei_jsonl:
            nuclei_index = load_nuclei_index(nuclei_jsonl, log)
    else:
        log.info("No vulnscan output dir — skipping vuln correlation (run 'so-ops scan' first)")

    if not skip_vuln and (nmap_index or nuclei_index):
        log.info(
            "=== Pass 2: vuln correlation (%d nmap, %d nuclei hosts) ===",
            len(nmap_index),
            len(nuclei_index),
        )
        vuln_findings = correlate_vuln(entries, nmap_index, nuclei_index, log)
        log.info(
            "Vuln findings: %d total (%d high, %d medium, %d low)",
            len(vuln_findings),
            sum(1 for f in vuln_findings if f["confidence"] == "high"),
            sum(1 for f in vuln_findings if f["confidence"] == "medium"),
            sum(1 for f in vuln_findings if f["confidence"] == "low"),
        )
    elif not skip_vuln:
        log.info("Pass 2 skipped — no scan data available")

    # ── Write JSONL log ───────────────────────────────────────────────
    findings_log = log_dir / "correlate_findings.jsonl"
    all_findings = patterns + vuln_findings
    with open(findings_log, "a", encoding="utf-8") as fh:
        for item in all_findings:
            fh.write(json.dumps(item) + "\n")
    log.info("Wrote %d findings to %s", len(all_findings), findings_log)

    # ── Pass 3: LLM analyst brief (rule patterns) ─────────────────────
    log.info("=== Pass 3: LLM analyst brief (rule patterns) ===")
    llm_brief = summarize_with_llm(
        patterns, vuln_findings, cfg, log, lookback_label=_lookback_label
    )

    # ── Pass 4: LLM triage review (grouped HIGH/MEDIUM, T-1 + T-0) ───
    log.info("=== Pass 4: LLM triage review ===")
    summary_dir = data_dir / "output" / "triage" / "summaries"
    triage_llm = run_triage_llm_review(triage_jsonl, cfg, log, summary_dir)
    triage_llm_brief = triage_llm.brief

    # ── Build report ──────────────────────────────────────────────────
    report = build_report(
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
        triage_llm_brief=triage_llm_brief,
    )
    report_path = correlate_dir / f"report_{timestamp}.md"
    report_path.write_text(report, encoding="utf-8")
    log.info("Report: %s", report_path)

    state.finish_run(correlations=len(all_findings))

    # ── Notify ────────────────────────────────────────────────────────
    high_count = sum(1 for p in patterns if p["confidence"] == "high")
    med_count = sum(1 for p in patterns if p["confidence"] == "medium")
    changes = [f for f in vuln_findings if f["verdict_changed"]]

    pattern_notify = bool(high_count or med_count or changes)
    triage_only_notify = (
        cfg.correlate.notify_on_triage_llm
        and not pattern_notify
        and triage_llm.notify_recommended
        and triage_llm.brief
    )

    if pattern_notify or triage_only_notify:
        if pattern_notify:
            notify_title = (
                f"[so-ops] Correlation: {high_count} high / {med_count} medium patterns"
            )
        else:
            notify_title = "[so-ops] Triage review: analyst attention recommended"

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

        if changes:
            detail_lines.append("VERDICT UPGRADES FROM VULN CORRELATION:")
            for f in changes:
                detail_lines.append(
                    f"  [{f['triage_verdict']} -> {f['recommended_verdict']}] {f['rule_name'][:60]}"
                )
                detail_lines.append(
                    f"    {f['source_ip']} -> {f['dest_ip']}:{f['dest_port']}"
                    f" | matched {f['matched_ip']} ({f['match_type']})"
                )
                detail_lines.append(f"    {f['reason']}")
                detail_lines.append("")

        detail_block = "\n".join(detail_lines).strip()
        triage_detail = format_triage_digest_detail(triage_llm.digest)
        notify_parts: list[str] = []
        if llm_brief:
            notify_parts.append(llm_brief.strip())
        if triage_llm_brief:
            notify_parts.append("---\n\nTRIAGE REVIEW (AI)\n\n" + triage_llm_brief.strip())
        if detail_block:
            notify_parts.append("---\n\n" + detail_block)
        if triage_detail:
            notify_parts.append("---\n\nTRIAGE DETAIL\n\n" + triage_detail)
        notify_body = "\n\n".join(notify_parts) if notify_parts else detail_block
        notify_results = notify_all(cfg.notifications, notify_title, notify_body)

        failed = [name for name, ok in notify_results.items() if not ok]
        if failed:
            log.error("Notification FAILED for provider(s): %s", ", ".join(failed))
        succeeded = [name for name, ok in notify_results.items() if ok]
        if succeeded:
            log.info("Notification sent via: %s", ", ".join(succeeded))
        if not notify_results:
            log.warning("Notification not sent — no providers enabled")

        notify_log_path = log_dir / "correlate_notifications.jsonl"
        with open(notify_log_path, "a") as f:
            f.write(
                json.dumps(
                    {
                        "sent_at": datetime.now(timezone.utc).isoformat(),
                        "subject": notify_title,
                        "providers": notify_results,
                    }
                )
                + "\n"
            )

    # ── Console summary ───────────────────────────────────────────────
    high_p = [p for p in patterns if p["confidence"] == "high"]

    print("\n" + "=" * 60)
    print("CORRELATION COMPLETE")
    print("=" * 60)
    print(f"Alerts analysed:  {len(entries)} (rule window {_lookback_label})")
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

    if high_p:
        print("\nHIGH CONFIDENCE PATTERNS:")
        for p in high_p:
            label = CONSOLE_PATTERN_LABELS.get(p["pattern_type"], p["pattern_type"].upper())
            peer = f" -> {p['peer_ip']}" if p["peer_ip"] else ""
            print(f"  [{p['recommended_verdict']}] {label}: {p['pivot_ip']}{peer}")
            print(f"        {p['reason'][:90]}")

    if changes:
        print("\nVULN VERDICT UPGRADES:")
        for f in changes:
            verdict_from = f["triage_verdict"]
            verdict_to = f["recommended_verdict"]
            print(f"  {verdict_from:6s} -> {verdict_to:6s}  {f['rule_name'][:55]}")

    if llm_brief:
        print("\n" + "-" * 60)
        print("ANALYST BRIEF — RULE PATTERNS (AI):")
        print("-" * 60)
        print(llm_brief.strip())

    if triage_llm_brief:
        print("\n" + "-" * 60)
        print("ANALYST BRIEF — TRIAGE REVIEW (AI):")
        print("-" * 60)
        print(triage_llm_brief.strip())

    print(f"\nReport: {report_path}")
    print(f"Log:    {findings_log}")
