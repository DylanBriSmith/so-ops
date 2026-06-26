"""Mock triage runner — simulates a full triage run without Elasticsearch.

Generates realistic fake Suricata alerts, runs them through the full pipeline:
  - Auto-noise classification
  - LLM triage via OpenRouter
  - ntfy notification for HIGH alerts

Usage:
    python scripts/mock_triage.py
    python scripts/mock_triage.py --dry-run   # skip LLM + notifications
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Make sure src/ is on path when running directly
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from so_ops.clients import make_llm_client
from so_ops.clients.notify import notify_all
from so_ops.config import load_config
from so_ops.tools.triage import (
    _build_triage_prompt,
    _classify_auto_noise,
    _enforce_minimum_severity,
    _generate_summary,
    _group_alerts,
    _log_triage_result,
)


# ── Fake alert data ───────────────────────────────────────────────────────────

def _ts(minutes_ago: int) -> str:
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return t.isoformat()


FAKE_ALERTS = [
    # Should be AUTO-NOISE (known benign)
    {
        "rule_name": "ET INFO Microsoft Connection Test",
        "rule_severity": 3, "sig_severity": "Informational",
        "category": "Not Suspicious Traffic",
        "source_ip": "192.168.1.55", "source_port": 50234,
        "dest_ip": "13.107.4.52", "dest_port": 80,
        "timestamp": _ts(5), "ruleset": "ET", "action": "allowed",
        "community_id": "1:abc123",
    },
    {
        "rule_name": "ET INFO Microsoft Connection Test",
        "rule_severity": 3, "sig_severity": "Informational",
        "category": "Not Suspicious Traffic",
        "source_ip": "192.168.1.22", "source_port": 49100,
        "dest_ip": "13.107.4.52", "dest_port": 80,
        "timestamp": _ts(3), "ruleset": "ET", "action": "allowed",
        "community_id": "1:def456",
    },
    # Should be LOW — NTLM on internal network
    {
        "rule_name": "ET POLICY NTLM Authentication Request",
        "rule_severity": 2, "sig_severity": "Minor",
        "category": "Potential Corporate Privacy Violation",
        "source_ip": "192.168.1.10", "source_port": 445,
        "dest_ip": "192.168.1.5", "dest_port": 445,
        "timestamp": _ts(20), "ruleset": "ET", "action": "allowed",
        "community_id": "1:ghi789",
    },
    {
        "rule_name": "ET POLICY NTLM Authentication Request",
        "rule_severity": 2, "sig_severity": "Minor",
        "category": "Potential Corporate Privacy Violation",
        "source_ip": "192.168.1.12", "source_port": 445,
        "dest_ip": "192.168.1.5", "dest_port": 445,
        "timestamp": _ts(18), "ruleset": "ET", "action": "allowed",
        "community_id": "1:jkl012",
    },
    # Should be MEDIUM — SNMP default community string
    {
        "rule_name": "ET POLICY SNMP Default Community String (public)",
        "rule_severity": 2, "sig_severity": "Major",
        "category": "Potential Corporate Privacy Violation",
        "source_ip": "192.168.1.100", "source_port": 161,
        "dest_ip": "192.168.1.1", "dest_port": 161,
        "timestamp": _ts(45), "ruleset": "ET", "action": "allowed",
        "community_id": "1:mno345",
    },
    # Should be HIGH — SSH scan from external IP (escalation rule: ET SCAN)
    {
        "rule_name": "ET SCAN Potential SSH Scan OUTBOUND",
        "rule_severity": 1, "sig_severity": "Major",
        "category": "Attempted Information Leak",
        "source_ip": "185.234.218.55", "source_port": 44123,
        "dest_ip": "192.168.1.231", "dest_port": 22,
        "timestamp": _ts(10), "ruleset": "ET", "action": "alert",
        "community_id": "1:pqr678",
    },
    {
        "rule_name": "ET SCAN Potential SSH Scan OUTBOUND",
        "rule_severity": 1, "sig_severity": "Major",
        "category": "Attempted Information Leak",
        "source_ip": "185.234.218.55", "source_port": 44200,
        "dest_ip": "192.168.1.10", "dest_port": 22,
        "timestamp": _ts(9), "ruleset": "ET", "action": "alert",
        "community_id": "1:stu901",
    },
    {
        "rule_name": "ET SCAN Potential SSH Scan OUTBOUND",
        "rule_severity": 1, "sig_severity": "Major",
        "category": "Attempted Information Leak",
        "source_ip": "185.234.218.55", "source_port": 44300,
        "dest_ip": "192.168.1.5", "dest_port": 22,
        "timestamp": _ts(8), "ruleset": "ET", "action": "alert",
        "community_id": "1:vwx234",
    },
    # Should be HIGH — known trojan signature
    {
        "rule_name": "ET TROJAN Possible Cobalt Strike Beacon",
        "rule_severity": 1, "sig_severity": "Critical",
        "category": "A Network Trojan was Detected",
        "source_ip": "192.168.1.77", "source_port": 52341,
        "dest_ip": "94.102.49.190", "dest_port": 443,
        "timestamp": _ts(2), "ruleset": "ET", "action": "alert",
        "community_id": "1:yza567",
    },
]


# ── Mock triage run ───────────────────────────────────────────────────────────

def run_mock_triage(cfg, dry_run: bool = False):
    data_dir = cfg.paths.data_dir
    log_dir = data_dir / "logs"
    summary_dir = data_dir / "output" / "triage" / "summaries"
    jsonl_path = log_dir / "triage.jsonl"

    log_dir.mkdir(parents=True, exist_ok=True)
    summary_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("SO Alert Triage — MOCK RUN")
    print(f"  {len(FAKE_ALERTS)} fake alerts | dry_run={dry_run}")
    print("=" * 60)

    llm = make_llm_client(cfg) if not dry_run else None
    noise_sigs = set(cfg.triage.auto_noise.signatures)
    zones = cfg.network.zones
    start = time.time()

    # Add required id field
    alerts = [dict(a, id=f"mock-{i}") for i, a in enumerate(FAKE_ALERTS)]

    auto_noise, needs_review = _classify_auto_noise(alerts, noise_sigs)
    print(f"\nAuto-classified {len(auto_noise)} as NOISE, {len(needs_review)} need LLM review")

    all_results = []

    for alert in auto_noise:
        entry = _log_triage_result(alert, {
            "verdict": "NOISE",
            "reason": alert["triage_reason"],
            "recommendation": "No action needed",
            "method": "auto",
        }, jsonl_path)
        all_results.append(entry)
        print(f"  [AUTO] NOISE  — {alert['rule_name']}")

    if needs_review:
        groups = _group_alerts(needs_review)
        print(f"\nGrouped into {len(groups)} unique signature+source combinations")

        for group_key, group_alerts in groups.items():
            rule_name = group_alerts[0]["rule_name"]

            if dry_run:
                print(f"  [DRY]  SKIP   — {rule_name} ({len(group_alerts)} alerts)")
                continue

            print(f"  [LLM]  ...     — {rule_name} ({len(group_alerts)} alerts)", end="", flush=True)
            prompt = _build_triage_prompt(group_alerts, cfg.triage.max_batch_size, zones)

            try:
                response = llm.generate(prompt, temperature=cfg.triage.llm_temperature)
                start_j = response.find("{")
                end_j = response.rfind("}") + 1
                result = json.loads(response[start_j:end_j])
                verdict = result.get("verdict", "LOW").upper()
                if verdict not in ("NOISE", "LOW", "MEDIUM", "HIGH"):
                    verdict = "LOW"

                original = verdict
                verdict = _enforce_minimum_severity(
                    rule_name, verdict,
                    cfg.triage.escalation.minimum_medium,
                    cfg.triage.escalation.minimum_high,
                )
                reason = result.get("reason", "")
                if verdict != original:
                    reason += f" [Escalated from {original}]"

                verdict_info = {
                    "verdict": verdict,
                    "reason": reason,
                    "recommendation": result.get("recommendation", ""),
                    "method": "llm",
                }
            except Exception as exc:
                print(f" ERROR: {exc}")
                verdict_info = {"verdict": "LOW", "reason": f"LLM error: {exc}", "recommendation": "Manual review", "method": "llm"}

            print(f"\r  [LLM]  {verdict_info['verdict']:<6} — {rule_name}")
            print(f"         Reason: {verdict_info['reason'][:100]}")

            for alert in group_alerts:
                entry = _log_triage_result(alert, verdict_info, jsonl_path)
                all_results.append(entry)

    run_time = time.time() - start
    summary_file, summary_text = _generate_summary(all_results, [], run_time, summary_dir)

    print(f"\n{'=' * 60}")
    print(summary_text)

    if not dry_run:
        high_alerts = [r for r in all_results if r["verdict"] == "HIGH"]
        if high_alerts:
            print(f"Sending ntfy notification for {len(high_alerts)} HIGH alert(s)...")
            alert_lines = [f"HIGH SEVERITY - {len(high_alerts)} alert(s)\n"]
            for a in high_alerts:
                alert_lines.append(f"  Rule: {a['rule_name']}")
                alert_lines.append(f"  {a['source_ip']} -> {a['dest_ip']}:{a['dest_port']}")
                alert_lines.append(f"  {a['reason']}")
                alert_lines.append("")

            # Build detailed short message (shown as push notification body)
            seen_rules: dict[str, list] = {}
            for a in high_alerts:
                seen_rules.setdefault(a["rule_name"], []).append(a["source_ip"])
            short_lines = [f"SO ALERT: {len(high_alerts)} HIGH severity"]
            for rule, ips in seen_rules.items():
                unique_ips = list(dict.fromkeys(ips))
                short_lines.append(f"- {rule}")
                short_lines.append(f"  from {', '.join(unique_ips)}")
                # Add first recommendation for this rule
                rec = next((a["recommendation"] for a in high_alerts if a["rule_name"] == rule), "")
                if rec:
                    short_lines.append(f"  Action: {rec[:120]}")

            notify_all(
                cfg.notifications,
                f"[SO ALERT] HIGH - {high_alerts[0]['rule_name']}",
                "\n".join(alert_lines),
                short="\n".join(short_lines),
            )
            print("  Notification sent — check your phone!")
        else:
            print("No HIGH alerts — no notification sent.")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock triage run (no Elasticsearch needed)")
    parser.add_argument("--dry-run", action="store_true", help="Skip LLM and notifications")
    args = parser.parse_args()

    cfg = load_config()
    run_mock_triage(cfg, dry_run=args.dry_run)
