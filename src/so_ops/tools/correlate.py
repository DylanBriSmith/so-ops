"""Alert-vulnscan correlation: cross-reference triage results with scan findings, no LLM."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

# Prefer defusedxml to guard against malformed XML; fall back to stdlib.
# The nmap XML is always local output, but defence-in-depth is cheap.
try:
    import defusedxml.ElementTree as ET  # type: ignore[import]
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]
from pathlib import Path

from so_ops.config import Config
from so_ops.log import setup_logging
from so_ops.state import ToolState

# ── Match confidence tiers ────────────────────────────────────────────────────

MATCH_EXACT_CVE = "exact_cve"  # rule name contains CVE that vulnscan found on dest_ip
MATCH_NUCLEI_CVE = "nuclei_cve"  # nuclei confirmed same CVE / template on dest_ip
MATCH_SERVICE_KEYWORD = "service_keyword"  # rule mentions a product found open on dest_ip
MATCH_TARGETED_HOST = "targeted_host"  # exploit/attack rule aimed at a host with any known CVE

CONFIDENCE = {
    MATCH_EXACT_CVE: "high",
    MATCH_NUCLEI_CVE: "high",
    MATCH_SERVICE_KEYWORD: "medium",
    MATCH_TARGETED_HOST: "low",
}

# Map of product keywords (lower-case) to what to look for in Suricata rule names.
# Key = substring to search in nmap service product string.
# Value = list of substrings that would appear in a matching Suricata rule name.
_SERVICE_KEYWORDS: list[tuple[str, list[str]]] = [
    ("apache", ["Apache", "HTTP", "Log4j", "Tomcat", "Struts", "HTTP Server"]),
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
    ("phpmyadmin", ["phpMyAdmin", "PHP"]),
    ("samba", ["Samba", "SMB", "SAMBA"]),
    ("vnc", ["VNC"]),
    ("elasticsearch", ["Elasticsearch"]),
    ("redis", ["Redis"]),
    ("mongodb", ["MongoDB"]),
]

# Rule categories that indicate an active exploit or attack attempt
_EXPLOIT_CATEGORIES = frozenset(
    [
        "Attempted Administrator Privilege Gain",
        "Attempted User Privilege Gain",
        "Attempted Information Leak",
        "Web Application Attack",
        "Executable Code was Detected",
        "Potential Corporate Privacy Violation",
        "A Network Trojan was Detected",
        "Misc Attack",
    ]
)

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


# ── Vulnscan data loading ────────────────────────────────────────────────────


def _find_latest_file(directory: Path, glob: str) -> Path | None:
    """Return the most recently modified file matching the glob, or None."""
    matches = sorted(directory.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _load_nmap_index(xml_path: Path, log) -> dict[str, dict]:
    """Parse nmap XML into {ip: {cves, services, hostname}}."""
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
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

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
            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "") if service_elem is not None else ""
            product = ""
            if service_elem is not None:
                prod = service_elem.get("product", "")
                ver = service_elem.get("version", "")
                product = f"{prod} {ver}".strip()

            services.append(f"{port_id}/{protocol} {service_name} {product}".strip())

            for script_elem in port_elem.findall("script"):
                if script_elem.get("id") != "vulners":
                    continue
                output = script_elem.get("output", "")
                for line in output.split("\n"):
                    line = line.strip()
                    m = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.?\d*)", line)
                    if m:
                        cves.append(
                            {
                                "cve": m.group(1),
                                "cvss": float(m.group(2)),
                                "port": f"{port_id}/{protocol}",
                                "service": product or service_name,
                            }
                        )

        cves.sort(key=lambda v: v["cvss"], reverse=True)
        index[ip] = {"hostname": hostname, "cves": cves, "services": services}

    log.info("nmap index: %d hosts loaded from %s", len(index), xml_path.name)
    return index


def _load_nuclei_index(jsonl_path: Path, log) -> dict[str, list[dict]]:
    """Parse nuclei JSONL into {ip: [findings]}."""
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

        host_url = entry.get("host", "")
        # Extract bare IP from "https://1.2.3.4:443" etc.
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", host_url)
        if not m:
            continue
        ip = m.group(1)

        cve_ids = entry.get("info", {}).get("classification", {}).get("cve-id", []) or []
        finding = {
            "template_id": entry.get("template-id", ""),
            "name": entry.get("info", {}).get("name", ""),
            "severity": entry.get("info", {}).get("severity", ""),
            "matched_at": entry.get("matched-at", ""),
            "cve_ids": cve_ids,
        }
        index.setdefault(ip, []).append(finding)

    log.info("nuclei index: %d hosts with findings from %s", len(index), jsonl_path.name)
    return index


# ── CVE and service matching ─────────────────────────────────────────────────


def _cves_in_rule(rule_name: str) -> list[str]:
    """Extract CVE IDs mentioned in a Suricata rule name."""
    return re.findall(r"CVE-\d{4}-\d+", rule_name, re.IGNORECASE)


def _is_exploit_rule(rule_name: str, category: str = "") -> bool:
    """True if the rule looks like an active exploit/attack attempt."""
    if any(rule_name.startswith(p) for p in _EXPLOIT_RULE_PREFIXES):
        return True
    if category in _EXPLOIT_CATEGORIES:
        return True
    return False


def _service_keywords_match(rule_name: str, services: list[str]) -> list[str]:
    """Return matched service strings where rule mentions a product found on this host."""
    matches = []
    services_lower = " ".join(services).lower()
    rule_lower = rule_name.lower()
    for svc_key, rule_terms in _SERVICE_KEYWORDS:
        if svc_key not in services_lower:
            continue
        for term in rule_terms:
            if term.lower() in rule_lower:
                # Find the specific service entry that matched
                for svc in services:
                    if svc_key in svc.lower():
                        if svc not in matches:
                            matches.append(svc)
                        break
    return matches


def _recommend_verdict(match_type: str, current_verdict: str) -> str:
    """Recommend a new verdict based on match type; never lower than current."""
    order = {"NOISE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    upgrades = {
        MATCH_EXACT_CVE: "HIGH",
        MATCH_NUCLEI_CVE: "HIGH",
        MATCH_SERVICE_KEYWORD: "MEDIUM",
        MATCH_TARGETED_HOST: "MEDIUM",
    }
    target = upgrades.get(match_type, current_verdict)
    current_n = order.get(current_verdict, 1)
    target_n = order.get(target, 1)
    return target if target_n > current_n else current_verdict


# ── Core correlation ──────────────────────────────────────────────────────────


def _correlate(
    triage_entries: list[dict],
    nmap_index: dict[str, dict],
    nuclei_index: dict[str, list[dict]],
    log,
) -> list[dict]:
    """Return a list of correlation findings sorted by confidence (high first)."""
    findings: list[dict] = []

    for entry in triage_entries:
        dest_ip = entry.get("dest_ip", "")
        rule_name = entry.get("rule_name", "")
        verdict = entry.get("verdict", "LOW")

        if not dest_ip or dest_ip == "?":
            continue

        host_info = nmap_index.get(dest_ip)
        nuclei_findings = nuclei_index.get(dest_ip, [])

        if not host_info and not nuclei_findings:
            continue  # host not in any scan results — no correlation possible

        rule_cves = _cves_in_rule(rule_name)
        host_cves = {c["cve"].upper(): c for c in (host_info["cves"] if host_info else [])}
        host_services = host_info["services"] if host_info else []

        matched = False

        # Tier 1 — exact CVE match (rule names CVE that vulnscan found on this host)
        for cve in rule_cves:
            if cve.upper() in host_cves:
                scan_cve = host_cves[cve.upper()]
                reason = (
                    f"Rule references {cve} which vulnscan confirmed on "
                    f"{dest_ip}:{scan_cve['port']} ({scan_cve['service']}, "
                    f"CVSS {scan_cve['cvss']})"
                )
                findings.append(
                    _build_finding(
                        entry,
                        dest_ip,
                        host_info,
                        MATCH_EXACT_CVE,
                        verdict,
                        reason,
                        matched_cves=[cve],
                        scan_cve_detail=scan_cve,
                    )
                )
                matched = True
                log.info(
                    "  EXACT CVE: %s → %s on %s (CVSS %.1f)",
                    rule_name[:60],
                    cve,
                    dest_ip,
                    scan_cve["cvss"],
                )

        # Tier 2 — nuclei CVE match (nuclei confirmed a CVE also in the rule, or on same host)
        for nf in nuclei_findings:
            # Sub-tier 2a: nuclei's CVE IDs overlap with rule's CVE IDs
            overlap = set(cve.upper() for cve in rule_cves) & set(c.upper() for c in nf["cve_ids"])
            if overlap:
                reason = (
                    f"Rule references {', '.join(overlap)} and nuclei confirmed "
                    f"'{nf['name']}' at {nf['matched_at']} (severity: {nf['severity']})"
                )
                findings.append(
                    _build_finding(
                        entry,
                        dest_ip,
                        host_info,
                        MATCH_NUCLEI_CVE,
                        verdict,
                        reason,
                        matched_cves=list(overlap),
                        nuclei_finding=nf,
                    )
                )
                matched = True
                log.info("  NUCLEI CVE: %s → %s on %s", rule_name[:60], ", ".join(overlap), dest_ip)
                continue

            # Sub-tier 2b: nuclei hit on same host with a high/critical finding
            if (
                nf["severity"] in ("critical", "high")
                and not matched
                and _is_exploit_rule(rule_name)
            ):
                reason = (
                    f"Exploit rule fired against {dest_ip} where nuclei confirmed "
                    f"'{nf['name']}' ({nf['severity']}) at {nf['matched_at']}"
                )
                findings.append(
                    _build_finding(
                        entry,
                        dest_ip,
                        host_info,
                        MATCH_NUCLEI_CVE,
                        verdict,
                        reason,
                        nuclei_finding=nf,
                    )
                )
                matched = True
                log.info("  NUCLEI HOST: %s → %s on %s", rule_name[:60], nf["name"], dest_ip)

        # Tier 3 — service keyword match
        if not matched and host_services:
            svc_matches = _service_keywords_match(rule_name, host_services)
            if svc_matches:
                reason = (
                    f"Rule mentions product also found open on {dest_ip}: "
                    f"{', '.join(svc_matches[:3])}"
                )
                findings.append(
                    _build_finding(
                        entry,
                        dest_ip,
                        host_info,
                        MATCH_SERVICE_KEYWORD,
                        verdict,
                        reason,
                        matched_services=svc_matches,
                    )
                )
                matched = True
                log.info("  SERVICE: %s → %s on %s", rule_name[:60], svc_matches[0], dest_ip)

        # Tier 4 — host targeted (exploit rule vs any known-vulnerable host)
        if not matched and host_info and host_info["cves"] and _is_exploit_rule(rule_name):
            top_cve = host_info["cves"][0]
            reason = (
                f"Exploit/attack rule targeting {dest_ip}, which has "
                f"{len(host_info['cves'])} known CVEs (highest: {top_cve['cve']} "
                f"CVSS {top_cve['cvss']})"
            )
            findings.append(
                _build_finding(
                    entry,
                    dest_ip,
                    host_info,
                    MATCH_TARGETED_HOST,
                    verdict,
                    reason,
                )
            )
            log.info(
                "  TARGETED HOST: %s → %s (%d CVEs)",
                rule_name[:60],
                dest_ip,
                len(host_info["cves"]),
            )

    # Sort: high confidence first, then by recommended verdict severity descending
    order_conf = {"high": 0, "medium": 1, "low": 2}
    order_verd = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "NOISE": 3}
    findings.sort(
        key=lambda f: (
            order_conf.get(f["confidence"], 9),
            order_verd.get(f["recommended_verdict"], 9),
        )
    )

    return findings


def _build_finding(
    triage_entry: dict,
    dest_ip: str,
    host_info: dict | None,
    match_type: str,
    current_verdict: str,
    reason: str,
    matched_cves: list[str] | None = None,
    matched_services: list[str] | None = None,
    scan_cve_detail: dict | None = None,
    nuclei_finding: dict | None = None,
) -> dict:
    recommended = _recommend_verdict(match_type, current_verdict)
    return {
        "correlated_at": datetime.now(timezone.utc).isoformat(),
        "alert_id": triage_entry.get("alert_id", ""),
        "alert_timestamp": triage_entry.get("alert_timestamp", ""),
        "rule_name": triage_entry.get("rule_name", ""),
        "source_ip": triage_entry.get("source_ip", ""),
        "dest_ip": dest_ip,
        "dest_port": triage_entry.get("dest_port", ""),
        "triage_verdict": current_verdict,
        "triage_method": triage_entry.get("method", ""),
        "match_type": match_type,
        "confidence": CONFIDENCE[match_type],
        "recommended_verdict": recommended,
        "verdict_changed": recommended != current_verdict,
        "reason": reason,
        "matched_cves": matched_cves or [],
        "matched_services": matched_services or [],
        "scan_cve_detail": scan_cve_detail,
        "nuclei_finding": nuclei_finding,
        "host_hostname": host_info.get("hostname", "") if host_info else "",
        "host_cve_count": len(host_info["cves"]) if host_info else 0,
        "host_top_cvss": host_info["cves"][0]["cvss"] if host_info and host_info["cves"] else 0.0,
    }


# ── Report ───────────────────────────────────────────────────────────────────


def _build_report(
    findings: list[dict],
    triage_count: int,
    nmap_hosts: int,
    nuclei_hosts: int,
    lookback_hours: int,
    nmap_file: str,
    nuclei_file: str,
    run_time: str,
) -> str:
    high_conf = [f for f in findings if f["confidence"] == "high"]
    med_conf = [f for f in findings if f["confidence"] == "medium"]
    low_conf = [f for f in findings if f["confidence"] == "low"]
    verdict_changes = [f for f in findings if f["verdict_changed"]]

    lines = [
        "# Alert-Vulnscan Correlation Report",
        f"**Run:** {run_time}",
        f"**Triage alerts checked:** {triage_count} (last {lookback_hours}h)",
        f"**Vulnscan hosts:** {nmap_hosts} (nmap) / {nuclei_hosts} (nuclei)",
        f"**Nmap source:** {nmap_file}",
        f"**Nuclei source:** {nuclei_file}",
        "",
        "## Summary",
        f"- Total correlations found: **{len(findings)}**",
        f"  - High confidence: {len(high_conf)} (exact CVE or nuclei-confirmed match)",
        f"  - Medium confidence: {len(med_conf)} (service/product keyword match)",
        f"  - Low confidence: {len(low_conf)} (exploit rule targeting vulnerable host)",
        f"- Verdict upgrades recommended: **{len(verdict_changes)}**",
        "",
    ]

    if not findings:
        lines.append("No correlations found between triage alerts and scan results.")
        lines.append("")
        lines.append("This means either:")
        lines.append("  - No triage alerts targeted hosts found in the vulnerability scan")
        lines.append("  - The scan results and alert window do not overlap")
        lines.append("  - All alerts targeted external IPs not in the scan scope")
        return "\n".join(lines)

    if verdict_changes:
        lines.append("## Recommended Verdict Upgrades")
        lines.append("")
        for f in verdict_changes:
            lines.append(
                f"- **{f['rule_name'][:70]}**  "
                f"`{f['triage_verdict']} → {f['recommended_verdict']}`  "
                f"[{f['confidence']} confidence]"
            )
            lines.append(f"  - Target: `{f['dest_ip']}` | Match: `{f['match_type']}`")
            lines.append(f"  - {f['reason']}")
            lines.append("")

    if high_conf:
        lines.append("## High Confidence Correlations")
        lines.append("")
        for f in high_conf:
            hostname = f" ({f['host_hostname']})" if f["host_hostname"] else ""
            lines.append(f"### {f['rule_name'][:80]}")
            lines.append(
                f"- **Alert:** `{f['alert_timestamp']}` | {f['source_ip']} → {f['dest_ip']}{hostname}:{f['dest_port']}"
            )
            lines.append(
                f"- **Triage verdict:** {f['triage_verdict']} (method: {f['triage_method']})"
            )
            lines.append(f"- **Recommended:** {f['recommended_verdict']}")
            lines.append(f"- **Match:** {f['match_type']} — {f['reason']}")
            if f["matched_cves"]:
                lines.append(f"- **CVEs:** {', '.join(f['matched_cves'])}")
            if f["scan_cve_detail"]:
                d = f["scan_cve_detail"]
                lines.append(
                    f"- **Scan detail:** {d['cve']} CVSS {d['cvss']} on {f['dest_ip']}:{d['port']} ({d['service']})"
                )
            if f["nuclei_finding"]:
                nf = f["nuclei_finding"]
                lines.append(f"- **Nuclei:** {nf['name']} ({nf['severity']}) at {nf['matched_at']}")
            lines.append("")

    if med_conf:
        lines.append("## Medium Confidence Correlations")
        lines.append("")
        for f in med_conf:
            lines.append(
                f"- **{f['rule_name'][:70]}** → `{f['dest_ip']}` | "
                f"{f['triage_verdict']}→{f['recommended_verdict']} | {f['reason']}"
            )
        lines.append("")

    if low_conf:
        lines.append("## Low Confidence Correlations")
        lines.append("")
        for f in low_conf:
            lines.append(
                f"- **{f['rule_name'][:70]}** → `{f['dest_ip']}` ({f['host_cve_count']} CVEs, "
                f"top CVSS {f['host_top_cvss']}) | {f['triage_verdict']}"
            )
        lines.append("")

    return "\n".join(lines)


# ── Entry point ──────────────────────────────────────────────────────────────


def run_correlate(cfg: Config, lookback_hours: int = 48):
    """Cross-reference recent triage alerts with the latest vulnscan results."""
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
    log.info("Triage lookback: %dh", lookback_hours)

    # ── Load triage alerts ────────────────────────────────────────────
    triage_jsonl = log_dir / "triage_alerts.jsonl"
    triage_entries: list[dict] = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    if not triage_jsonl.exists():
        log.warning("No triage log found at %s — run 'so-ops triage' first", triage_jsonl)
        print(f"No triage log found. Run 'so-ops triage' first.\nExpected: {triage_jsonl}")
        state.finish_run(correlations=0)
        return

    total_triage = 0
    skipped_old = 0
    for line in triage_jsonl.read_text(encoding="utf-8").strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        total_triage += 1
        ts_str = entry.get("alert_timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts < cutoff:
                skipped_old += 1
                continue
        except (ValueError, TypeError):
            pass
        triage_entries.append(entry)

    log.info(
        "Triage log: %d total entries, %d within %dh lookback, %d older (skipped)",
        total_triage,
        len(triage_entries),
        lookback_hours,
        skipped_old,
    )

    if not triage_entries:
        log.warning("No triage alerts in the last %dh. Nothing to correlate.", lookback_hours)
        print(f"No triage alerts found in the last {lookback_hours}h.")
        state.finish_run(correlations=0)
        return

    # ── Load vulnscan results ─────────────────────────────────────────
    if not scan_dir.exists():
        log.warning("No vulnscan output directory found at %s — run 'so-ops scan' first", scan_dir)
        print(f"No scan results found. Run 'so-ops scan' first.\nExpected: {scan_dir}")
        state.finish_run(correlations=0)
        return

    nmap_xml = _find_latest_file(scan_dir, "nmap_*.xml")
    nuclei_jsonl = _find_latest_file(scan_dir, "nuclei_*.jsonl")

    nmap_index: dict[str, dict] = {}
    nuclei_index: dict[str, list[dict]] = {}

    if nmap_xml:
        log.info("Loading nmap results: %s", nmap_xml.name)
        nmap_index = _load_nmap_index(nmap_xml, log)
    else:
        log.warning("No nmap XML found in %s — only nuclei results will be used", scan_dir)

    if nuclei_jsonl:
        log.info("Loading nuclei results: %s", nuclei_jsonl.name)
        nuclei_index = _load_nuclei_index(nuclei_jsonl, log)
    else:
        log.info("No nuclei JSONL found in %s — skipping nuclei correlation", scan_dir)

    if not nmap_index and not nuclei_index:
        log.error("No scan data available. Run 'so-ops scan' first.")
        print("No scan data available. Run 'so-ops scan' first.")
        state.finish_run(correlations=0)
        return

    log.info(
        "Scan data: %d nmap hosts, %d nuclei hosts",
        len(nmap_index),
        len(nuclei_index),
    )

    # ── Correlate ─────────────────────────────────────────────────────
    log.info("=== Running correlation (%d triage alerts) ===", len(triage_entries))
    findings = _correlate(triage_entries, nmap_index, nuclei_index, log)
    log.info(
        "Correlation complete: %d findings (%d high, %d medium, %d low)",
        len(findings),
        sum(1 for f in findings if f["confidence"] == "high"),
        sum(1 for f in findings if f["confidence"] == "medium"),
        sum(1 for f in findings if f["confidence"] == "low"),
    )

    # ── Write JSONL findings log ──────────────────────────────────────
    findings_log = log_dir / "correlate_findings.jsonl"
    for finding in findings:
        with open(findings_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(finding) + "\n")
    log.info("Findings written to %s", findings_log)

    # ── Build and save report ─────────────────────────────────────────
    report = _build_report(
        findings,
        triage_count=len(triage_entries),
        nmap_hosts=len(nmap_index),
        nuclei_hosts=len(nuclei_index),
        lookback_hours=lookback_hours,
        nmap_file=nmap_xml.name if nmap_xml else "none",
        nuclei_file=nuclei_jsonl.name if nuclei_jsonl else "none",
        run_time=run_time,
    )
    report_path = correlate_dir / f"report_{timestamp}.md"
    report_path.write_text(report, encoding="utf-8")
    log.info("Report saved: %s", report_path)

    state.finish_run(correlations=len(findings))

    # ── Console output ────────────────────────────────────────────────
    high = [f for f in findings if f["confidence"] == "high"]
    med = [f for f in findings if f["confidence"] == "medium"]
    low = [f for f in findings if f["confidence"] == "low"]
    changes = [f for f in findings if f["verdict_changed"]]

    print("\n" + "=" * 60)
    print("CORRELATION COMPLETE")
    print("=" * 60)
    print(f"Triage alerts checked: {len(triage_entries)} (last {lookback_hours}h)")
    print(f"Scan hosts: {len(nmap_index)} nmap, {len(nuclei_index)} nuclei")
    print(
        f"Correlations: {len(findings)} total  ({len(high)} high / {len(med)} medium / {len(low)} low)"
    )
    print(f"Verdict upgrades recommended: {len(changes)}")

    if high:
        print("\nHIGH CONFIDENCE FINDINGS:")
        for f in high:
            print(f"  [{f['recommended_verdict']}] {f['rule_name'][:65]}")
            print(f"        → {f['dest_ip']} | {f['reason'][:80]}")

    if changes:
        print("\nRECOMMENDED UPGRADES:")
        for f in changes:
            print(
                f"  {f['triage_verdict']:6s} → {f['recommended_verdict']:6s}  {f['rule_name'][:55]}"
            )

    print(f"\nReport: {report_path}")
    print(f"Log:    {findings_log}")
