"""Pass 2: load vulnscan data and cross-reference with triage alerts."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    import defusedxml.ElementTree as ET  # type: ignore[import]
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]

from so_ops.tools.correlate_common import confidence_rank, is_exploit_rule, verdict_rank

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


def find_latest_file(directory: Path, glob: str) -> Path | None:
    matches = sorted(directory.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def load_nmap_index(xml_path: Path, log) -> dict[str, dict]:
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


def load_nuclei_index(jsonl_path: Path, log) -> dict[str, list[dict]]:
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
    return target if verdict_rank(target) > verdict_rank(current) else current


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
        if nf["severity"] in ("critical", "high") and not matched and is_exploit_rule(rule_name):
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

    if not matched and host_info and host_info["cves"] and is_exploit_rule(rule_name):
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


def correlate_vuln(
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

    findings.sort(
        key=lambda f: (
            confidence_rank(f["confidence"]),
            -verdict_rank(f["recommended_verdict"]),
        )
    )
    return findings
