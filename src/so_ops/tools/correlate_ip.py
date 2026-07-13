"""IP scrubbing helpers shared by correlate LLM passes."""

from __future__ import annotations


def collect_ips_from_entries(entries: list[dict]) -> set[str]:
    ips: set[str] = set()
    for e in entries:
        for field in ("source_ip", "dest_ip"):
            ip = e.get(field)
            if ip and ip != "?":
                ips.add(ip)
    return ips


def collect_ips_from_patterns(patterns: list[dict]) -> set[str]:
    ips: set[str] = set()
    for p in patterns:
        if p.get("pivot_ip"):
            ips.add(p["pivot_ip"])
        if p.get("peer_ip"):
            ips.add(p["peer_ip"])
        ips.update(p.get("dest_ips", []))
    return ips


def collect_ips_from_vuln_findings(findings: list[dict]) -> set[str]:
    ips: set[str] = set()
    for f in findings:
        for field in ("source_ip", "dest_ip", "matched_ip"):
            if f.get(field):
                ips.add(f[field])
    return ips


def build_ip_map(ips: set[str], internal_prefixes: list[str]) -> dict[str, str]:
    ip_map: dict[str, str] = {}
    int_n = ext_n = 0
    for ip in sorted(ips):
        if any(ip.startswith(px) for px in internal_prefixes):
            int_n += 1
            ip_map[ip] = f"INT-{int_n:03d}"
        else:
            ext_n += 1
            ip_map[ip] = f"EXT-{ext_n:03d}"
    return ip_map


def scrub_text(text: str, ip_map: dict[str, str]) -> str:
    for real, token in ip_map.items():
        text = text.replace(real, token)
    return text
