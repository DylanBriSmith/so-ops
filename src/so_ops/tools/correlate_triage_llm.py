"""Pass 4: LLM review of grouped HIGH/MEDIUM triage across the last two runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from so_ops.clients import make_llm_client
from so_ops.config import Config
from so_ops.tools.correlate_common import load_triage_entries, parse_alert_timestamp
from so_ops.tools.correlate_ip import (
    build_ip_map,
    collect_ips_from_entries,
    scrub_text,
)


@dataclass
class RunWindow:
    label: str
    start: datetime
    end: datetime


@dataclass
class TriageLlmResult:
    brief: str | None
    digest_high_count: int
    digest_medium_count: int
    digest_group_count: int
    notify_recommended: bool = False
    digest: list[dict] = field(default_factory=list)


def parse_triage_notify_recommendation(brief: str | None) -> bool:
    """Return True if the triage LLM brief recommends a Teams notification."""
    if not brief:
        return False
    for line in reversed(brief.strip().splitlines()):
        upper = line.strip().upper()
        if upper.startswith("NOTIFY_RECOMMENDATION:"):
            value = upper.split(":", 1)[1].strip()
            return value.startswith("YES")
    return False


def format_triage_digest_detail(digest: list[dict], max_groups: int = 20) -> str:
    """Format grouped digest rows with real IPs for Teams / report detail."""
    if not digest:
        return ""

    lines: list[str] = []
    shown = digest[:max_groups]
    for g in shown:
        t_first = str(g.get("time_first", ""))[:16]
        t_last = str(g.get("time_last", ""))[:16]
        lines.append(
            f"[{g.get('verdict', '?')}] {g.get('window', '?')}"
            f" | {g.get('alert_count', 0)} alerts"
            f" | {t_first} - {t_last}"
        )
        lines.append(
            f"  {g.get('source_ip', '?')} -> {g.get('dest_ip', '?')}:{g.get('dest_port', '?')}"
        )
        org = g.get("source_org") or ""
        loc = g.get("source_location") or ""
        if org or loc:
            org_bits = [b for b in (org, loc) if b]
            lines.append(f"  Org: {' / '.join(org_bits)}")
        rule = g.get("rule_name", "")
        if rule:
            lines.append(f"  Rule: {rule}")
        reason = g.get("reason", "")
        if reason:
            lines.append(f"  Reason: {reason}")
        lines.append("")

    remaining = len(digest) - len(shown)
    if remaining > 0:
        lines.append(f"...({remaining} more groups)")

    return "\n".join(lines).strip()


def _parse_summary_timestamp(path: Path) -> datetime:
    """Parse dryrun_YYYYMMDD_HHMMSS.md filename."""
    parts = path.stem.split("_", 1)
    if len(parts) < 2:
        raise ValueError(f"unexpected summary filename: {path.name}")
    return datetime.strptime(parts[1], "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)


def load_last_n_run_windows(summary_dir: Path, n: int = 2) -> list[RunWindow]:
    """Build T-1 / T-0 windows from the newest n dry-run summary files."""
    summaries = sorted(summary_dir.glob("dryrun_*.md"), key=lambda p: p.name)
    if not summaries:
        return []

    now = datetime.now(timezone.utc)
    picked = summaries[-n:]
    timestamps = [_parse_summary_timestamp(p) for p in picked]

    if len(picked) == 1:
        t_curr = timestamps[0]
        return [RunWindow(label="T-0", start=t_curr, end=now)]

    t_prev, t_curr = timestamps[0], timestamps[1]
    return [
        RunWindow(label="T-1", start=t_prev, end=t_curr),
        RunWindow(label="T-0", start=t_curr, end=now),
    ]


def assign_window(alert_ts: datetime, windows: list[RunWindow]) -> str | None:
    for w in windows:
        if w.label == windows[-1].label:
            if alert_ts >= w.start:
                return w.label
        elif w.start <= alert_ts < w.end:
            return w.label
    return None


def _group_key(entry: dict, window_label: str) -> tuple:
    return (
        window_label,
        entry.get("rule_name", ""),
        entry.get("source_ip", "?"),
        entry.get("dest_ip", "?"),
        str(entry.get("dest_port", "?")),
        entry.get("verdict", "?"),
    )


def build_grouped_digest(
    entries: list[dict],
    windows: list[RunWindow],
) -> list[dict]:
    """Deduped entries → grouped HIGH/MEDIUM rows per window."""
    groups: dict[tuple, dict] = {}

    for e in entries:
        verdict = e.get("verdict", "")
        if verdict not in ("HIGH", "MEDIUM"):
            continue

        ts = parse_alert_timestamp(e.get("alert_timestamp", ""))
        if ts is None:
            continue
        window_label = assign_window(ts, windows)
        if window_label is None:
            continue

        key = _group_key(e, window_label)
        g = groups.get(key)
        if g is None:
            groups[key] = {
                "window": window_label,
                "rule_name": e.get("rule_name", ""),
                "source_ip": e.get("source_ip", "?"),
                "dest_ip": e.get("dest_ip", "?"),
                "dest_port": e.get("dest_port", "?"),
                "verdict": verdict,
                "reason": e.get("reason", ""),
                "source_org": e.get("source_org", "") or "",
                "source_location": e.get("source_location", "") or "",
                "alert_count": 1,
                "time_first": e.get("alert_timestamp", ""),
                "time_last": e.get("alert_timestamp", ""),
                "community_ids": [e["community_id"]] if e.get("community_id") else [],
            }
            continue

        g["alert_count"] += 1
        if not g.get("source_org") and e.get("source_org"):
            g["source_org"] = e["source_org"]
        if not g.get("source_location") and e.get("source_location"):
            g["source_location"] = e["source_location"]
        ats = e.get("alert_timestamp", "")
        if ats and ats < g["time_first"]:
            g["time_first"] = ats
        if ats and ats > g["time_last"]:
            g["time_last"] = ats
        cid = e.get("community_id")
        if cid and cid not in g["community_ids"] and len(g["community_ids"]) < 3:
            g["community_ids"].append(cid)

    return sorted(
        groups.values(),
        key=lambda g: (
            g["window"],
            {"HIGH": 0, "MEDIUM": 1}.get(g["verdict"], 2),
            -g["alert_count"],
        ),
    )


def summarize_triage_with_llm(
    digest: list[dict],
    ip_map: dict[str, str],
    cfg: Config,
    log,
) -> str | None:
    if not digest:
        return None

    lines = [
        "You are a Security Operations Center analyst reviewing automated alert triage output.",
        "Below are grouped HIGH and MEDIUM alerts from two consecutive 15-minute triage windows.",
        "Window T-1 is the previous scheduled run; T-0 is the current run. IPs are scrubbed",
        "(INT-### / EXT-###). Prefer depth and analyst usefulness over brevity — no fluff.",
        "",
        "Formatting: plain text only. Do not use markdown headers (## or ###) or a title —",
        "this is rendered in a chat card, not a document. Use the numbered labels below as",
        "plain bold text (e.g. **1. What happened**), not headers.",
        "",
        "Write a structured brief with these sections:",
        "",
        "1. What happened",
        "   3–6 sentences on the main activity: who → whom, ports, rules, and volumes.",
        "   Explicitly compare T-1 vs T-0 (new activity, continuing, escalating, or quiet).",
        "",
        "2. Notable hosts",
        "   Call out the most important scrubbed IPs and why they matter (repeat across",
        "   windows, many targets, attack-category rules, high alert counts).",
        "   Use source org/location when present (e.g. Fastly, Cloudflare, ISP names) to",
        "   judge CDN vs hostile hosting.",
        "",
        "3. Likely false positives",
        "   Call out expected noise: VoIP/SIP, LDAP binds, SNMP/monitoring,",
        "   ET INFO TLS Handshake Failure, and reputation/blocklist hits (CINS, Dshield,",
        "   etc.) especially on HTTPS port 443.",
        "   Major cloud/CDN orgs (Microsoft, Amazon, Google, Fastly, Cloudflare, Akamai,",
        "   Azure, AWS, etc.) are usually benign when volume is low — say so explicitly.",
        "   Say 'None apparent' only if that is truly the case.",
        "",
        "4. What an analyst should do next",
        "   2–4 concrete steps (e.g. SO Hunt by community_id / 5-tuple, verify host role,",
        "   check firewall blocks, compare to baseline). If you recommend NO notify,",
        "   still give 1–2 optional checks, not an urgent playbook.",
        "",
        "5. Overall risk — one line ending with: LOW / MEDIUM / HIGH / CRITICAL",
        "",
        "6. Notify — end with exactly one line:",
        "   NOTIFY_RECOMMENDATION: YES",
        "   or",
        "   NOTIFY_RECOMMENDATION: NO",
        "   Default to NO for low-volume cloud/CDN traffic, TLS handshake failures,",
        "   and reputation-only alerts on web ports (443/80).",
        "   Say YES when there is a flood worth human attention: many distinct external",
        "   IPs (even from Microsoft/CDN), high alert counts, many internal targets,",
        "   attack/exploit/scan rules (not INFO), or clear escalation across T-1→T-0.",
        "   A handful of Microsoft/CDN or reputation hits on 443 alone is NOT enough.",
        "",
        "Do not invent IPs or rules not present in the groups. Do not repeat rule-pattern",
        "correlation engine output — this is independent triage analysis.",
        "",
        "--- TRIAGE GROUPS ---",
        "",
    ]

    for i, g in enumerate(digest, 1):
        src = scrub_text(str(g["source_ip"]), ip_map)
        dst = scrub_text(str(g["dest_ip"]), ip_map)
        lines.append(f"[G{i}] {g['window']} | {g['verdict']} | {g['rule_name'][:80]}")
        lines.append(
            f"  {src} -> {dst}:{g['dest_port']} | count={g['alert_count']}"
            f" | {g['time_first'][:16]} to {g['time_last'][:16]}"
        )
        org = g.get("source_org") or ""
        loc = g.get("source_location") or ""
        if org or loc:
            org_bits = [b for b in (org, loc) if b]
            lines.append(f"  Org: {' / '.join(org_bits)}")
        if g.get("reason"):
            lines.append(f"  Reason: {scrub_text(g['reason'], ip_map)}")
        if g.get("community_ids"):
            lines.append(f"  community_id sample: {', '.join(g['community_ids'][:3])}")
        lines.append("")

    prompt = "\n".join(lines)
    log.info("Triage LLM: sending %d groups (%d chars)", len(digest), len(prompt))

    try:
        llm = make_llm_client(cfg)
        brief = llm.generate(prompt, temperature=0.3)
        log.info("Triage LLM: received %d chars", len(brief))
        return brief
    except Exception as exc:
        log.warning("Triage LLM failed (%s) — report will proceed without it", exc)
        return None


def run_triage_llm_review(
    triage_jsonl: Path,
    cfg: Config,
    log,
    summary_dir: Path,
    n_runs: int = 2,
) -> TriageLlmResult:
    """Pass 4: group HIGH/MEDIUM triage from the last n dry-runs and call LLM."""
    empty = TriageLlmResult(None, 0, 0, 0, False, [])
    windows = load_last_n_run_windows(summary_dir, n=n_runs)
    if not windows:
        log.info("Triage LLM: no dryrun summaries found — skipping")
        return empty

    llm_cutoff = windows[0].start
    log.info(
        "Triage LLM: loading last %d run(s) from %s (since %s)",
        len(windows),
        triage_jsonl.name,
        llm_cutoff.strftime("%Y-%m-%d %H:%M UTC"),
    )
    if not triage_jsonl.exists():
        log.warning("Triage LLM: no triage log at %s — skipping", triage_jsonl)
        return empty

    entries, load_stats = load_triage_entries(triage_jsonl, llm_cutoff)
    log.info(
        "Triage LLM load: %d in run window(s), %d skipped (outside), "
        "%d skipped (noise), %d skipped (invalid)",
        load_stats["in_window"],
        load_stats["skipped_old"],
        load_stats["skipped_noise"],
        load_stats["skipped_invalid"],
    )

    digest = build_grouped_digest(entries, windows)
    high_n = sum(1 for g in digest if g["verdict"] == "HIGH")
    med_n = sum(1 for g in digest if g["verdict"] == "MEDIUM")
    log.info(
        "Triage LLM: %d groups (%d HIGH, %d MEDIUM) across %d window(s)",
        len(digest),
        high_n,
        med_n,
        len(windows),
    )

    if not digest:
        log.info("Triage LLM: no HIGH/MEDIUM groups in window — skipping")
        return empty

    scrub = getattr(getattr(cfg, "triage", None), "scrub_ips", True)
    all_ips = collect_ips_from_entries(
        [{"source_ip": g["source_ip"], "dest_ip": g["dest_ip"]} for g in digest]
    )
    ip_map = build_ip_map(all_ips, cfg.network.internal_prefixes) if scrub else {}

    brief = summarize_triage_with_llm(digest, ip_map, cfg, log)
    notify = parse_triage_notify_recommendation(brief)
    if brief:
        log.info("Triage LLM notify recommendation: %s", "YES" if notify else "NO")
    return TriageLlmResult(brief, high_n, med_n, len(digest), notify, digest)
