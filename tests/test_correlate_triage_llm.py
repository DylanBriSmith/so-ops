"""Tests for correlate triage LLM helpers (no live LLM calls)."""

from datetime import datetime, timezone

from so_ops.tools.correlate_common import load_triage_entries
from so_ops.tools.correlate_ip import build_ip_map, scrub_text
from so_ops.tools.correlate_triage_llm import (
    RunWindow,
    assign_window,
    build_grouped_digest,
    format_triage_digest_detail,
    load_last_n_run_windows,
    parse_triage_notify_recommendation,
)


def _entry(
    alert_id: str,
    verdict: str,
    ts: str,
    rule: str = "ET SCAN Test",
    src: str = "10.0.0.1",
    dst: str = "192.168.1.10",
    port: int = 445,
    triaged_at: str = "2026-07-10T14:00:00+00:00",
) -> dict:
    return {
        "alert_id": alert_id,
        "alert_timestamp": ts,
        "triaged_at": triaged_at,
        "verdict": verdict,
        "rule_name": rule,
        "source_ip": src,
        "dest_ip": dst,
        "dest_port": port,
        "reason": "test",
        "community_id": f"cid-{alert_id}",
    }


def test_load_triage_entries_dedupes_by_alert_id(tmp_path):
    log = tmp_path / "triage.jsonl"
    log.write_text(
        "\n".join(
            [
                '{"alert_id":"a1","alert_timestamp":"2026-07-10T14:05:00+00:00",'
                '"triaged_at":"2026-07-10T14:00:00+00:00","verdict":"MEDIUM",'
                '"rule_name":"R","source_ip":"1.1.1.1","dest_ip":"2.2.2.2","dest_port":80}',
                '{"alert_id":"a1","alert_timestamp":"2026-07-10T14:05:00+00:00",'
                '"triaged_at":"2026-07-10T14:15:00+00:00","verdict":"MEDIUM",'
                '"rule_name":"R","source_ip":"1.1.1.1","dest_ip":"2.2.2.2","dest_port":80}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cutoff = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)
    entries, stats = load_triage_entries(log, cutoff)
    assert len(entries) == 1
    assert entries[0]["triaged_at"] == "2026-07-10T14:15:00+00:00"
    assert stats["in_window"] == 1


def test_load_triage_entries_skips_audit_and_noise(tmp_path):
    log = tmp_path / "triage.jsonl"
    log.write_text(
        "\n".join(
            [
                '{"ts":"2026-07-10T14:00:00+00:00","level":"INFO","msg":"starting"}',
                '{"alert_id":"n1","alert_timestamp":"2026-07-10T14:05:00+00:00",'
                '"verdict":"NOISE","rule_name":"R","source_ip":"1.1.1.1","dest_ip":"2.2.2.2","dest_port":80}',
                '{"alert_id":"a2","alert_timestamp":"2026-07-10T14:05:00+00:00",'
                '"verdict":"HIGH","rule_name":"R","source_ip":"1.1.1.1","dest_ip":"2.2.2.2","dest_port":80}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cutoff = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)
    entries, stats = load_triage_entries(log, cutoff)
    assert len(entries) == 1
    assert entries[0]["alert_id"] == "a2"
    assert stats["skipped_noise"] == 1
    assert stats["skipped_invalid"] == 1


def test_build_grouped_digest_groups_identical_rows():
    windows = [
        RunWindow(
            label="T-0",
            start=datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc),
            end=datetime(2026, 7, 10, 14, 30, tzinfo=timezone.utc),
        )
    ]
    entries = [
        _entry("1", "MEDIUM", "2026-07-10T14:05:00+00:00"),
        _entry("2", "MEDIUM", "2026-07-10T14:06:00+00:00"),
        _entry("3", "MEDIUM", "2026-07-10T14:07:00+00:00", port=443),
    ]
    digest = build_grouped_digest(entries, windows)
    assert len(digest) == 2
    group_445 = next(g for g in digest if g["dest_port"] == 445)
    assert group_445["alert_count"] == 2


def test_build_grouped_digest_separates_windows():
    windows = [
        RunWindow(
            label="T-1",
            start=datetime(2026, 7, 10, 13, 45, tzinfo=timezone.utc),
            end=datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc),
        ),
        RunWindow(
            label="T-0",
            start=datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc),
            end=datetime(2026, 7, 10, 14, 15, tzinfo=timezone.utc),
        ),
    ]
    entries = [
        _entry("1", "HIGH", "2026-07-10T13:50:00+00:00"),
        _entry("2", "HIGH", "2026-07-10T14:05:00+00:00"),
    ]
    digest = build_grouped_digest(entries, windows)
    labels = {g["window"] for g in digest}
    assert labels == {"T-1", "T-0"}


def test_assign_window_last_window_includes_end_boundary():
    windows = [
        RunWindow(
            label="T-1",
            start=datetime(2026, 7, 10, 13, 45, tzinfo=timezone.utc),
            end=datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc),
        ),
        RunWindow(
            label="T-0",
            start=datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc),
            end=datetime(2026, 7, 10, 14, 15, tzinfo=timezone.utc),
        ),
    ]
    ts = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)
    assert assign_window(ts, windows) == "T-0"


def test_load_last_n_run_windows_from_summaries(tmp_path):
    summary_dir = tmp_path / "summaries"
    summary_dir.mkdir()
    (summary_dir / "dryrun_20260710_140000.md").write_text("# dry run", encoding="utf-8")
    (summary_dir / "dryrun_20260710_141500.md").write_text("# dry run", encoding="utf-8")
    windows = load_last_n_run_windows(summary_dir, n=2)
    assert len(windows) == 2
    assert windows[0].label == "T-1"
    assert windows[1].label == "T-0"


def test_parse_triage_notify_recommendation():
    assert parse_triage_notify_recommendation("Summary\nNOTIFY_RECOMMENDATION: YES") is True
    assert parse_triage_notify_recommendation("Summary\nNOTIFY_RECOMMENDATION: NO") is False
    assert parse_triage_notify_recommendation(None) is False
    assert parse_triage_notify_recommendation("no notify line here") is False


def test_format_triage_digest_detail_includes_real_ips_and_fields():
    digest = [
        {
            "window": "T-0",
            "verdict": "MEDIUM",
            "alert_count": 12,
            "time_first": "2026-07-14T12:01:00+00:00",
            "time_last": "2026-07-14T12:08:00+00:00",
            "source_ip": "94.26.105.226",
            "dest_ip": "192.168.1.10",
            "dest_port": 443,
            "rule_name": "ET SCAN MS Terminal Server Traffic on Non-standard Port",
            "reason": "external scan activity",
        }
    ]
    text = format_triage_digest_detail(digest)
    assert "[MEDIUM] T-0 | 12 alerts |" in text
    assert "94.26.105.226 -> 192.168.1.10:443" in text
    assert "Rule: ET SCAN MS Terminal Server Traffic on Non-standard Port" in text
    assert "Reason: external scan activity" in text


def test_format_triage_digest_detail_truncates():
    digest = [
        {
            "window": "T-0",
            "verdict": "MEDIUM",
            "alert_count": i,
            "time_first": "2026-07-14T12:00:00+00:00",
            "time_last": "2026-07-14T12:01:00+00:00",
            "source_ip": f"10.0.0.{i}",
            "dest_ip": "192.168.1.10",
            "dest_port": 443,
            "rule_name": "ET SCAN Test",
            "reason": "test",
        }
        for i in range(1, 26)
    ]
    text = format_triage_digest_detail(digest, max_groups=20)
    assert "...(5 more groups)" in text
    assert "10.0.0.1 ->" in text
    assert "10.0.0.20 ->" in text
    assert "10.0.0.21 ->" not in text


def test_build_ip_map_and_scrub():
    ip_map = build_ip_map({"192.168.1.10", "8.8.8.8"}, ["192.168."])
    assert "192.168.1.10" in ip_map
    assert ip_map["192.168.1.10"].startswith("INT-")
    assert ip_map["8.8.8.8"].startswith("EXT-")
    assert "INT-" in scrub_text("traffic 192.168.1.10 -> 8.8.8.8", ip_map)
