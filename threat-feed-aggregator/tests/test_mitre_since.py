"""
Tests for MITRE ATT&CK tagging and --since date filtering.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from aggregator.filter import parse_since, apply_since_filter
from aggregator.mitre import tag_mitre
from aggregator.models import FeedItem


# ── Helpers ───────────────────────────────────────────────────────────────────

def _item(title: str = "", summary: str = "", tags: list[str] | None = None,
          published: datetime | None = None) -> FeedItem:
    return FeedItem(
        source="test", title=title, summary=summary or "",
        url="https://example.com", published=published, tags=tags or [],
    )


_NOW = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ── parse_since ───────────────────────────────────────────────────────────────

def test_parse_since_yesterday():
    with patch("aggregator.filter.datetime") as mock_dt:
        mock_dt.now.return_value = _NOW
        result = parse_since("yesterday")
    assert result == _NOW - timedelta(days=1)


def test_parse_since_days():
    with patch("aggregator.filter.datetime") as mock_dt:
        mock_dt.now.return_value = _NOW
        result = parse_since("3d")
    assert result == _NOW - timedelta(days=3)


def test_parse_since_days_ago():
    with patch("aggregator.filter.datetime") as mock_dt:
        mock_dt.now.return_value = _NOW
        result = parse_since("7 days ago")
    assert result == _NOW - timedelta(days=7)


def test_parse_since_hours():
    with patch("aggregator.filter.datetime") as mock_dt:
        mock_dt.now.return_value = _NOW
        result = parse_since("24h")
    assert result == _NOW - timedelta(hours=24)


def test_parse_since_weeks():
    with patch("aggregator.filter.datetime") as mock_dt:
        mock_dt.now.return_value = _NOW
        result = parse_since("2w")
    assert result == _NOW - timedelta(weeks=2)


def test_parse_since_months():
    with patch("aggregator.filter.datetime") as mock_dt:
        mock_dt.now.return_value = _NOW
        result = parse_since("1m")
    assert result == _NOW - timedelta(days=30)


def test_parse_since_iso_date():
    result = parse_since("2024-01-14")
    assert result.year == 2024
    assert result.month == 1
    assert result.day == 14
    assert result.tzinfo is not None


def test_parse_since_iso_datetime():
    result = parse_since("2024-01-14T09:30:00")
    assert result.hour == 9
    assert result.minute == 30


def test_parse_since_invalid():
    with pytest.raises(Exception):
        parse_since("not a date at all !!!")


# ── apply_since_filter ────────────────────────────────────────────────────────

_CUTOFF = datetime(2024, 6, 10, tzinfo=timezone.utc)
_BEFORE = datetime(2024, 6, 5, tzinfo=timezone.utc)   # before cutoff → drop
_AFTER  = datetime(2024, 6, 12, tzinfo=timezone.utc)  # after cutoff → keep


def test_apply_since_keeps_items_after_cutoff():
    items = [_item(published=_AFTER), _item(published=_BEFORE)]
    result = apply_since_filter(items, _CUTOFF)
    assert len(result) == 1
    assert result[0].published == _AFTER


def test_apply_since_drops_items_before_cutoff():
    items = [_item(published=_BEFORE)]
    result = apply_since_filter(items, _CUTOFF)
    assert result == []


def test_apply_since_keeps_undated_by_default():
    items = [_item(published=None)]
    result = apply_since_filter(items, _CUTOFF)
    assert len(result) == 1


def test_apply_since_drops_undated_when_disabled():
    items = [_item(published=None)]
    result = apply_since_filter(items, _CUTOFF, include_undated=False)
    assert result == []


def test_apply_since_naive_datetime_treated_as_utc():
    naive_dt = datetime(2024, 6, 12)  # no tzinfo
    items = [_item(published=naive_dt)]
    result = apply_since_filter(items, _CUTOFF)
    assert len(result) == 1


# ── tag_mitre ─────────────────────────────────────────────────────────────────

def test_tag_mitre_ransomware():
    items = [_item(title="Ransomware group hits hospitals")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1486" in ids


def test_tag_mitre_phishing():
    items = [_item(title="Spear-phishing campaign targets executives")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1566" in ids


def test_tag_mitre_rce_exploit():
    items = [_item(title="Critical RCE in Apache", summary="Exploit public-facing application via HTTP")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1190" in ids


def test_tag_mitre_c2_cobalt_strike():
    items = [_item(title="Cobalt Strike beacon detected on corporate network")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1071" in ids


def test_tag_mitre_credential_dump():
    items = [_item(summary="Threat actor used mimikatz to dump LSASS credentials")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1003" in ids


def test_tag_mitre_inline_t_number():
    items = [_item(title="Advisory references T1059 and T1486 techniques")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1059" in ids
    assert "T1486" in ids


def test_tag_mitre_no_match_leaves_empty():
    items = [_item(title="Product update: performance improvements in v2.3")]
    tag_mitre(items)
    assert items[0].mitre_techniques == []


def test_tag_mitre_deduplicates():
    # "ransomware" + "encrypt files" both map to T1486; should appear once
    items = [_item(title="Ransomware encrypts files on victim systems")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert ids.count("T1486") == 1


def test_tag_mitre_multiple_techniques():
    items = [_item(title="Phishing leads to credential dumping and ransomware deployment")]
    tag_mitre(items)
    ids = [t.split()[0] for t in items[0].mitre_techniques]
    assert "T1566" in ids   # phishing
    assert "T1003" in ids   # credential dump
    assert "T1486" in ids   # ransomware


def test_tag_mitre_technique_format():
    items = [_item(title="Cobalt Strike C2 beacon observed")]
    tag_mitre(items)
    # Each entry should start with a T-number
    for tech in items[0].mitre_techniques:
        parts = tech.split()
        assert parts[0].startswith("T")
