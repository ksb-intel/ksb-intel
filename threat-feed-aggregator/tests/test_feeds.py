"""
Unit tests for feed fetchers using mocked HTTP responses.
Run with:  python -m pytest tests/ -v
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from aggregator.feeds import (
    fetch_urlhaus,
    fetch_malware_bazaar,
    fetch_threatfox,
    fetch_cisa_kev,
    fetch_rss,
    _parse_rss_xml,
)
from aggregator.filter import apply_keywords, escalate_severity, sort_items
from aggregator.models import FeedItem


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_response(json_data=None, text_data=None, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.raise_for_status = MagicMock()
    if json_data is not None:
        resp.json = MagicMock(return_value=json_data)
    if text_data is not None:
        resp.text = text_data
    return resp


# ── abuse.ch URLhaus ──────────────────────────────────────────────────────────

_URLHAUS_PAYLOAD = {
    "query_status": "ok",
    "urls": [
        {
            "url": "http://evil.example.com/payload.exe",
            "url_status": "online",
            "host": "evil.example.com",
            "threat": "malware_download",
            "reporter": "testbot",
            "date_added": "2024-01-15 12:00:00 UTC",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
            "tags": ["Emotet", "macro"],
        }
    ],
}


def test_fetch_urlhaus_parses_correctly():
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.post.return_value = _mock_response(json_data=_URLHAUS_PAYLOAD)
        items = fetch_urlhaus(limit=5)

    assert len(items) == 1
    item = items[0]
    assert item.source == "abuse.ch URLhaus"
    assert "malware_download" in item.title
    assert item.ioc == "http://evil.example.com/payload.exe"
    assert item.severity == "high"
    assert "Emotet" in item.tags
    assert item.published is not None


def test_fetch_urlhaus_empty_on_network_error():
    import requests as _requests
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.post.side_effect = _requests.RequestException("network error")
        items = fetch_urlhaus()
    assert items == []


# ── MalwareBazaar ─────────────────────────────────────────────────────────────

_BAZAAR_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "abcdef1234567890" * 4,
            "file_type": "exe",
            "signature": "AgentTesla",
            "imphash": "deadbeef",
            "reporter": "shadowserver",
            "first_seen": "2024-01-15 10:00:00",
            "tags": ["stealer"],
        }
    ],
}


def test_fetch_malware_bazaar_parses_correctly():
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.post.return_value = _mock_response(json_data=_BAZAAR_PAYLOAD)
        items = fetch_malware_bazaar(limit=5)

    assert len(items) == 1
    item = items[0]
    assert item.source == "abuse.ch MalwareBazaar"
    assert "AgentTesla" in item.summary
    assert item.severity == "high"
    assert item.ioc is not None and len(item.ioc) > 10


# ── ThreatFox ─────────────────────────────────────────────────────────────────

_THREATFOX_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "id": "99",
            "ioc_value": "192.0.2.1:4444",
            "ioc_type": "ip:port",
            "malware": "win.cobalt_strike",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 95,
            "first_seen": "2024-01-15 09:00:00 UTC",
            "reporter": "threatresearcher",
            "tags": ["C2"],
        }
    ],
}


def test_fetch_threatfox_parses_correctly():
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.post.return_value = _mock_response(json_data=_THREATFOX_PAYLOAD)
        items = fetch_threatfox(limit=5)

    assert len(items) == 1
    item = items[0]
    assert item.source == "abuse.ch ThreatFox"
    assert "Cobalt Strike" in item.title
    assert item.severity == "critical"   # confidence 95 >= 90
    assert item.ioc == "192.0.2.1:4444"


def test_fetch_threatfox_high_severity_at_70():
    payload = dict(_THREATFOX_PAYLOAD)
    payload["data"] = [dict(_THREATFOX_PAYLOAD["data"][0], confidence_level=75)]
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.post.return_value = _mock_response(json_data=payload)
        items = fetch_threatfox()
    assert items[0].severity == "high"


# ── CISA KEV ─────────────────────────────────────────────────────────────────

_KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1234",
            "vulnerabilityName": "SuperApp RCE",
            "dateAdded": "2024-01-14",
            "dueDate": "2024-02-04",
            "vendorProject": "Acme",
            "product": "SuperApp",
            "shortDescription": "Remote code execution in SuperApp allows unauthenticated RCE.",
        },
        {
            # older than 14 days back from 2024-01-15 → should be filtered
            "cveID": "CVE-2023-0001",
            "vulnerabilityName": "Old Vuln",
            "dateAdded": "2023-06-01",
            "dueDate": "2023-06-22",
            "vendorProject": "Legacy Corp",
            "product": "OldApp",
            "shortDescription": "Old vulnerability.",
        },
    ]
}


def test_fetch_cisa_kev_filters_old_entries():
    # Pin "now" to 2024-01-20 so 2024-01-14 is within 14 days but 2023-06-01 is not
    fixed_now = datetime(2024, 1, 20, tzinfo=timezone.utc)
    with patch("aggregator.feeds._SESSION") as mock_sess, \
         patch("aggregator.feeds._now_utc", return_value=fixed_now):
        mock_sess.get.return_value = _mock_response(json_data=_KEV_PAYLOAD)
        items = fetch_cisa_kev(days_back=14)

    cve_ids = [i.ioc for i in items]
    assert "CVE-2024-1234" in cve_ids
    assert "CVE-2023-0001" not in cve_ids


def test_fetch_cisa_kev_severity_is_critical():
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.get.return_value = _mock_response(json_data=_KEV_PAYLOAD)
        items = fetch_cisa_kev(days_back=365 * 10)  # fetch everything

    for item in items:
        assert item.severity == "critical"


# ── RSS XML parser ────────────────────────────────────────────────────────────

_RSS2_XML = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>Ransomware hits hospitals</title>
      <link>https://example.com/article/1</link>
      <description>A new ransomware campaign targeted three hospitals.</description>
      <pubDate>Mon, 15 Jan 2024 10:00:00 +0000</pubDate>
      <category>ransomware</category>
    </item>
    <item>
      <title>Phishing wave detected</title>
      <link>https://example.com/article/2</link>
      <description>Credential-harvesting phishing emails targeting finance sector.</description>
      <pubDate>Mon, 15 Jan 2024 09:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>"""

_ATOM_XML = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Test</title>
  <entry>
    <title>Zero-day in Browser Engine</title>
    <link href="https://example.com/vuln/zero-day"/>
    <summary>A zero-day vulnerability was found in a major browser engine.</summary>
    <published>2024-01-15T11:00:00Z</published>
    <category term="zero-day"/>
  </entry>
</feed>"""


def test_parse_rss2():
    items = _parse_rss_xml(_RSS2_XML, "TestFeed", "https://example.com", 10)
    assert len(items) == 2
    assert items[0].title == "Ransomware hits hospitals"
    assert items[0].url == "https://example.com/article/1"
    assert "ransomware" in items[0].tags
    assert items[0].published is not None
    assert items[0].source == "TestFeed"


def test_parse_atom():
    items = _parse_rss_xml(_ATOM_XML, "AtomFeed", "https://example.com", 10)
    assert len(items) == 1
    assert "Zero-day" in items[0].title
    assert items[0].url == "https://example.com/vuln/zero-day"
    assert "zero-day" in items[0].tags


def test_parse_rss_max_items():
    items = _parse_rss_xml(_RSS2_XML, "TestFeed", "https://example.com", 1)
    assert len(items) == 1


def test_parse_rss_invalid_xml():
    items = _parse_rss_xml("<not valid xml <<<", "Bad", "https://x.com", 10)
    assert items == []


def test_fetch_rss_calls_get():
    with patch("aggregator.feeds._SESSION") as mock_sess:
        mock_sess.get.return_value = _mock_response(text_data=_RSS2_XML)
        items = fetch_rss("TestFeed", "https://example.com/feed", 10)
    assert len(items) == 2


# ── Keyword filtering ─────────────────────────────────────────────────────────

def _make_item(title: str, summary: str = "", severity: str = "info") -> FeedItem:
    return FeedItem(
        source="test", title=title, summary=summary,
        url="https://example.com", published=None, severity=severity,
    )


def test_apply_keywords_matches():
    items = [
        _make_item("Ransomware attack on hospital"),
        _make_item("Normal software update released"),
        _make_item("Critical RCE in Apache"),
    ]
    result = apply_keywords(items, ["ransomware", "RCE", "critical"])
    matched = [i for i in result if i.matched_keywords]
    assert len(matched) == 2
    assert "ransomware" in matched[0].matched_keywords or "ransomware" in matched[1].matched_keywords


def test_apply_keywords_strict_drops_non_matches():
    items = [
        _make_item("Ransomware hits schools"),
        _make_item("Weather forecast for tomorrow"),
    ]
    result = apply_keywords(items, ["ransomware"], strict=True)
    assert len(result) == 1
    assert result[0].title.startswith("Ransomware")


def test_apply_keywords_case_insensitive():
    items = [_make_item("RANSOMWARE campaign detected")]
    result = apply_keywords(items, ["ransomware"])
    assert result[0].matched_keywords == ["ransomware"]


def test_escalate_severity_zero_day():
    items = [_make_item("Zero-day exploit found in kernel", severity="info")]
    escalate_severity(items)
    assert items[0].severity == "critical"


def test_escalate_severity_rce():
    items = [_make_item("Remote code execution in OpenSSL", severity="medium")]
    escalate_severity(items)
    assert items[0].severity == "critical"


def test_escalate_severity_no_downgrade():
    # Already critical → stays critical even if only medium-level keyword found
    items = [_make_item("Ransomware campaign expanding", severity="critical")]
    escalate_severity(items)
    assert items[0].severity == "critical"


def test_sort_items_by_keyword_then_severity():
    low_match = _make_item("Ransomware detected", severity="low")
    high_no_match = _make_item("Critical patch released", severity="critical")
    apply_keywords([low_match, high_no_match], ["ransomware"])

    sorted_items = sort_items([low_match, high_no_match])
    # low_match has keyword hit → should be first
    assert sorted_items[0] is low_match
