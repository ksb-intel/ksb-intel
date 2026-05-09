"""
Feed fetchers for each source type.
Each public function returns a list[FeedItem].
"""

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from .models import FeedItem

log = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "ksb-intel-threat-aggregator/1.0"})
_TIMEOUT = 15

# XML namespaces common in RSS/Atom
_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc":   "http://purl.org/dc/elements/1.1/",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(url: str, **kwargs) -> requests.Response | None:
    try:
        r = _SESSION.get(url, timeout=_TIMEOUT, **kwargs)
        r.raise_for_status()
        return r
    except requests.RequestException as exc:
        log.warning("GET %s failed: %s", url, exc)
        return None


def _post(url: str, json_body: dict) -> requests.Response | None:
    try:
        r = _SESSION.post(url, json=json_body, timeout=_TIMEOUT)
        r.raise_for_status()
        return r
    except requests.RequestException as exc:
        log.warning("POST %s failed: %s", url, exc)
        return None


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    from dateutil import parser as dtparser
    try:
        dt = dtparser.parse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


# ── RSS / Atom XML parser (stdlib) ────────────────────────────────────────────

def _parse_rss_xml(xml_text: str, source_name: str, feed_url: str, max_items: int) -> list[FeedItem]:
    """Parse RSS 2.0 or Atom 1.0 XML into FeedItem list."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.warning("XML parse error for %s: %s", source_name, exc)
        return []

    items: list[FeedItem] = []

    # ── RSS 2.0 ────────────────────────────────────────────────────────────────
    channel = root.find("channel")
    if channel is not None:
        for elem in list(channel.findall("item"))[:max_items]:
            title = elem.findtext("title", "").strip()
            link  = elem.findtext("link", feed_url).strip()
            desc  = _strip_html(elem.findtext("description", ""))[:200]
            pub_raw = elem.findtext("pubDate") or elem.findtext(f"dc:date", namespaces=_NS)
            published = None
            if pub_raw:
                try:
                    published = parsedate_to_datetime(pub_raw.strip())
                except Exception:
                    published = _parse_dt(pub_raw.strip())

            tags = [c.text for c in elem.findall("category") if c.text]
            items.append(FeedItem(
                source=source_name,
                title=title or "(no title)",
                summary=desc,
                url=link,
                published=published,
                tags=tags,
                severity="info",
            ))
        return items

    # ── Atom 1.0 ──────────────────────────────────────────────────────────────
    atom_ns = "http://www.w3.org/2005/Atom"
    entries = root.findall(f"{{{atom_ns}}}entry")
    if not entries:
        entries = root.findall("entry")  # without ns if already stripped

    for elem in entries[:max_items]:
        def _text(tag):
            node = elem.find(f"{{{atom_ns}}}{tag}")
            return (node.text or "").strip() if node is not None else ""

        title = _text("title")
        # link can be <link href="..."/> or <link>url</link>
        link_node = elem.find(f"{{{atom_ns}}}link")
        link = ""
        if link_node is not None:
            link = link_node.get("href", link_node.text or "")

        summary = _strip_html(_text("summary") or _text("content"))[:200]
        pub_raw = _text("published") or _text("updated")
        published = _parse_dt(pub_raw) if pub_raw else None

        tags = [t.get("term", "") for t in elem.findall(f"{{{atom_ns}}}category")]

        items.append(FeedItem(
            source=source_name,
            title=title or "(no title)",
            summary=summary,
            url=link or feed_url,
            published=published,
            tags=tags,
            severity="info",
        ))

    return items


def fetch_rss(name: str, url: str, max_items: int = 15) -> list[FeedItem]:
    """Fetch and parse any RSS 2.0 or Atom 1.0 feed."""
    resp = _get(url)
    if resp is None:
        return []
    return _parse_rss_xml(resp.text, name, url, max_items)


# ── abuse.ch ─────────────────────────────────────────────────────────────────

def fetch_urlhaus(limit: int = 20) -> list[FeedItem]:
    """Recent malicious URLs from URLhaus."""
    resp = _post("https://urlhaus-api.abuse.ch/v1/urls/recent/", {"limit": limit})
    if resp is None:
        return []
    data = resp.json()
    items: list[FeedItem] = []
    for entry in data.get("urls", []):
        tags = entry.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        threat = entry.get("threat", "malware_download")
        severity = "high" if "malware" in threat.lower() else "medium"
        items.append(FeedItem(
            source="abuse.ch URLhaus",
            title=f"{threat}: {entry.get('url', '')[:80]}",
            summary=(
                f"Host: {entry.get('host', 'unknown')} | "
                f"Status: {entry.get('url_status', '?')} | "
                f"Reporter: {entry.get('reporter', '?')}"
            ),
            url=entry.get("urlhaus_reference", "https://urlhaus.abuse.ch"),
            published=_parse_dt(entry.get("date_added")),
            tags=tags,
            severity=severity,
            ioc=entry.get("url"),
        ))
    return items


def fetch_malware_bazaar(limit: int = 20) -> list[FeedItem]:
    """Recent malware samples from MalwareBazaar."""
    resp = _post("https://mb-api.abuse.ch/api/v1/", {"query": "get_recent", "selector": "time"})
    if resp is None:
        return []
    data = resp.json()
    items: list[FeedItem] = []
    for entry in list(data.get("data", []))[:limit]:
        tags = entry.get("tags") or []
        file_type = entry.get("file_type", "unknown")
        items.append(FeedItem(
            source="abuse.ch MalwareBazaar",
            title=f"{file_type} sample: {entry.get('sha256_hash', '')[:16]}…",
            summary=(
                f"Family: {entry.get('signature', 'unknown')} | "
                f"Imphash: {entry.get('imphash', 'n/a')} | "
                f"Reporter: {entry.get('reporter', '?')}"
            ),
            url=f"https://bazaar.abuse.ch/sample/{entry.get('sha256_hash', '')}",
            published=_parse_dt(entry.get("first_seen")),
            tags=tags,
            severity="high",
            ioc=entry.get("sha256_hash"),
        ))
    return items


def fetch_threatfox(limit: int = 20) -> list[FeedItem]:
    """Recent IOCs from ThreatFox."""
    resp = _post("https://threatfox-api.abuse.ch/api/v1/", {"query": "get_iocs", "days": 3})
    if resp is None:
        return []
    data = resp.json()
    items: list[FeedItem] = []
    for entry in list(data.get("data", []))[:limit]:
        ioc_value = entry.get("ioc_value", "")
        malware_family = entry.get("malware_printable", entry.get("malware", "unknown"))
        confidence = entry.get("confidence_level", 0)
        severity = "critical" if confidence >= 90 else "high" if confidence >= 70 else "medium"
        items.append(FeedItem(
            source="abuse.ch ThreatFox",
            title=f"{malware_family} IOC ({entry.get('ioc_type', '?')}): {ioc_value[:60]}",
            summary=(
                f"Confidence: {confidence}% | "
                f"Tags: {', '.join(entry.get('tags') or []) or 'none'} | "
                f"Reporter: {entry.get('reporter', '?')}"
            ),
            url=f"https://threatfox.abuse.ch/ioc/{entry.get('id', '')}",
            published=_parse_dt(entry.get("first_seen")),
            tags=entry.get("tags") or [],
            severity=severity,
            ioc=ioc_value,
        ))
    return items


# ── CISA ──────────────────────────────────────────────────────────────────────

def fetch_cisa_kev(days_back: int = 14) -> list[FeedItem]:
    """CISA Known Exploited Vulnerabilities catalog (recent additions)."""
    resp = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if resp is None:
        return []
    data = resp.json()
    cutoff = _now_utc() - timedelta(days=days_back)
    items: list[FeedItem] = []
    for vuln in data.get("vulnerabilities", []):
        added = _parse_dt(vuln.get("dateAdded"))
        if added and added < cutoff:
            continue
        due = vuln.get("dueDate", "")
        product = vuln.get("product", "unknown product")
        vendor = vuln.get("vendorProject", "")
        cve_id = vuln.get("cveID", "")
        items.append(FeedItem(
            source="CISA KEV",
            title=f"{cve_id}: {vuln.get('vulnerabilityName', 'Unknown')}",
            summary=(
                f"{vendor} {product} | "
                f"Action due: {due} | "
                f"{vuln.get('shortDescription', '')[:120]}"
            ),
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            published=added,
            tags=[cve_id, "KEV", vendor],
            severity="critical",
            ioc=cve_id,
        ))
    items.sort(key=lambda x: x.published or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return items


def fetch_cisa_advisories() -> list[FeedItem]:
    """CISA cybersecurity advisories via RSS."""
    return fetch_rss(
        "CISA Advisories",
        "https://www.cisa.gov/cybersecurity-advisories/all-advisories.xml",
        max_items=20,
    )
