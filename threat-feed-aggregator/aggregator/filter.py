"""Keyword filtering, date filtering, and severity scoring."""

import re
from datetime import datetime, timezone, timedelta
from .models import FeedItem

# ── --since parsing ───────────────────────────────────────────────────────────
# Supports: "2d", "3 days", "1w", "2 weeks", "24h", "yesterday",
#           "2 days ago", ISO dates "2024-01-14", "2024-01-14T12:00"
_RELATIVE_RE = re.compile(
    r'^(?P<n>\d+)\s*(?P<unit>h(?:ours?)?|d(?:ays?)?|w(?:eeks?)?|m(?:onths?)?)',
    re.I,
)


def parse_since(value: str) -> datetime:
    """
    Parse a --since string into a timezone-aware UTC datetime.
    Raises ValueError if the string cannot be parsed.
    """
    v = value.strip().lower()
    now = datetime.now(timezone.utc)

    if v in ("yesterday",):
        return now - timedelta(days=1)

    # Strip trailing " ago"
    v = re.sub(r'\s+ago$', '', v).strip()

    m = _RELATIVE_RE.match(v)
    if m:
        n = int(m.group("n"))
        unit = m.group("unit")[0]   # first char: h, d, w, m
        delta = {
            "h": timedelta(hours=n),
            "d": timedelta(days=n),
            "w": timedelta(weeks=n),
            "m": timedelta(days=n * 30),
        }[unit]
        return now - delta

    # Fall back to dateutil for ISO dates
    from dateutil import parser as dtparser
    dt = dtparser.parse(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def apply_since_filter(items: list[FeedItem], since: datetime,
                       include_undated: bool = True) -> list[FeedItem]:
    """
    Drop items published before `since`.
    Items with no published date are kept when include_undated=True.
    """
    result = []
    for item in items:
        if item.published is None:
            if include_undated:
                result.append(item)
        else:
            pub = item.published
            if pub.tzinfo is None:
                pub = pub.replace(tzinfo=timezone.utc)
            if pub >= since:
                result.append(item)
    return result

_SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Keywords that auto-escalate severity when found in title/summary
_ESCALATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bzero.?day\b|\b0.?day\b", re.I), "critical"),
    (re.compile(r"\bRCE\b|remote code execution", re.I), "critical"),
    (re.compile(r"\bransomware\b", re.I), "high"),
    (re.compile(r"\bdata breach\b|\bleak\b", re.I), "high"),
    (re.compile(r"\bphishing\b|\bcredential\b", re.I), "medium"),
]


def apply_keywords(items: list[FeedItem], keywords: list[str], strict: bool = False) -> list[FeedItem]:
    """
    Tag each item with matched_keywords.
    If strict=True, drop items with no keyword matches.
    """
    patterns = [re.compile(re.escape(kw), re.I) for kw in keywords]
    result: list[FeedItem] = []
    for item in items:
        haystack = f"{item.title} {item.summary} {' '.join(item.tags)}"
        matched = [kw for kw, pat in zip(keywords, patterns) if pat.search(haystack)]
        item.matched_keywords = matched
        if strict and not matched:
            continue
        result.append(item)
    return result


def escalate_severity(items: list[FeedItem]) -> list[FeedItem]:
    """Bump severity based on title/summary content."""
    for item in items:
        haystack = f"{item.title} {item.summary}"
        for pattern, new_sev in _ESCALATION_PATTERNS:
            if pattern.search(haystack):
                if _SEVERITY_WEIGHTS.get(new_sev, 0) > _SEVERITY_WEIGHTS.get(item.severity, 0):
                    item.severity = new_sev
                break
    return items


def sort_items(items: list[FeedItem]) -> list[FeedItem]:
    """Sort by: keyword match (desc) → severity (desc) → published (desc)."""
    from datetime import datetime, timezone
    _epoch = datetime.min.replace(tzinfo=timezone.utc)
    return sorted(
        items,
        key=lambda i: (
            len(i.matched_keywords),
            _SEVERITY_WEIGHTS.get(i.severity, 0),
            i.published or _epoch,
        ),
        reverse=True,
    )
