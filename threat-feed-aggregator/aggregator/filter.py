"""Keyword filtering and severity scoring."""

import re
from .models import FeedItem

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
