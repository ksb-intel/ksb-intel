"""
Rich terminal dashboard and export helpers.
"""

import json
import csv
import io
from datetime import datetime, timezone
from typing import Callable

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns
from rich.rule import Rule
from rich.style import Style

from .models import FeedItem

console = Console()

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "white",
}

_SOURCE_COLORS: dict[str, str] = {
    "abuse.ch URLhaus":      "magenta",
    "abuse.ch MalwareBazaar":"magenta",
    "abuse.ch ThreatFox":    "magenta",
    "CISA KEV":              "bold red",
    "CISA Advisories":       "red",
}


def _sev_badge(severity: str) -> Text:
    style = _SEVERITY_STYLE.get(severity, "white")
    label = severity.upper().center(8)
    return Text(label, style=style)


def _fmt_date(dt: datetime | None, fmt: str) -> str:
    if dt is None:
        return "unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(fmt)


def render_dashboard(
    items: list[FeedItem],
    date_fmt: str = "%Y-%m-%d %H:%M UTC",
    max_per_source: int = 10,
    show_urls: bool = True,
) -> None:
    if not items:
        console.print(Panel("[yellow]No feed items retrieved.[/yellow]", title="Threat Feed Aggregator"))
        return

    # ── Summary stats panel ───────────────────────────────────────────────────
    sources = sorted({i.source for i in items})
    by_sev: dict[str, int] = {}
    for i in items:
        by_sev[i.severity] = by_sev.get(i.severity, 0) + 1

    stat_parts = [
        f"[bold]{len(items)}[/bold] items from [bold]{len(sources)}[/bold] sources",
        "  |  Severity: " + "  ".join(
            f"[{_SEVERITY_STYLE.get(s,'white')}]{s.upper()}: {c}[/]"
            for s, c in sorted(by_sev.items(), key=lambda x: -["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 99)
        ),
    ]
    keyword_hits = [i for i in items if i.matched_keywords]
    if keyword_hits:
        stat_parts.append(f"  |  [bold green]{len(keyword_hits)} keyword matches[/bold green]")

    console.print()
    console.print(Panel(
        "  ".join(stat_parts),
        title="[bold blue]Threat Feed Aggregator[/bold blue]",
        subtitle=f"Run at {datetime.now(timezone.utc).strftime(date_fmt)}",
        border_style="blue",
    ))
    console.print()

    # ── Group by source ───────────────────────────────────────────────────────
    grouped: dict[str, list[FeedItem]] = {}
    for item in items:
        grouped.setdefault(item.source, []).append(item)

    for source in sources:
        source_items = grouped[source][:max_per_source]
        color = _SOURCE_COLORS.get(source, "blue")

        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style=f"bold {color}",
            expand=True,
            show_lines=False,
        )
        table.add_column("SEV", width=9, no_wrap=True)
        table.add_column("Title", ratio=3)
        table.add_column("Summary", ratio=4)
        table.add_column("Published", width=17, no_wrap=True)

        for item in source_items:
            title_text = Text(item.title, overflow="fold")
            # Highlight matched keywords in title
            for kw in item.matched_keywords:
                title_text.highlight_words([kw], style="bold yellow")

            summary_text = Text(item.summary[:160], overflow="fold")

            if show_urls and item.url:
                url_text = Text(f"\n{item.url[:80]}", style="dim underline blue")
                title_text.append_text(url_text)

            table.add_row(
                _sev_badge(item.severity),
                title_text,
                summary_text,
                _fmt_date(item.published, "%m-%d %H:%M"),
            )

        console.rule(f"[{color}]{source}[/{color}]  ({len(grouped[source])} items)", style=color)
        console.print(table)

    console.print()


# ── Export helpers ────────────────────────────────────────────────────────────

def to_json(items: list[FeedItem], indent: int = 2) -> str:
    def _serial(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Not serializable: {type(obj)}")

    records = []
    for i in items:
        records.append({
            "source": i.source,
            "title": i.title,
            "summary": i.summary,
            "url": i.url,
            "published": i.published,
            "tags": i.tags,
            "severity": i.severity,
            "matched_keywords": i.matched_keywords,
            "ioc": i.ioc,
        })
    return json.dumps(records, default=_serial, indent=indent)


def to_csv(items: list[FeedItem]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "source", "severity", "title", "summary", "url",
        "published", "tags", "matched_keywords", "ioc",
    ])
    writer.writeheader()
    for i in items:
        writer.writerow({
            "source": i.source,
            "severity": i.severity,
            "title": i.title,
            "summary": i.summary,
            "url": i.url,
            "published": i.published.isoformat() if i.published else "",
            "tags": "|".join(i.tags),
            "matched_keywords": "|".join(i.matched_keywords),
            "ioc": i.ioc or "",
        })
    return buf.getvalue()


def to_markdown(items: list[FeedItem], date_fmt: str = "%Y-%m-%d %H:%M UTC") -> str:
    lines = [
        f"# Threat Intelligence Feed — {datetime.now(timezone.utc).strftime(date_fmt)}",
        "",
        f"**{len(items)} items** from {len({i.source for i in items})} sources",
        "",
    ]
    current_source = None
    for item in items:
        if item.source != current_source:
            current_source = item.source
            lines += [f"## {current_source}", ""]
        kw_badge = f" `{'` `'.join(item.matched_keywords)}`" if item.matched_keywords else ""
        date_str = _fmt_date(item.published, date_fmt)
        lines += [
            f"### [{item.title}]({item.url})",
            f"**Severity:** `{item.severity}`  **Published:** {date_str}{kw_badge}",
            "",
            item.summary,
            "",
        ]
    return "\n".join(lines)
