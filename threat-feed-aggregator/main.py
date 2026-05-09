#!/usr/bin/env python3
"""
Threat Feed Aggregator — CLI entry point.

Usage:
    python main.py                          # Run with config.yaml defaults
    python main.py --keywords "RCE,CVE"    # Override keywords (comma-separated)
    python main.py --sources cisa,rss      # Only specific source groups
    python main.py --strict                # Hide items with no keyword match
    python main.py --since "2 days ago"    # Only items newer than this date
    python main.py --since 2024-01-14      # ISO date cutoff
    python main.py --since 12h             # Last 12 hours
    python main.py --output feed.json      # Save output to file
    python main.py --format json           # Output format: table|json|csv|markdown
    python main.py --iocs-only             # Print raw IOC list to stdout
"""

import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import click
import yaml

from aggregator import feeds as src
from aggregator.filter import apply_keywords, escalate_severity, sort_items, apply_since_filter, parse_since
from aggregator.mitre import tag_mitre
from aggregator.display import console, render_dashboard, to_json, to_csv, to_markdown
from aggregator.models import FeedItem

_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_config(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _collect_feeds(cfg: dict, source_filter: list[str] | None) -> list[FeedItem]:
    """Fan-out all enabled fetchers concurrently and collect results."""
    tasks: dict[str, callable] = {}

    abuse = cfg.get("abuse_ch", {})
    if not source_filter or "abuse" in source_filter:
        if abuse.get("urlhaus", {}).get("enabled", True):
            tasks["URLhaus"] = lambda: src.fetch_urlhaus(abuse.get("urlhaus", {}).get("limit", 20))
        if abuse.get("malware_bazaar", {}).get("enabled", True):
            tasks["MalwareBazaar"] = lambda: src.fetch_malware_bazaar(
                abuse.get("malware_bazaar", {}).get("limit", 20)
            )
        if abuse.get("threatfox", {}).get("enabled", True):
            tasks["ThreatFox"] = lambda: src.fetch_threatfox(
                abuse.get("threatfox", {}).get("limit", 20)
            )

    cisa_cfg = cfg.get("cisa", {})
    if not source_filter or "cisa" in source_filter:
        if cisa_cfg.get("enabled", True):
            if cisa_cfg.get("kev_enabled", True):
                days = cisa_cfg.get("kev_days_back", 14)
                tasks["CISA KEV"] = lambda d=days: src.fetch_cisa_kev(d)
            if cisa_cfg.get("advisories_enabled", True):
                tasks["CISA Advisories"] = src.fetch_cisa_advisories

    rss_list = cfg.get("rss_feeds", [])
    if not source_filter or "rss" in source_filter:
        for feed_cfg in rss_list:
            if not feed_cfg.get("enabled", True):
                continue
            name = feed_cfg["name"]
            url = feed_cfg["url"]
            max_items = cfg.get("display", {}).get("max_items_per_source", 15)
            tasks[name] = lambda n=name, u=url, m=max_items: src.fetch_rss(n, u, m)

    all_items: list[FeedItem] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                all_items.extend(result)
                console.print(f"  [dim]✓ {name}: {len(result)} items[/dim]")
            except Exception as exc:
                console.print(f"  [red]✗ {name}: {exc}[/red]")

    return all_items


@click.command()
@click.option("--config", "config_path", default=str(_CONFIG_PATH),
              show_default=True, help="Path to config.yaml")
@click.option("--keywords", default="", help="Comma-separated keyword overrides")
@click.option("--sources", default="",
              help="Comma-separated source groups to include: abuse, cisa, rss")
@click.option("--strict", is_flag=True, default=False,
              help="Hide items with no keyword match")
@click.option("--output", "output_path", default="",
              help="Save results to this file path")
@click.option("--format", "fmt", default="",
              type=click.Choice(["table", "json", "csv", "markdown"], case_sensitive=False),
              help="Output format (default from config)")
@click.option("--since", "since_str", default="",
              help='Only show items published after this point. '
                   'Accepts: "2 days ago", "12h", "1w", "yesterday", '
                   'or ISO date "2024-01-14".')
@click.option("--iocs-only", is_flag=True, default=False,
              help="Print raw IOC values only, one per line")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(config_path, keywords, sources, strict, since_str, output_path, fmt, iocs_only, verbose):
    """Threat Feed Aggregator — one dashboard for all your intel sources."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = load_config(Path(config_path))
    except FileNotFoundError:
        console.print(f"[red]Config not found: {config_path}[/red]")
        sys.exit(1)

    # Resolve options (CLI overrides config)
    kw_list: list[str] = (
        [k.strip() for k in keywords.split(",") if k.strip()]
        or cfg.get("keywords", [])
    )
    strict_mode = strict or cfg.get("strict_filter", False)
    source_filter = [s.strip().lower() for s in sources.split(",") if s.strip()] or None
    output_fmt = fmt or cfg.get("output", {}).get("default_format", "table")
    save_path = output_path or cfg.get("output", {}).get("auto_save", "")

    console.print("\n[bold blue]Threat Feed Aggregator[/bold blue]  — fetching…\n")

    # ── Fetch ─────────────────────────────────────────────────────────────────
    raw_items = _collect_feeds(cfg, source_filter)

    # ── Parse --since ─────────────────────────────────────────────────────────
    since_dt = None
    if since_str:
        try:
            since_dt = parse_since(since_str)
            console.print(f"  [dim]Filtering: published ≥ {since_dt.strftime('%Y-%m-%d %H:%M UTC')}[/dim]")
        except Exception as exc:
            console.print(f"[red]Cannot parse --since value '{since_str}': {exc}[/red]")
            sys.exit(1)

    # ── Filter & sort ─────────────────────────────────────────────────────────
    items = apply_keywords(raw_items, kw_list, strict=strict_mode)
    if since_dt:
        items = apply_since_filter(items, since_dt)
    items = escalate_severity(items)
    items = tag_mitre(items)
    items = sort_items(items)

    # ── IOC-only mode ─────────────────────────────────────────────────────────
    if iocs_only:
        iocs = [i.ioc for i in items if i.ioc]
        print("\n".join(iocs))
        return

    # ── Render / export ───────────────────────────────────────────────────────
    disp_cfg = cfg.get("display", {})
    date_fmt = disp_cfg.get("date_format", "%Y-%m-%d %H:%M UTC")
    max_per = disp_cfg.get("max_items_per_source", 10)
    show_urls = disp_cfg.get("show_urls", True)

    if output_fmt == "json":
        content = to_json(items)
        if save_path:
            Path(save_path).expanduser().write_text(content)
        else:
            print(content)
    elif output_fmt == "csv":
        content = to_csv(items)
        if save_path:
            Path(save_path).expanduser().write_text(content)
        else:
            print(content)
    elif output_fmt == "markdown":
        content = to_markdown(items, date_fmt)
        if save_path:
            Path(save_path).expanduser().write_text(content)
        else:
            print(content)
    else:
        # Default: rich table dashboard
        render_dashboard(items, date_fmt=date_fmt, max_per_source=max_per, show_urls=show_urls)
        if save_path:
            # Also save JSON alongside the visual output
            save = Path(save_path).expanduser()
            save.write_text(to_json(items))
            console.print(f"[green]Saved {len(items)} items → {save}[/green]")


if __name__ == "__main__":
    main()
