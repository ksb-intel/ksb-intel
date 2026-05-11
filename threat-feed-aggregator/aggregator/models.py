from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class FeedItem:
    source: str          # "URLhaus", "CISA KEV", "Krebs on Security", …
    title: str
    summary: str
    url: str
    published: Optional[datetime]
    tags: list[str] = field(default_factory=list)
    severity: str = "info"   # critical | high | medium | low | info
    matched_keywords: list[str] = field(default_factory=list)
    ioc: Optional[str] = None          # raw IOC value when relevant
    mitre_techniques: list[str] = field(default_factory=list)  # "T1566 Phishing [Initial Access]"
