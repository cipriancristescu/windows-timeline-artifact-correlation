from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    timestamp: datetime
    source: str
    event_type: str
    description: str
    raw_data: dict = field(default_factory=dict)
    application: str = "unknown"
    activity_family: str = "unknown"
    activity_mode: str = "unknown"

    def __str__(self):
        return f"[{self.timestamp}] [{self.source}] {self.event_type}: {self.description}"
