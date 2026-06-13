from dataclasses import dataclass, field
from src.models.event import Event
from src.models.correlation_finding import CorrelationFinding


@dataclass
class EventGroup:
    events: list[Event]
    confidence: str  # "HIGH", "MEDIUM", or "LOW" — see _compute_confidence() in timeline_builder
    findings: list[CorrelationFinding] = field(default_factory=list)
    core_event_count: int = 0
    support_event_count: int = 0
    primary_activity: str = "unknown"
    activity_family_estimate: str = "system_activity"
    important_apps: list[str] = field(default_factory=list)
    short_title: str = "Activity group"

    def __len__(self) -> int:
        return len(self.events)
