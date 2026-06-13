from dataclasses import dataclass, field


@dataclass
class CorrelationFinding:
    rule_name: str
    explanation: str
    matched_sources: list[str] = field(default_factory=list)
    matched_entities: list[str] = field(default_factory=list)
