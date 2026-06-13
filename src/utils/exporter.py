import csv
import json
from src.models.event import Event
from src.models.event_group import EventGroup


def export_json(events: list[Event], output_path: str) -> None:
    """Serialize a list of events to a JSON file."""
    records = []
    for event in events:
        records.append({
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "event_type": event.event_type,
            "role": event.raw_data.get("role", ""),
            "activity_family_estimate": event.raw_data.get("activity_family_estimate", ""),
            "description": event.description,
            "raw_data": event.raw_data,
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def export_groups_json(groups: list[EventGroup], output_path: str) -> None:
    """Serialize grouped events with confidence levels and findings to a JSON file."""
    records = []
    for group in groups:
        records.append({
            "confidence": group.confidence,
            "event_count": len(group.events),
            "core_event_count": group.core_event_count,
            "support_event_count": group.support_event_count,
            "primary_activity": group.primary_activity,
            "activity_family_estimate": group.activity_family_estimate,
            "important_apps": group.important_apps,
            "short_title": group.short_title,
            "sources": sorted({e.source for e in group.events}),
            "findings": [
                {
                    "rule_name": f.rule_name,
                    "explanation": f.explanation,
                    "matched_sources": f.matched_sources,
                    "matched_entities": f.matched_entities,
                }
                for f in group.findings
            ],
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "source": e.source,
                    "event_type": e.event_type,
                    "role": e.raw_data.get("role", ""),
                    "activity_family_estimate": e.raw_data.get("activity_family_estimate", ""),
                    "description": e.description,
                    "raw_data": e.raw_data,
                }
                for e in group.events
            ],
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def export_csv(events: list[Event], output_path: str) -> None:
    """Serialize a list of events to a CSV file.

    raw_data is stored as a JSON string since CSV is a flat format.
    """
    fieldnames = [
        "timestamp", "source", "event_type", "role",
        "activity_family_estimate", "description", "raw_data",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow({
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "event_type": event.event_type,
                "role": event.raw_data.get("role", ""),
                "activity_family_estimate": event.raw_data.get("activity_family_estimate", ""),
                "description": event.description,
                "raw_data": json.dumps(event.raw_data) if event.raw_data else "",
            })
