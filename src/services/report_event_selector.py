from __future__ import annotations

from pathlib import Path
from typing import Any

from src.models.event import Event
from src.models.event_group import EventGroup


DEFAULT_REPORT_CONFIG = {
    "max_representative_events": 25,
}


def load_report_config(path: str = "config/app_config.yaml") -> dict[str, Any]:
    """Load the small report: config block without requiring PyYAML."""
    config = dict(DEFAULT_REPORT_CONFIG)
    cfg_path = Path(path)
    if not cfg_path.exists():
        return config

    in_report = False
    for raw_line in cfg_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.strip() == "report:":
            in_report = True
            continue
        if not in_report:
            continue
        if not line.startswith("  "):
            break
        key, sep, value = line.strip().partition(":")
        if not sep:
            continue
        try:
            config[key] = int(value.strip())
        except ValueError:
            config[key] = value.strip()

    return config


def select_representative_events_for_report(
    group: EventGroup,
    max_events: int = 25,
) -> list[Event]:
    """Select a compact, chronological set of events for reports and AI prompts."""
    if max_events <= 0:
        return []

    events = sorted(group.events, key=lambda e: e.timestamp)
    core_events = [e for e in events if e.raw_data.get("role") == "core"]
    candidates: dict[tuple[str, str, str, str], tuple[Event, int]] = {}
    pinned_keys: set[tuple[str, str, str, str]] = set()

    def add(event: Event, score: int) -> None:
        key = _event_key(event)
        existing = candidates.get(key)
        if existing is None or score > existing[1]:
            candidates[key] = (event, score)

    for event in core_events[:5]:
        add(event, 100)
        pinned_keys.add(_event_key(event))
    for event in core_events[-5:]:
        add(event, 100)
        pinned_keys.add(_event_key(event))

    important_apps = {app.lower() for app in group.important_apps if app}
    matched_entities = {
        str(entity).lower()
        for finding in group.findings
        for entity in finding.matched_entities
        if entity
    }

    for event in events:
        text = _event_text(event)
        if event.application and event.application.lower() in important_apps:
            add(event, 80)
        if any(entity in text for entity in matched_entities):
            add(event, 85)
        if event.event_type in {"file_created", "file_modified"} and _has_relevant_file_detail(event):
            add(event, 75)
        if event.event_type == "program_execution" and _has_relevant_executable(event):
            add(event, 75)
        if event.event_type == "browser_visit" and _looks_like_search_or_download(event):
            add(event, 65)

    # Add a few time-spread core events so long groups show middle activity too.
    for event in _time_samples(core_events, slots=max(3, min(7, max_events // 4))):
        add(event, 55)

    for app in important_apps:
        for event in _best_matching_events(events, app, limit=2):
            add(event, 95)
            pinned_keys.add(_event_key(event))

    for entity in matched_entities:
        for event in _best_matching_events(events, entity, limit=2):
            add(event, 95)
            pinned_keys.add(_event_key(event))

    selected = [event for event, _score in candidates.values()]
    if len(selected) > max_events:
        pinned = sorted([
            candidates[key]
            for key in pinned_keys
            if key in candidates
        ], key=lambda item: (-item[1], item[0].timestamp, item[0].description))
        ranked = sorted(
            [item for item in candidates.values() if _event_key(item[0]) not in pinned_keys],
            key=lambda item: (-item[1], item[0].timestamp, item[0].description),
        )
        remaining_slots = max(max_events - len(pinned), 0)
        selected = [event for event, _score in pinned[:max_events]]
        selected.extend(event for event, _score in ranked[:remaining_slots])

    return sorted(_dedupe_events(selected), key=lambda e: e.timestamp)


def matched_entities_for_group(group: EventGroup) -> list[str]:
    entities = {
        str(entity)
        for finding in group.findings
        for entity in finding.matched_entities
        if entity
    }
    return sorted(entities, key=str.lower)


def _event_key(event: Event) -> tuple[str, str, str, str]:
    return (
        event.timestamp.isoformat(),
        event.source,
        event.event_type,
        event.description,
    )


def _dedupe_events(events: list[Event]) -> list[Event]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[Event] = []
    for event in events:
        key = _event_key(event)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _event_text(event: Event) -> str:
    values = [
        event.description,
        event.application,
        event.event_type,
        event.source,
    ]
    values.extend(str(value) for value in event.raw_data.values() if value is not None)
    return " ".join(values).lower()


def _has_relevant_file_detail(event: Event) -> bool:
    text = _event_text(event)
    return any(token in text for token in (".pdf", ".txt", ".docx", ".xlsx", ".py", ".ps1", ".bat", ".zip", ".rar", ".7z", ".csv", ".json", ".xml", ".exe", ".msi"))


def _has_relevant_executable(event: Event) -> bool:
    text = _event_text(event)
    if "windows\\system32" in text and event.application == "unknown":
        return False
    return ".exe" in text or ".msi" in text or event.application != "unknown"


def _looks_like_search_or_download(event: Event) -> bool:
    text = _event_text(event)
    return any(token in text for token in ("search", "download", "/download", "q=", ".exe", ".msi", ".zip", ".rar", ".7z", ".pdf"))


def _time_samples(events: list[Event], slots: int) -> list[Event]:
    if not events or slots <= 0:
        return []
    if len(events) <= slots:
        return events

    samples: list[Event] = []
    last_index = len(events) - 1
    for idx in range(slots):
        position = round(idx * last_index / max(slots - 1, 1))
        samples.append(events[position])
    return samples


def _best_matching_events(events: list[Event], needle: str, limit: int) -> list[Event]:
    matches = [event for event in events if needle in _event_text(event)]
    ranked = sorted(
        matches,
        key=lambda event: (
            -_event_priority(event),
            event.timestamp,
            event.description,
        ),
    )
    return ranked[:limit]


def _event_priority(event: Event) -> int:
    if event.event_type == "program_execution":
        return 5
    if event.event_type in {"file_created", "file_modified"}:
        return 4
    if event.event_type == "browser_visit" and _looks_like_search_or_download(event):
        return 3
    if event.raw_data.get("role") == "core":
        return 2
    return 1
