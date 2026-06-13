from collections import Counter
from datetime import timedelta
from urllib.parse import urlparse

from src.models.event import Event
from src.models.event_group import EventGroup


GROUP_GAP = timedelta(minutes=4)
FAMILY_CHANGE_GAP = timedelta(seconds=90)
NEARBY_BROWSER_WINDOW = timedelta(seconds=30)
SUPPORT_ATTACH_PADDING = timedelta(seconds=30)

DOCUMENT_EXTENSIONS = frozenset({".pdf"})
FILE_EXTENSIONS = frozenset({".txt", ".docx", ".xlsx"})
SCRIPT_EXTENSIONS = frozenset({".py", ".ps1", ".bat"})
ARCHIVE_EXTENSIONS = frozenset({".zip", ".rar", ".7z"})
EXPORT_EXTENSIONS = frozenset({".csv", ".json", ".xml"})
INSTALLER_EXTENSIONS = frozenset({".exe", ".msi"})
BROWSER_EXECUTABLES = frozenset({"CHROME.EXE", "MSEDGE.EXE"})


def build_timeline(events: list[Event]) -> list[Event]:
    """Return events sorted chronologically."""
    return sorted(events, key=lambda e: e.timestamp)


def build_sessions(
    events: list[Event],
    soft_gap_minutes: int | None = None,
    base_gap_minutes: int | None = None,
    semantic_gap_minutes: int | None = None,
    hard_gap_minutes: int | None = None,
) -> list[EventGroup]:
    """Group only core events with simple temporal rules."""
    if not events:
        return []

    ordered = build_timeline(events)
    _annotate_events(ordered)

    core_events = [e for e in ordered if e.raw_data.get("role") == "core"]
    support_events = [e for e in ordered if e.raw_data.get("role") == "support"]

    core_buckets = _group_core_events(core_events)
    attachments = [[] for _ in core_buckets]

    for event in support_events:
        idx = _best_attachment_index(event, core_buckets)
        if idx is not None:
            attachments[idx].append(event)

    groups = [
        _build_group(bucket + attached)
        for bucket, attached in zip(core_buckets, attachments)
    ]
    return sorted(groups, key=lambda g: min(e.timestamp for e in g.events))


def _annotate_events(events: list[Event]) -> None:
    for event in events:
        event.raw_data["activity_family_estimate"] = estimate_activity_family(event)

    for event in events:
        event.raw_data["role"] = classify_event_role(event, events)


def estimate_activity_family(event: Event) -> str:
    """Estimate activity family with intentionally simple rules."""
    process_category = event.raw_data.get("process_category", "")
    path = _event_path(event)
    extension = _extension(event)

    if _has_ads_marker(event, "smartscreen", "zone.identifier"):
        return "system_activity"

    if _is_windows_system_path(event.raw_data.get("process_path", path)):
        return "system_activity"
    if process_category.startswith("system_") or process_category == "browser_component":
        return "system_activity"

    if event.event_type == "browser_visit" and _url_scheme(event) in {"http", "https"}:
        return "web_activity"
    if event.event_type == "local_file_access" and _url_scheme(event) == "file":
        return "file_activity"

    if extension in DOCUMENT_EXTENSIONS:
        return "document_activity"
    if extension in FILE_EXTENSIONS:
        return "file_activity"
    if extension in SCRIPT_EXTENSIONS:
        return "script_activity"
    if extension in ARCHIVE_EXTENSIONS:
        return "archive_activity"
    if extension in EXPORT_EXTENSIONS:
        return "data_export"
    if (extension in INSTALLER_EXTENSIONS and _is_downloads_path(path)) or process_category == "installer":
        return "software_installation"

    return "generic_activity"


def classify_event_role(event: Event, all_events: list[Event]) -> str:
    """Classify event role as core, support, or noise."""
    family = event.raw_data.get("activity_family_estimate", "generic_activity")
    process_category = event.raw_data.get("process_category", "")
    executable = _executable_name(event)

    if _has_ads_marker(event, "zone.identifier"):
        return "support"
    if _has_ads_marker(event, "smartscreen"):
        return "noise"
    if family == "system_activity":
        return "noise"
    if process_category.startswith("system_") or process_category == "browser_component":
        return "noise"

    if executable in BROWSER_EXECUTABLES:
        return "core" if _near_browser_visit(event, all_events) else "support"

    if event.event_type in {"browser_visit", "local_file_access", "file_created", "file_modified"}:
        return "core"
    if event.event_type == "program_execution":
        return "core"

    return "support"


def _group_core_events(core_events: list[Event]) -> list[list[Event]]:
    if not core_events:
        return []

    buckets: list[list[Event]] = [[core_events[0]]]
    for event in core_events[1:]:
        current = buckets[-1]
        previous = current[-1]
        gap = event.timestamp - previous.timestamp
        family_changed = _family(event) != _family(previous)

        if gap > GROUP_GAP:
            buckets.append([event])
        elif family_changed and gap > FAMILY_CHANGE_GAP:
            buckets.append([event])
        else:
            current.append(event)

    return buckets


def _best_attachment_index(event: Event, core_buckets: list[list[Event]]) -> int | None:
    best_idx = None
    best_distance = None

    for idx, bucket in enumerate(core_buckets):
        start = min(e.timestamp for e in bucket)
        end = max(e.timestamp for e in bucket)
        if not (start - SUPPORT_ATTACH_PADDING <= event.timestamp <= end + SUPPORT_ATTACH_PADDING):
            continue

        if start <= event.timestamp <= end:
            distance = 0
        else:
            distance = min(
                abs((event.timestamp - start).total_seconds()),
                abs((event.timestamp - end).total_seconds()),
            )

        if best_distance is None or distance < best_distance:
            best_idx = idx
            best_distance = distance

    return best_idx


def _build_group(events: list[Event]) -> EventGroup:
    group_events = sorted(events, key=lambda e: e.timestamp)
    core_events = [e for e in group_events if e.raw_data.get("role") == "core"]
    family = _dominant_family(core_events)

    return EventGroup(
        events=group_events,
        confidence=_compute_confidence(group_events),
        core_event_count=len(core_events),
        support_event_count=len(group_events) - len(core_events),
        primary_activity=family,
        activity_family_estimate=family,
        important_apps=_important_apps(core_events),
        short_title=_title_for_family(family),
    )


def _dominant_family(events: list[Event]) -> str:
    families = [_family(e) for e in events]
    meaningful = [f for f in families if f not in {"system_activity", "generic_activity"}]
    if meaningful:
        return Counter(meaningful).most_common(1)[0][0]
    if families:
        return Counter(families).most_common(1)[0][0]
    return "generic_activity"


def _compute_confidence(events: list[Event]) -> str:
    core_events = [e for e in events if e.raw_data.get("role") == "core"]
    sources = {e.source for e in core_events}
    if len(sources) >= 2:
        return "HIGH"
    if len(core_events) >= 3:
        return "MEDIUM"
    return "LOW"


def _important_apps(events: list[Event]) -> list[str]:
    apps = [e.application for e in events if e.application != "unknown"]
    return [app for app, _ in Counter(apps).most_common()]


def _title_for_family(family: str) -> str:
    return {
        "web_activity": "Web browsing / search activity",
        "file_activity": "File operations",
        "document_activity": "Document/PDF activity",
        "script_activity": "Script/code activity",
        "archive_activity": "Archive activity",
        "software_installation": "Software installation",
        "data_export": "Data export",
        "generic_activity": "Program execution",
        "system_activity": "System activity",
    }.get(family, "Program execution")


def _near_browser_visit(event: Event, events: list[Event]) -> bool:
    return any(
        other.event_type == "browser_visit"
        and abs((event.timestamp - other.timestamp).total_seconds()) <= NEARBY_BROWSER_WINDOW.total_seconds()
        for other in events
        if other is not event
    )


def _family(event: Event) -> str:
    return event.raw_data.get("activity_family_estimate", "generic_activity")


def _event_path(event: Event) -> str:
    return (
        event.raw_data.get("file_path")
        or event.raw_data.get("local_path")
        or event.raw_data.get("process_path")
        or event.raw_data.get("url")
        or ""
    )


def _extension(event: Event) -> str:
    ext = event.raw_data.get("extension", "")
    if ext:
        return ext.lower() if ext.startswith(".") else f".{ext.lower()}"

    name = _event_path(event).rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if "." in name:
        return "." + name.rsplit(".", 1)[-1].lower()
    return ""


def _executable_name(event: Event) -> str:
    value = (
        event.raw_data.get("process_name")
        or event.raw_data.get("executable")
        or event.raw_data.get("process_path")
        or ""
    )
    return value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].upper()


def _url_scheme(event: Event) -> str:
    url = event.raw_data.get("url", "")
    return urlparse(url).scheme.lower() if url else ""


def _is_windows_system_path(path: str) -> bool:
    normalised = path.lower().replace("/", "\\")
    return "\\windows\\system32" in normalised or normalised.startswith("c:\\windows\\system32")


def _is_downloads_path(path: str) -> bool:
    normalised = path.lower().replace("/", "\\")
    return "\\downloads\\" in normalised or normalised.endswith("\\downloads")


def _has_ads_marker(event: Event, *markers: str) -> bool:
    haystack = " ".join([
        event.description,
        _event_path(event),
        event.raw_data.get("filename", ""),
    ]).lower()
    return any(f":{marker.lower()}" in haystack or marker.lower() in haystack for marker in markers)


def group_by_time_window(events: list[Event], window_minutes: int = 4) -> list[EventGroup]:
    """Backward-compatible wrapper around build_sessions."""
    return build_sessions(events)
