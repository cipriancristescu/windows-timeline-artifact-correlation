from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re
from typing import Any

import requests

from src.models.event import Event
from src.models.event_group import EventGroup
from src.services.report_event_selector import (
    load_report_config,
    matched_entities_for_group,
    select_representative_events_for_report,
)


DEFAULT_AI_CONFIG = {
    "enabled": True,
    "provider": "ollama",
    "model": "llama3.2:3b",
    "timeout_seconds": 60,
    "max_core_events": 15,
    "max_support_events": 5,
}

OLLAMA_URL = "http://localhost:11434/api/generate"


def load_ai_config(path: str = "config/app_config.yaml") -> dict[str, Any]:
    """Load the small ai: config block without requiring PyYAML."""
    config = dict(DEFAULT_AI_CONFIG)
    cfg_path = Path(path)
    if not cfg_path.exists():
        return config

    in_ai = False
    for raw_line in cfg_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.strip() == "ai:":
            in_ai = True
            continue
        if not in_ai:
            continue
        if not line.startswith("  "):
            break
        key, sep, value = line.strip().partition(":")
        if not sep:
            continue
        value = value.strip()
        if value.lower() in {"true", "false"}:
            parsed: Any = value.lower() == "true"
        else:
            try:
                parsed = int(value)
            except ValueError:
                parsed = value
        config[key] = parsed

    return config


def generate_group_analysis(
    group: EventGroup,
    model: str | None = None,
    timeout_seconds: int | None = None,
    max_core_events: int | None = None,
    max_support_events: int | None = None,
) -> tuple[str | None, str | None]:
    """Return (analysis_text, error_message) for one group."""
    config = load_ai_config()
    if not config.get("enabled", True):
        return None, "Local AI analysis is unavailable. Showing deterministic summary instead."

    prompt = build_group_prompt(
        group,
        max_core_events=max_core_events or int(config["max_core_events"]),
        max_support_events=max_support_events or int(config["max_support_events"]),
    )

    payload = {
        "model": model or config["model"],
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=timeout_seconds or int(config["timeout_seconds"]),
        )
        response.raise_for_status()
        data = response.json()
        text = (data.get("response") or "").strip()
        if not text:
            return None, "Local AI analysis is unavailable. Showing deterministic summary instead."
        return text, None
    except requests.RequestException:
        return None, "Local AI analysis is unavailable. Showing deterministic summary instead."
    except ValueError:
        return None, "Local AI analysis is unavailable. Showing deterministic summary instead."


def build_group_prompt(
    group: EventGroup,
    max_core_events: int = 15,
    max_support_events: int = 5,
) -> str:
    report_config = load_report_config()
    max_representative_events = int(report_config.get("max_representative_events", 25))
    representative_events = select_representative_events_for_report(
        group,
        max_events=max_representative_events,
    )
    support_events = [e for e in group.events if e.raw_data.get("role") != "core"]
    start, end = _time_interval(group.events)
    sources = ", ".join(sorted({e.source for e in group.events})) or "none"
    apps = ", ".join(group.important_apps) if group.important_apps else "none"
    matched_entities = matched_entities_for_group(group)
    matched_entities_text = ", ".join(matched_entities) if matched_entities else "none"
    detected_indicators = _detected_indicator_lines(group, representative_events)

    representative_lines = _event_lines(representative_events[:max_representative_events])
    support_lines = _event_lines(support_events[:max_support_events])
    finding_lines = [
        f"- {finding.rule_name}: {finding.explanation}; matched entities: "
        f"{', '.join(finding.matched_entities) if finding.matched_entities else 'none'}"
        for finding in group.findings
    ] or ["- none"]

    return f"""You are assisting with a Windows forensic timeline analysis.

Use only the provided information. Do not invent facts.

Group metadata:
- Title: {group.short_title}
- Time interval: {start} - {end}
- Confidence: {group.confidence}
- Sources: {sources}
- Activity family: {group.activity_family_estimate}
- Important applications: {apps}
- Matched entities: {matched_entities_text}

Detected indicators:
{detected_indicators}

Representative events:
These are representative events selected from a larger group. Use them together with Detected indicators, findings, important applications, and matched entities.
{representative_lines}

Supporting events:
{support_lines}

Findings:
{chr(10).join(finding_lines)}

Task:
Write a short, clear AI interpretation in English using this format:

Probable interpretation:
...

Evidence:
...

Confidence:
...

Limitations:
...

Rules:
- In Probable interpretation, write one short paragraph.
- This group may contain multiple related actions because grouping is based on temporal proximity. If multiple distinct applications, installer files, downloads, or executions are visible, mention them briefly in the same paragraph instead of focusing on only one.
- Use only the provided representative events, findings, important applications, and matched entities.
- Do not contradict the deterministic summary.
- Do not say that no download or execution occurred if file_created, file_modified, or program_execution events are listed.
- Do not invent facts.
- Do not mention event numbers.
- Do not over-explain.
- If uncertain, use "likely" or "possibly".
- Use cautious wording such as "likely", "suggests", or "appears to".
- Keep the response under 130 words.
- Do not change the group classification.
- Do not claim certainty if the evidence is incomplete.
"""


def _event_lines(events: list[Event]) -> str:
    if not events:
        return "none"
    lines = []
    for idx, event in enumerate(events, start=1):
        detail = (
            event.raw_data.get("url")
            or event.raw_data.get("file_path")
            or event.raw_data.get("local_path")
            or event.raw_data.get("process_name")
            or event.raw_data.get("executable")
            or event.description
        )
        lines.append(
            f"{idx}. {event.timestamp.isoformat(sep=' ', timespec='seconds')} | "
            f"{event.source} | {event.event_type} | {event.application} | {detail}"
        )
    return "\n".join(lines)


def _time_interval(events: list[Event]) -> tuple[str, str]:
    if not events:
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        return now, now
    timestamps = sorted(e.timestamp for e in events)
    return (
        timestamps[0].isoformat(sep=" ", timespec="seconds"),
        timestamps[-1].isoformat(sep=" ", timespec="seconds"),
    )


def _detected_indicator_lines(group: EventGroup, events: list[Event]) -> str:
    apps = group.important_apps or []
    matched_entities = matched_entities_for_group(group)
    matched_executables = _matched_executables(group, events)
    search_terms = _search_terms(group)
    installer_files = _installer_files(events)

    return "\n".join([
        f"- Important applications: {_join_or_none(apps)}",
        f"- Matched executables: {_join_or_none(matched_executables)}",
        f"- Search terms: {_join_or_none(search_terms)}",
        f"- Downloaded or created installer files: {_join_or_none(installer_files)}",
        f"- Other matched entities: {_join_or_none(matched_entities)}",
    ])


def _matched_executables(group: EventGroup, events: list[Event]) -> list[str]:
    executables: set[str] = set()
    for finding in group.findings:
        for entity in finding.matched_entities:
            value = str(entity).strip()
            if _looks_like_executable(value):
                executables.add(value)

    for event in events:
        if event.event_type != "program_execution":
            continue
        for key in ("process_name", "executable", "prefetch_file"):
            value = event.raw_data.get(key)
            if value and _looks_like_executable(str(value)):
                executables.add(str(value))
        for match in re.findall(r"[\w.-]+\.(?:exe|msi)\b", event.description, flags=re.IGNORECASE):
            executables.add(match)

    return sorted(executables, key=str.lower)


def _search_terms(group: EventGroup) -> list[str]:
    terms: set[str] = set()
    for finding in group.findings:
        if finding.rule_name != "search_then_action":
            continue
        for entity in finding.matched_entities:
            value = str(entity).strip()
            if value:
                terms.add(value)
    return sorted(terms, key=str.lower)


def _installer_files(events: list[Event]) -> list[str]:
    files: set[str] = set()
    for event in events:
        if event.event_type not in {"file_created", "file_modified"}:
            continue
        for key in ("filename", "file_path", "local_path"):
            value = event.raw_data.get(key)
            if not value:
                continue
            name = str(value).rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if _looks_like_executable(name):
                files.add(name)
        for match in re.findall(r"[\w.-]+\.(?:exe|msi)\b", event.description, flags=re.IGNORECASE):
            files.add(match)
    return sorted(files, key=str.lower)


def _looks_like_executable(value: str) -> bool:
    return bool(re.search(r"\.(?:exe|msi)\b", value, flags=re.IGNORECASE))


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else "none"
