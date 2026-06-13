from src.models.event import Event
from src.models.event_group import EventGroup
from src.models.correlation_finding import CorrelationFinding


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_executable(event: Event) -> str:
    """Return the lowercase basename of the executable referenced by an event.

    Reads raw_data["executable"] first (prefetch), then falls back to
    raw_data["filename"] (mft). Returns empty string if neither is present.
    """
    raw = event.raw_data.get("executable") or event.raw_data.get("filename", "")
    name = raw.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return name


def _get_mft_path(event: Event) -> str:
    """Return the lowercase file path stored in an MFT event."""
    return event.raw_data.get("file_path", "").lower()


def _get_url(event: Event) -> str:
    """Return the URL stored in a browser event."""
    return event.raw_data.get("url", "").lower()


def _is_search_url(url: str) -> bool:
    """Return True if the URL looks like a search engine query.

    Detects the most common patterns without NLP or external lookup.
    """
    search_signals = ("google.", "bing.", "duckduckgo.", "yahoo.", "search?q=", "/search?")
    return any(signal in url for signal in search_signals)


def _is_downloads_path(path: str) -> bool:
    return "downloads" in path


def _basename(path: str) -> str:
    """Return the lowercase filename portion of a path."""
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _stem(filename: str) -> str:
    """Return the filename without its extension."""
    return filename.rsplit(".", 1)[0] if "." in filename else filename


# ---------------------------------------------------------------------------
# Correlation rules
# Each rule takes the events of one group and returns a finding or None.
# ---------------------------------------------------------------------------

def _rule_same_executable(events: list[Event]) -> CorrelationFinding | None:
    """Fire when multiple events in the group reference the same executable.

    This can indicate repeated execution or cross-source confirmation of
    a specific program being used (e.g. prefetch + MFT record for same .exe).
    """
    names: list[str] = []
    for e in events:
        name = _get_executable(e)
        if name:
            names.append(name)

    # Count occurrences; fire if any executable appears more than once.
    seen: dict[str, int] = {}
    for name in names:
        seen[name] = seen.get(name, 0) + 1

    repeated = [name for name, count in seen.items() if count > 1]
    if not repeated:
        return None

    return CorrelationFinding(
        rule_name="same_executable_correlation",
        explanation=f"Multiple events reference the same executable(s): {', '.join(repeated)}.",
        matched_sources=sorted({e.source for e in events if _get_executable(e) in repeated}),
        matched_entities=repeated,
    )


def _rule_download_correlation(events: list[Event]) -> CorrelationFinding | None:
    """Fire when a browser visit co-occurs with an MFT file event in Downloads.

    Indicates the user likely downloaded a file during the browsing session.
    Optionally checks for a filename/URL fragment match for stronger evidence.
    """
    browser_events = [e for e in events if e.source == "browser"]
    mft_downloads = [
        e for e in events
        if e.source == "mft" and _is_downloads_path(_get_mft_path(e))
    ]

    if not browser_events or not mft_downloads:
        return None

    # Check for a loose filename/URL match as an optional signal.
    matched_entities: list[str] = []
    for mft_e in mft_downloads:
        fname = _basename(_get_mft_path(mft_e))
        stem = _stem(fname)
        for br_e in browser_events:
            if stem and stem in _get_url(br_e):
                matched_entities.append(fname)

    explanation = "A browser visit co-occurred with a file download in the Downloads folder."
    if matched_entities:
        explanation += f" Possible match: {', '.join(set(matched_entities))}."

    return CorrelationFinding(
        rule_name="download_correlation",
        explanation=explanation,
        matched_sources=["browser", "mft"],
        matched_entities=matched_entities,
    )


def _rule_download_and_execution(events: list[Event]) -> CorrelationFinding | None:
    """Fire when a download (browser + MFT in Downloads) is followed by execution (Prefetch).

    This is one of the strongest forensic signals: the user downloaded a file
    and then ran it. The executable name is compared to the downloaded filename
    using stem matching (e.g. 'setup' in 'setup.exe' matches 'setup.zip').
    """
    browser_events = [e for e in events if e.source == "browser"]
    mft_downloads = [
        e for e in events
        if e.source == "mft" and _is_downloads_path(_get_mft_path(e))
    ]
    prefetch_events = [e for e in events if e.source == "prefetch"]

    if not browser_events or not mft_downloads or not prefetch_events:
        return None

    matched: list[str] = []
    for mft_e in mft_downloads:
        dl_stem = _stem(_basename(_get_mft_path(mft_e)))
        for pf_e in prefetch_events:
            exe_stem = _stem(_get_executable(pf_e))
            if dl_stem and exe_stem and (dl_stem in exe_stem or exe_stem in dl_stem):
                matched.append(_get_executable(pf_e))

    # Report even without a name match — co-occurrence alone is significant.
    explanation = (
        "A file was downloaded via browser and a program was executed in the same time window."
    )
    if matched:
        explanation += f" Likely executed: {', '.join(set(matched))}."

    return CorrelationFinding(
        rule_name="download_and_execution",
        explanation=explanation,
        matched_sources=["browser", "mft", "prefetch"],
        matched_entities=matched,
    )


def _rule_search_then_action(events: list[Event]) -> CorrelationFinding | None:
    """Fire when a search engine query is followed by local activity (MFT or Prefetch).

    Indicates the user searched for something and then performed a related
    local operation — a common pattern in both legitimate and suspicious activity.
    """
    search_events = [
        e for e in events
        if e.source == "browser" and _is_search_url(_get_url(e))
    ]
    local_events = [e for e in events if e.source in ("mft", "prefetch")]

    if not search_events or not local_events:
        return None

    queries: list[str] = []
    for e in search_events:
        url = _get_url(e)
        # Extract the query string value from common search URL patterns.
        for marker in ("search?q=", "?q=", "&q="):
            if marker in url:
                raw_q = url.split(marker, 1)[1].split("&")[0]
                queries.append(raw_q.replace("+", " ").replace("%20", " "))
                break

    explanation = "A search engine query was followed by local file or program activity."
    if queries:
        explanation += f" Search term(s): {', '.join(queries[:3])}."

    return CorrelationFinding(
        rule_name="search_then_action",
        explanation=explanation,
        matched_sources=sorted({e.source for e in search_events + local_events}),
        matched_entities=queries,
    )


def _rule_local_file_workflow(events: list[Event]) -> CorrelationFinding | None:
    """Fire when a user-facing program runs alongside relevant local file activity.

    Detects patterns like: notepad.exe + .txt file, python.exe + .py file,
    winword.exe + .docx file. Indicates a productive file editing session.
    """
    # Pairs of (executable stem, relevant extension).
    WORKFLOW_PAIRS = [
        ("notepad", ".txt"),
        ("wordpad", ".txt"),
        ("python",  ".py"),
        ("winword", ".docx"),
        ("winword", ".doc"),
        ("excel",   ".xlsx"),
        ("excel",   ".xls"),
        ("chrome",  ".pdf"),
        ("msedge",  ".pdf"),
        ("firefox", ".pdf"),
    ]

    prefetch_events = [e for e in events if e.source == "prefetch"]
    mft_events = [e for e in events if e.source == "mft"]

    if not prefetch_events or not mft_events:
        return None

    matched_pairs: list[str] = []
    for pf_e in prefetch_events:
        exe_stem = _stem(_get_executable(pf_e))
        for mft_e in mft_events:
            ext = mft_e.raw_data.get("extension", "").lower()
            fname = _basename(_get_mft_path(mft_e))
            for exe_pattern, ext_pattern in WORKFLOW_PAIRS:
                if exe_pattern in exe_stem and ext == ext_pattern:
                    matched_pairs.append(f"{_get_executable(pf_e)} + {fname}")

    if not matched_pairs:
        return None

    return CorrelationFinding(
        rule_name="local_file_workflow",
        explanation=f"Program execution matches local file activity: {'; '.join(set(matched_pairs))}.",
        matched_sources=["prefetch", "mft"],
        matched_entities=list(set(matched_pairs)),
    )


def _rule_cross_source_confirmation(events: list[Event]) -> CorrelationFinding | None:
    """Fire when a group contains events from 2 or more distinct relevant sources.

    Multiple independent artifact types recording overlapping activity
    increases confidence that the activity is genuine and unaltered.
    Three distinct sources provide stronger confirmation than two.
    """
    PRIMARY_SOURCES = {"prefetch", "mft", "browser"}
    present = {e.source for e in events} & PRIMARY_SOURCES

    if len(present) < 2:
        return None

    if len(present) >= 3:
        explanation = (
            f"Three independent artifact sources confirm activity in this window: "
            f"{', '.join(sorted(present))}. This is strong corroborating evidence."
        )
    else:
        explanation = (
            f"Two independent artifact sources confirm activity in this window: "
            f"{', '.join(sorted(present))}."
        )

    return CorrelationFinding(
        rule_name="cross_source_confirmation",
        explanation=explanation,
        matched_sources=sorted(present),
        matched_entities=[],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate_group(group: EventGroup) -> list[CorrelationFinding]:
    """Run all correlation rules against a single group and return findings.

    Rules are independent — multiple rules can fire on the same group.
    Rules that do not match return None and are excluded from the result.
    """
    rules = [
        _rule_cross_source_confirmation,
        _rule_same_executable,
        _rule_download_correlation,
        _rule_download_and_execution,
        _rule_search_then_action,
        _rule_local_file_workflow,
    ]

    findings: list[CorrelationFinding] = []
    for rule in rules:
        result = rule(group.events)
        if result is not None:
            findings.append(result)

    return findings


def correlate_all(groups: list[EventGroup]) -> list[EventGroup]:
    """Run correlation over all groups in-place and return the updated list."""
    for group in groups:
        group.findings = correlate_group(group)
    return groups
