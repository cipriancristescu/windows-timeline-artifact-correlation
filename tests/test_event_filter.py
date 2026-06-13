from datetime import datetime
from src.models.event import Event
from src.correlator.event_filter import (
    filter_events,
    filter_by_time_range,
    filter_by_sources,
    is_relevant_event,
)


def make_event(source: str, event_type: str = "test", url: str = "",
               executable: str = "", file_path: str = "",
               minutes: int = 0) -> Event:
    return Event(
        timestamp=datetime(2024, 3, 10, 8, 0 + minutes, 0),
        source=source,
        event_type=event_type,
        description="test event",
        raw_data={
            "url": url,
            "executable": executable,
            "file_path": file_path,
        },
    )


# ---------------------------------------------------------------------------
# Browser heuristics
# ---------------------------------------------------------------------------

def test_browser_normal_url_is_kept():
    e = make_event("browser", url="https://www.google.com")
    assert is_relevant_event(e) is True


def test_browser_chrome_internal_url_is_excluded():
    e = make_event("browser", url="chrome://settings/")
    assert is_relevant_event(e) is False


def test_browser_edge_internal_url_is_excluded():
    e = make_event("browser", url="edge://newtab/")
    assert is_relevant_event(e) is False


def test_browser_about_blank_is_excluded():
    e = make_event("browser", url="about:blank")
    assert is_relevant_event(e) is False


def test_browser_chrome_extension_url_is_excluded():
    e = make_event("browser", url="chrome-extension://abcdef/popup.html")
    assert is_relevant_event(e) is False


def test_browser_moz_extension_url_is_excluded():
    e = make_event("browser", url="moz-extension://abcdef/background.js")
    assert is_relevant_event(e) is False


def test_browser_empty_url_is_kept():
    # An event with no URL in raw_data passes through — we cannot confirm it's noise.
    e = make_event("browser", url="")
    assert is_relevant_event(e) is True


# ---------------------------------------------------------------------------
# Prefetch heuristics
# ---------------------------------------------------------------------------

def test_prefetch_user_executable_is_kept():
    e = make_event("prefetch", executable="notepad.exe")
    assert is_relevant_event(e) is True


def test_prefetch_noisy_executable_is_excluded():
    e = make_event("prefetch", executable="svchost.exe")
    assert is_relevant_event(e) is False


def test_prefetch_executable_with_path_is_filtered_by_name():
    e = make_event("prefetch", executable=r"C:\Windows\System32\svchost.exe")
    assert is_relevant_event(e) is False


# ---------------------------------------------------------------------------
# filter_by_time_range
# ---------------------------------------------------------------------------

def test_time_range_both_bounds(tmp_path):
    events = [make_event("mft", minutes=i) for i in range(5)]
    result = filter_by_time_range(
        events,
        start=datetime(2024, 3, 10, 8, 1, 0),
        end=datetime(2024, 3, 10, 8, 3, 0),
    )
    assert len(result) == 3


def test_time_range_no_bounds_returns_all():
    events = [make_event("mft", minutes=i) for i in range(5)]
    assert filter_by_time_range(events) == events


# ---------------------------------------------------------------------------
# filter_by_sources
# ---------------------------------------------------------------------------

def test_filter_by_sources_keeps_matching():
    events = [make_event("mft"), make_event("prefetch"), make_event("browser")]
    result = filter_by_sources(events, ["prefetch", "browser"])
    assert all(e.source in {"prefetch", "browser"} for e in result)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# filter_events (integration)
# ---------------------------------------------------------------------------

def test_filter_events_combines_source_and_heuristics():
    events = [
        make_event("browser", url="https://example.com"),
        make_event("browser", url="chrome://settings/"),
        make_event("prefetch", executable="notepad.exe"),
    ]
    result = filter_events(events, sources=["browser"])
    # Only browser events, and chrome:// is excluded by heuristics
    assert len(result) == 1
    assert result[0].raw_data["url"] == "https://example.com"
