from datetime import datetime
from src.models.event import Event
from src.models.event_group import EventGroup
from src.correlator.event_correlator import correlate_group


def make_event(source: str, event_type: str = "test", minutes: int = 0,
               url: str = "", executable: str = "",
               file_path: str = "", extension: str = "") -> Event:
    return Event(
        timestamp=datetime(2024, 3, 10, 8, minutes, 0),
        source=source,
        event_type=event_type,
        description="test",
        raw_data={
            "url": url,
            "executable": executable,
            "file_path": file_path,
            "filename": file_path.rsplit("\\", 1)[-1] if file_path else "",
            "extension": extension,
        },
    )


def make_group(*events) -> EventGroup:
    return EventGroup(events=list(events), confidence="LOW")


def rule_names(group: EventGroup) -> list[str]:
    return [f.rule_name for f in correlate_group(group)]


# ---------------------------------------------------------------------------
# cross_source_confirmation
# ---------------------------------------------------------------------------

def test_cross_source_two_primary_sources():
    g = make_group(
        make_event("prefetch", executable="notepad.exe"),
        make_event("mft", file_path=r"C:\Users\User\Desktop\notes.txt", extension=".txt"),
    )
    assert "cross_source_confirmation" in rule_names(g)


def test_cross_source_single_source_does_not_fire():
    g = make_group(
        make_event("prefetch", executable="notepad.exe"),
        make_event("prefetch", executable="cmd.exe"),
    )
    assert "cross_source_confirmation" not in rule_names(g)


def test_cross_source_single_source_mft_does_not_count_as_cross_source():
    g = make_group(
        make_event("mft"),
        make_event("mft"),
    )
    assert "cross_source_confirmation" not in rule_names(g)


def test_cross_source_three_sources_fires():
    g = make_group(
        make_event("browser", url="https://example.com"),
        make_event("mft", file_path=r"C:\Users\User\Downloads\tool.zip", extension=".zip"),
        make_event("prefetch", executable="tool.exe"),
    )
    findings = correlate_group(g)
    cf = next(f for f in findings if f.rule_name == "cross_source_confirmation")
    assert "three" in cf.explanation.lower()


# ---------------------------------------------------------------------------
# same_executable_correlation
# ---------------------------------------------------------------------------

def test_same_executable_fires_on_duplicate():
    g = make_group(
        make_event("prefetch", executable="cmd.exe"),
        make_event("mft", file_path=r"C:\Windows\cmd.exe", extension=".exe"),
    )
    assert "same_executable_correlation" in rule_names(g)


def test_same_executable_does_not_fire_on_unique_names():
    g = make_group(
        make_event("prefetch", executable="notepad.exe"),
        make_event("prefetch", executable="cmd.exe"),
    )
    assert "same_executable_correlation" not in rule_names(g)


# ---------------------------------------------------------------------------
# download_correlation
# ---------------------------------------------------------------------------

def test_download_correlation_fires():
    g = make_group(
        make_event("browser", url="https://example.com/tool.zip"),
        make_event("mft", file_path=r"C:\Users\User\Downloads\tool.zip", extension=".zip"),
    )
    assert "download_correlation" in rule_names(g)


def test_download_correlation_no_mft_does_not_fire():
    g = make_group(
        make_event("browser", url="https://example.com"),
    )
    assert "download_correlation" not in rule_names(g)


def test_download_correlation_mft_not_in_downloads_does_not_fire():
    g = make_group(
        make_event("browser", url="https://example.com"),
        make_event("mft", file_path=r"C:\Users\User\Documents\notes.txt", extension=".txt"),
    )
    assert "download_correlation" not in rule_names(g)


# ---------------------------------------------------------------------------
# download_and_execution
# ---------------------------------------------------------------------------

def test_download_and_execution_fires():
    g = make_group(
        make_event("browser", url="https://example.com/setup.zip"),
        make_event("mft", file_path=r"C:\Users\User\Downloads\setup.zip", extension=".zip"),
        make_event("prefetch", executable="setup.exe"),
    )
    assert "download_and_execution" in rule_names(g)


def test_download_and_execution_missing_prefetch_does_not_fire():
    g = make_group(
        make_event("browser", url="https://example.com/setup.zip"),
        make_event("mft", file_path=r"C:\Users\User\Downloads\setup.zip", extension=".zip"),
    )
    assert "download_and_execution" not in rule_names(g)


# ---------------------------------------------------------------------------
# search_then_action
# ---------------------------------------------------------------------------

def test_search_then_action_fires_on_google():
    g = make_group(
        make_event("browser", url="https://www.google.com/search?q=python+forensics"),
        make_event("prefetch", executable="python.exe"),
    )
    assert "search_then_action" in rule_names(g)


def test_search_then_action_extracts_query():
    g = make_group(
        make_event("browser", url="https://www.google.com/search?q=forensic+tools"),
        make_event("mft", file_path=r"C:\Users\User\Desktop\notes.txt", extension=".txt"),
    )
    findings = correlate_group(g)
    f = next(x for x in findings if x.rule_name == "search_then_action")
    assert "forensic" in f.matched_entities[0]


def test_search_then_action_no_local_activity_does_not_fire():
    g = make_group(
        make_event("browser", url="https://www.google.com/search?q=test"),
    )
    assert "search_then_action" not in rule_names(g)


# ---------------------------------------------------------------------------
# local_file_workflow
# ---------------------------------------------------------------------------

def test_local_file_workflow_notepad_txt():
    g = make_group(
        make_event("prefetch", executable="notepad.exe"),
        make_event("mft", file_path=r"C:\Users\User\Desktop\notes.txt", extension=".txt"),
    )
    assert "local_file_workflow" in rule_names(g)


def test_local_file_workflow_python_py():
    g = make_group(
        make_event("prefetch", executable="python.exe"),
        make_event("mft", file_path=r"C:\Users\User\Desktop\script.py", extension=".py"),
    )
    assert "local_file_workflow" in rule_names(g)


def test_local_file_workflow_no_match_does_not_fire():
    g = make_group(
        make_event("prefetch", executable="notepad.exe"),
        make_event("mft", file_path=r"C:\Users\User\Desktop\data.xlsx", extension=".xlsx"),
    )
    assert "local_file_workflow" not in rule_names(g)
