from datetime import datetime
from src.parsers.prefetch_parser import parse

SAMPLE_CSV = """\
SourceFilename,ExecutableName,Hash,RunCount,LastRun
CMD.EXE-4A81B364.pf,CMD.EXE,4A81B364,5,2024-03-10 08:04:00
NOTEPAD.EXE-D8414F97.pf,NOTEPAD.EXE,D8414F97,3,2024-03-10 08:09:30
"""


def _write_csv(tmp_path, content):
    f = tmp_path / "sample_prefetch.csv"
    f.write_text(content, encoding="utf-8")
    return str(f)


def test_parse_returns_correct_event_count(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert len(events) == 2


def test_parse_source_is_prefetch(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert all(e.source == "prefetch" for e in events)


def test_parse_event_type_is_program_execution(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert all(e.event_type == "program_execution" for e in events)


def test_parse_maps_timestamp(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].timestamp == datetime(2024, 3, 10, 8, 4, 0)


def test_parse_maps_description(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].description == "CMD.EXE executed"


def test_parse_stores_run_count_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["run_count"] == 5


def test_parse_skips_rows_without_executable(tmp_path):
    csv = "SourceFilename,ExecutableName,Hash,RunCount,LastRun\nFOO.pf,,ABC,1,2024-03-10 08:00:00\n"
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 0


def test_parse_skips_malformed_timestamp(tmp_path):
    csv = "SourceFilename,ExecutableName,Hash,RunCount,LastRun\nFOO.pf,FOO.EXE,ABC,1,not-a-date\n"
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 0
