from datetime import datetime
from src.parsers.mft_parser import parse

SAMPLE_CSV = """\
EntryNumber,ParentPath,FileName,Extension,FileSize,Created0x10,LastModified0x10,LastRecordChange0x10,LastAccess0x10
1001,C:\\Users\\User\\Documents,report.pdf,.pdf,204800,2024-03-10 07:50:00.000000,2024-03-10 08:05:00.000000,2024-03-10 08:05:01.000000,2024-03-10 08:05:00.000000
1002,C:\\Users\\User\\Desktop,analysis.py,.py,3200,2024-03-10 08:10:00.000000,2024-03-10 08:45:00.000000,2024-03-10 08:45:01.000000,2024-03-10 08:45:00.000000
1003,,,,.exe,0,,,,
"""


def _write_csv(tmp_path, content):
    f = tmp_path / "sample_mft.csv"
    f.write_text(content, encoding="utf-8")
    return str(f)


def test_parse_returns_correct_event_count(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert len(events) == 2  # third row has no timestamp or path — skipped


def test_parse_source_is_mft(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert all(e.source == "mft" for e in events)


def test_parse_event_type_is_file_activity(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert all(e.event_type == "file_activity" for e in events)


def test_parse_uses_modified_timestamp(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    # First row: LastModified0x10 = 2024-03-10 08:05:00
    assert events[0].timestamp == datetime(2024, 3, 10, 8, 5, 0)


def test_parse_falls_back_to_created_when_modified_missing(tmp_path):
    csv = (
        "ParentPath,FileName,Created0x10,LastModified0x10\n"
        "C:\\Users\\User\\Desktop,notes.txt,2024-03-10 09:00:00.000000,\n"
    )
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 1
    assert events[0].timestamp == datetime(2024, 3, 10, 9, 0, 0)


def test_parse_stores_file_path_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert "file_path" in events[0].raw_data
    assert "report.pdf" in events[0].raw_data["file_path"]


def test_parse_stores_extension_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["extension"] == ".pdf"
    assert events[1].raw_data["extension"] == ".py"


def test_parse_skips_rows_without_timestamp(tmp_path):
    csv = (
        "ParentPath,FileName,Created0x10,LastModified0x10\n"
        "C:\\Users\\User\\Desktop,notes.txt,,\n"
    )
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 0


def test_parse_skips_rows_without_file_path(tmp_path):
    csv = (
        "ParentPath,FileName,Created0x10,LastModified0x10\n"
        ",,2024-03-10 08:00:00.000000,2024-03-10 08:01:00.000000\n"
    )
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 0


def test_parse_stores_source_file_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["source_file"] == path


def test_parse_description_is_human_readable(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].description.startswith("File activity:")
    assert "report.pdf" in events[0].description
