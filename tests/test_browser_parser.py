from datetime import datetime
from src.parsers.browser_parser import parse

SAMPLE_CSV = """\
URL,Title,Visit Time,Web Browser
https://www.google.com/search?q=test,test - Google Search,2024-03-10 08:20:00,Chrome
https://github.com/example,Example Repo,2024-03-10 08:22:00,Chrome
,Missing URL row,2024-03-10 08:25:00,Chrome
https://example.com,Bad Timestamp Row,not-a-date,Chrome
"""


def _write_csv(tmp_path, content):
    f = tmp_path / "sample_browser.csv"
    f.write_text(content, encoding="utf-8")
    return str(f)


def test_parse_returns_correct_event_count(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert len(events) == 2  # missing URL and bad timestamp rows are skipped


def test_parse_source_is_browser(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert all(e.source == "browser" for e in events)


def test_parse_event_type_is_url_visit(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert all(e.event_type == "url_visit" for e in events)


def test_parse_maps_timestamp(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].timestamp == datetime(2024, 3, 10, 8, 20, 0)


def test_parse_stores_url_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["url"] == "https://www.google.com/search?q=test"


def test_parse_stores_title_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["title"] == "test - Google Search"


def test_parse_stores_source_file_in_raw_data(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["source_file"] == path


def test_parse_description_includes_url(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert "https://www.google.com/search?q=test" in events[0].description


def test_parse_description_includes_title_when_present(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert "test - Google Search" in events[0].description


def test_parse_skips_missing_url(tmp_path):
    csv = "URL,Title,Visit Time\n,No URL,2024-03-10 08:00:00\n"
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 0


def test_parse_skips_bad_timestamp(tmp_path):
    csv = "URL,Title,Visit Time\nhttps://example.com,Test,not-a-date\n"
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert len(events) == 0


def test_parse_extracts_domain(tmp_path):
    path = _write_csv(tmp_path, SAMPLE_CSV)
    events = parse(path)
    assert events[0].raw_data["domain"] == "www.google.com"


def test_parse_description_without_title(tmp_path):
    csv = "URL,Title,Visit Time\nhttps://example.com,,2024-03-10 08:00:00\n"
    path = _write_csv(tmp_path, csv)
    events = parse(path)
    assert events[0].description == "Visited https://example.com"
