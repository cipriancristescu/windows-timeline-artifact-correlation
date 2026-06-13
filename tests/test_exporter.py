import csv
import json
from datetime import datetime
from src.models.event import Event
from src.models.event_group import EventGroup
from src.utils.exporter import export_json, export_csv, export_groups_json


def sample_events() -> list[Event]:
    return [
        Event(datetime(2024, 3, 10, 8, 0, 0),  "browser",  "browser_visit",     "Visited example",  {"url": "https://example.com"}),
        Event(datetime(2024, 3, 10, 9, 0, 0),  "prefetch", "program_execution", "cmd.exe executed", {"run_count": 3}),
    ]


# --- export_json ---

def test_export_json_creates_file(tmp_path):
    path = str(tmp_path / "timeline.json")
    export_json(sample_events(), path)
    assert (tmp_path / "timeline.json").exists()


def test_export_json_correct_number_of_records(tmp_path):
    path = str(tmp_path / "timeline.json")
    export_json(sample_events(), path)
    with open(path) as f:
        data = json.load(f)
    assert len(data) == 2


def test_export_json_fields_are_correct(tmp_path):
    path = str(tmp_path / "timeline.json")
    export_json(sample_events(), path)
    with open(path) as f:
        data = json.load(f)
    first = data[0]
    assert first["timestamp"] == "2024-03-10T08:00:00"
    assert first["source"] == "browser"
    assert first["event_type"] == "browser_visit"
    assert first["raw_data"]["url"] == "https://example.com"


# --- export_csv ---

def test_export_csv_creates_file(tmp_path):
    path = str(tmp_path / "timeline.csv")
    export_csv(sample_events(), path)
    assert (tmp_path / "timeline.csv").exists()


def test_export_csv_correct_number_of_rows(tmp_path):
    path = str(tmp_path / "timeline.csv")
    export_csv(sample_events(), path)
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2


def test_export_csv_fields_are_correct(tmp_path):
    path = str(tmp_path / "timeline.csv")
    export_csv(sample_events(), path)
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["source"] == "browser"
    assert rows[1]["event_type"] == "program_execution"
    assert rows[0]["timestamp"] == "2024-03-10T08:00:00"


# --- export_groups_json ---

def test_export_groups_json_creates_file(tmp_path):
    path = str(tmp_path / "groups.json")
    export_groups_json([EventGroup(events=sample_events(), confidence="HIGH")], path)
    assert (tmp_path / "groups.json").exists()


def test_export_groups_json_includes_confidence(tmp_path):
    path = str(tmp_path / "groups.json")
    export_groups_json([EventGroup(events=sample_events(), confidence="HIGH")], path)
    with open(path) as f:
        data = json.load(f)
    assert data[0]["confidence"] == "HIGH"


def test_export_groups_json_includes_sources_and_count(tmp_path):
    path = str(tmp_path / "groups.json")
    export_groups_json([EventGroup(events=sample_events(), confidence="HIGH")], path)
    with open(path) as f:
        data = json.load(f)
    assert data[0]["event_count"] == 2
    assert "browser" in data[0]["sources"]
    assert "prefetch" in data[0]["sources"]
