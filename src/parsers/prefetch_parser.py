import csv
from datetime import datetime
from src.models.event import Event


DEFAULT_EXCLUDED_PROCESSES = frozenset({
    "SVCHOST.EXE",
    "RUNTIMEBROKER.EXE",
    "DLLHOST.EXE",
    "TASKHOSTW.EXE",
    "SEARCHFILTERHOST.EXE",
    "SEARCHPROTOCOLHOST.EXE",
    "SEARCHINDEXER.EXE",
    "CONHOST.EXE",
    "AUDIODG.EXE",
    "FONTDRVHOST.EXE",
    "WWAHOST.EXE",
    "SEARCHAPP.EXE",
    "APPLICATIONFRAMEHOST.EXE",
    "BACKGROUNDTASKHOST.EXE",
    "SHELLEXPERIENCEHOST.EXE",
    "STARTMENUEXPERIENCEHOST.EXE",
    "TEXTINPUTHOST.EXE",
    "USEROOBEBROKER.EXE",
    "LOCKAPP.EXE",
    "WMIPRVSE.EXE",
    "RUNDLL32.EXE",
    "TIWORKER.EXE",
    "TRUSTEDINSTALLER.EXE",
    "COMPATTELRUNNER.EXE",
    "MPCMDRUN.EXE",
})

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
]

HEADERLESS_FIELDS = [
    "prefetch_file",
    "created_time",
    "modified_time",
    "file_size",
    "process_name",
    "process_path",
    "run_count",
    "last_run_times",
    "missing_process",
]


def _parse_timestamp(value: str) -> datetime:
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {value!r}")


def _parse_timestamps(value: str) -> list[datetime]:
    timestamps = []
    for part in (value or "").split(","):
        raw = part.strip().strip('"')
        if raw:
            timestamps.append(_parse_timestamp(raw))
    return timestamps


def _get(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key, "")
        if value is None:
            continue
        value = value.strip()
        if value:
            return value
    return ""


def _detect_encoding(file_path: str) -> str:
    for encoding in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            with open(file_path, encoding=encoding) as probe:
                probe.read()
            return encoding
        except (UnicodeDecodeError, UnicodeError):
            continue
    return "latin-1"


def _has_header(file_path: str, encoding: str) -> bool:
    with open(file_path, encoding=encoding, newline="") as f:
        first_row = next(csv.reader(f), [])
    first_cell = first_row[0].strip().lower() if first_row else ""
    known_headers = {
        "prefetch_file",
        "sourcefilename",
        "source filename",
        "filename",
        "file name",
    }
    return first_cell in known_headers or not first_cell.endswith(".pf")


def _normalise_process_name(value: str) -> str:
    return value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].strip()


def parse(
    file_path: str,
    verbose: bool = False,
    exclude_processes: set[str] | list[str] | tuple[str, ...] | None = None,
    dedup_seconds: int = 5,
) -> list[Event]:
    """Parse a Prefetch CSV export into program_execution events.

    Supports the controlled VM export without a header using these fields:
    prefetch_file, created_time, modified_time, file_size, process_name,
    process_path, run_count, last_run_times, missing_process.
    Headered PECmd/WinPrefetchView-style exports remain supported.
    """
    events: list[Event] = []
    encoding = _detect_encoding(file_path)
    has_header = _has_header(file_path, encoding)
    excluded = {p.upper() for p in (exclude_processes or DEFAULT_EXCLUDED_PROCESSES)}
    seen_by_process: dict[str, list[datetime]] = {}

    with open(file_path, encoding=encoding, newline="") as f:
        reader = csv.DictReader(f, fieldnames=None if has_header else HEADERLESS_FIELDS)

        for row in reader:
            row = {k.lower().strip(): v for k, v in row.items() if k is not None}
            try:
                process_name = _normalise_process_name(_get(
                    row,
                    "process_name",
                    "executablename",
                    "executable name",
                    "process exe",
                    "filename",
                ))
                if not process_name:
                    if verbose:
                        print(f"[WARN] Skipping row in {file_path}: missing process name")
                    continue

                if process_name.upper() in excluded:
                    if verbose:
                        print(f"[INFO] Excluding configured system process: {process_name}")
                    continue

                raw_last_runs = _get(
                    row,
                    "last_run_times",
                    "run times",
                    "lastrun",
                    "last run time",
                    "last run",
                    "timestamp",
                )
                if not raw_last_runs:
                    if verbose:
                        print(f"[WARN] Skipping row in {file_path}: missing last run time")
                    continue

                timestamps = sorted(_parse_timestamps(raw_last_runs))
                process_key = process_name.upper()
                seen = seen_by_process.setdefault(process_key, [])

                run_count_raw = _get(row, "run_count", "runcount", "run count")
                run_count_clean = run_count_raw.replace(",", "")
                run_count = int(run_count_clean) if run_count_clean.isdigit() else None
                pf_file = _get(row, "prefetch_file", "sourcefilename", "sourcefile")
                process_path = _get(row, "process_path", "full path")

                for timestamp in timestamps:
                    if any(abs((timestamp - prev).total_seconds()) <= dedup_seconds for prev in seen):
                        continue
                    seen.append(timestamp)

                    events.append(Event(
                        timestamp=timestamp,
                        source="prefetch",
                        event_type="program_execution",
                        description=f"{process_name} executed",
                        raw_data={
                            "prefetch_file": pf_file,
                            "pf_file": pf_file,
                            "created_time": _get(row, "created_time", "created time"),
                            "modified_time": _get(row, "modified_time", "modified time"),
                            "file_size": _get(row, "file_size", "file size"),
                            "process_name": process_name,
                            "process_path": process_path,
                            "executable": process_name,
                            "run_count": run_count,
                            "missing_process": _get(row, "missing_process", "extra"),
                            "hash": _get(row, "hash"),
                            "source_file": file_path,
                        },
                    ))

            except (ValueError, KeyError) as e:
                if verbose:
                    print(f"[WARN] Skipping row in {file_path}: {e}")
                continue

    return sorted(events, key=lambda e: e.timestamp)
