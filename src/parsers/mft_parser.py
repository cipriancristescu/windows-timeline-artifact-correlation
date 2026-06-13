import csv
from datetime import datetime, timedelta
from src.models.event import Event


TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%m/%d/%Y %H:%M:%S",
]

DEFAULT_RELEVANT_PATHS = (
    r"Users\crist\Desktop\licenta_vm_test",
    r"Users\crist\Downloads",
    r"Users\crist\AppData\Roaming\Microsoft\Windows\Recent",
)

MFT_TIME_OFFSET = timedelta(hours=3)


def _normalise_timestamp_value(value: str) -> str:
    value = value.strip()
    if "." not in value:
        return value
    head, tail = value.split(".", 1)
    suffix = ""
    if tail.endswith("Z"):
        tail = tail[:-1]
        suffix = "Z"
    if len(tail) > 6:
        tail = tail[:6]
    return f"{head}.{tail}{suffix}"


def _parse_timestamp(value: str) -> datetime:
    value = _normalise_timestamp_value(value)
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt) + MFT_TIME_OFFSET
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {value!r}")


def _get(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key, "")
        if value is None:
            continue
        value = value.strip()
        if value:
            return value
    return ""


def _normalise_path(path: str) -> str:
    path = (path or "").strip().replace("/", "\\")
    while path.startswith(".\\"):
        path = path[2:]
    if path == ".":
        return ""
    return path.lstrip("\\")


def _build_file_path(row: dict) -> str:
    parent = _normalise_path(_get(row, "parentpath", "parent path", "parent"))
    filename = _get(row, "filename", "file name", "name")
    if parent and filename:
        return parent.rstrip("\\") + "\\" + filename
    return filename or parent


def _is_directory(row: dict) -> bool:
    return _get(row, "isdirectory", "is directory").lower() == "true"


def _is_zone_identifier(path: str) -> bool:
    return path.lower().endswith(":zone.identifier") or "zone.identifier" in path.lower()


def _is_relevant_path(path: str, relevant_paths: tuple[str, ...]) -> bool:
    path_l = _normalise_path(path).lower()
    return any(_normalise_path(p).lower() in path_l for p in relevant_paths)


def _extension(row: dict, file_path: str) -> str:
    ext = _get(row, "extension")
    if ext:
        return ext if ext.startswith(".") else f".{ext.lower()}"
    filename = file_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""


def parse(
    file_path: str,
    verbose: bool = False,
    include_directories: bool = False,
    relevant_paths: tuple[str, ...] | list[str] | None = None,
) -> list[Event]:
    """Parse MFTECmd CSV rows into file_created and file_modified events."""
    events: list[Event] = []
    relevant = tuple(relevant_paths or DEFAULT_RELEVANT_PATHS)

    with open(file_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            row = {k.lower().strip(): v for k, v in row.items() if k is not None}

            try:
                full_path = _build_file_path(row)
                if not full_path:
                    if verbose:
                        print(f"[WARN] Skipping row in {file_path}: missing file path")
                    continue
                if _is_zone_identifier(full_path):
                    continue
                if _is_directory(row) and not include_directories:
                    continue
                if relevant and not _is_relevant_path(full_path, relevant):
                    continue

                raw_created = _get(row, "created0x10", "created", "std info creation date", "creation date")
                raw_modified = _get(row, "lastmodified0x10", "lastmodified", "last modified",
                                    "std info modification date", "modified")
                raw_accessed = _get(row, "lastaccess0x10", "lastaccess", "last access",
                                    "std info access date")
                raw_entry_mod = _get(row, "lastrecordchange0x10", "lastrecordchange",
                                     "std info entry date", "entry modified")
                filename_only = _get(row, "filename", "file name", "name")
                extension = _extension(row, full_path)

                def _try_parse(raw: str) -> str:
                    if not raw:
                        return ""
                    try:
                        return _parse_timestamp(raw).isoformat()
                    except ValueError:
                        return ""

                base_raw = {
                    "file_path": full_path,
                    "filename": filename_only,
                    "extension": extension,
                    "is_directory": _is_directory(row),
                    "ts_created": _try_parse(raw_created),
                    "ts_modified": _try_parse(raw_modified),
                    "ts_accessed": _try_parse(raw_accessed),
                    "ts_entry_mod": _try_parse(raw_entry_mod),
                    "source_file": file_path,
                }

                for event_type, raw_ts, label in (
                    ("file_created", raw_created, "File created"),
                    ("file_modified", raw_modified, "File modified"),
                ):
                    if not raw_ts:
                        continue
                    events.append(Event(
                        timestamp=_parse_timestamp(raw_ts),
                        source="mft",
                        event_type=event_type,
                        description=f"{label}: {full_path}",
                        raw_data={**base_raw, "mft_timestamp_field": event_type},
                    ))

            except (ValueError, KeyError) as e:
                if verbose:
                    print(f"[WARN] Skipping row in {file_path}: {e}")
                continue

    return sorted(events, key=lambda e: e.timestamp)
