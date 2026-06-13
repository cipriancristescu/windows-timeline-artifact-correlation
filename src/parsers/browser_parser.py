import csv
from datetime import datetime
from urllib.parse import unquote, urlparse
from src.models.event import Event


# Timestamp formats commonly found in browser history CSV exports.
# BrowsingHistoryView (NirSoft) uses a localized format; manual exports
# from browser DevTools or extensions typically use ISO 8601.
TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",        # BrowsingHistoryView default
    "%Y-%m-%dT%H:%M:%S",        # ISO 8601 without timezone
    "%Y-%m-%dT%H:%M:%S.%fZ",    # ISO 8601 with microseconds (UTC)
    "%Y-%m-%dT%H:%M:%SZ",       # ISO 8601 without microseconds (UTC)
    "%m/%d/%Y %H:%M:%S",        # US locale format 24h
    "%m/%d/%Y %I:%M:%S %p",    # US locale format 12h AM/PM (NirSoft BrowsingHistoryView)
]


def _parse_timestamp(value: str) -> datetime:
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {value!r}")


def _get(row: dict, *keys: str) -> str:
    """Return the first non-empty value found among the given keys."""
    for key in keys:
        value = row.get(key, "").strip()
        if value:
            return value
    return ""


def _build_description(url: str, title: str) -> str:
    if title:
        return f"Browser visit: {url} ({title})"
    return f"Browser visit: {url}"


def _extract_domain(url: str) -> str:
    """Return the hostname of a URL, or an empty string if unparseable."""
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def _extract_local_path(url: str) -> str:
    """Return a local filesystem path from a file:// URL."""
    parsed = urlparse(url)
    path = unquote(parsed.path or "")
    if parsed.netloc and parsed.netloc.lower() != "localhost":
        path = f"//{parsed.netloc}{path}"
    if len(path) >= 3 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return path.replace("/", "\\")


def parse(file_path: str, verbose: bool = False) -> list[Event]:
    """Parse a CSV export of browser history into a list of Events.

    Supports exports from:
    - BrowsingHistoryView (NirSoft): URL, Title, Visit Time, Web Browser
    - Chrome/Edge JSON-to-CSV conversions: url, title, time_usec
    - Generic browser history exports with common column names

    Each row produces one Event representing a single URL visit.
    Rows with a missing or unparseable timestamp are skipped.
    Rows with a missing URL are skipped — a visit event without a URL
    has no forensic meaning.
    """
    events = []

    for encoding in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            with open(file_path, encoding=encoding) as _probe:
                _probe.read()
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    else:
        encoding = "latin-1"

    with open(file_path, encoding=encoding) as f:
        reader = csv.DictReader(f)

        for original_row in reader:
            raw_columns = {k: v for k, v in original_row.items() if k is not None}
            row = {k.lower().strip(): v for k, v in raw_columns.items()}

            try:
                raw_timestamp = _get(row, "visit time", "visited time", "timestamp",
                                     "time", "date", "visit_time")
                if not raw_timestamp:
                    if verbose:
                        print(f"[WARN] Skipping row in {file_path}: missing timestamp")
                    continue
                timestamp = _parse_timestamp(raw_timestamp)

                url = _get(row, "url", "address", "page url")
                if not url:
                    if verbose:
                        print(f"[WARN] Skipping row in {file_path}: missing URL")
                    continue

                title = _get(row, "title", "page title", "pagetitle")
                browser = _get(row, "web browser", "browser", "browser name", "browsername")
                lower_url = url.lower()

                if lower_url.startswith(("http://", "https://")):
                    event_type = "browser_visit"
                    domain = _extract_domain(url)
                    local_path = ""
                elif lower_url.startswith("file://"):
                    event_type = "local_file_access"
                    domain = ""
                    local_path = _extract_local_path(url)
                else:
                    if verbose:
                        print(f"[WARN] Skipping row in {file_path}: unsupported URL scheme")
                    continue

                raw_data = dict(raw_columns)
                raw_data.update({
                    "url": url,
                    "title": title,
                    "domain": domain,
                    "local_path": local_path,
                    "browser": browser,
                    # Traceability: which CSV file this event was parsed from.
                    "source_file": file_path,
                })

                events.append(Event(
                    timestamp=timestamp,
                    source="browser",
                    event_type=event_type,
                    description=_build_description(url, title),
                    raw_data=raw_data,
                ))

            except (ValueError, KeyError) as e:
                # print(f"[WARN] Skipping row in {file_path}: {e}")
                if verbose:
                    print(f"[WARN] Skipping row in {file_path}: {e}")
                continue

    return events
