import argparse
import os
from datetime import datetime

from src.parsers import prefetch_parser, mft_parser, browser_parser
from src.correlator.timeline_builder import build_timeline, build_sessions
from src.correlator.event_filter import filter_events
from src.correlator.event_normalizer import normalize_events
from src.correlator.event_correlator import correlate_all
from src.utils.exporter import export_json, export_csv, export_groups_json
from src.models.event import Event


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO 8601 datetime string from the CLI."""
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid datetime: {value!r}. Expected ISO 8601 format, e.g. 2024-03-10T08:00:00"
        )


def load_events(input_dir: str, verbose: bool = False) -> list[Event]:
    """Scan input_dir and route each CSV file to the appropriate parser.

    Routing is based on filename for Browser History, Prefetch, and MFT CSV exports.
    """
    events: list[Event] = []

    try:
        filenames = sorted(os.listdir(input_dir))
    except FileNotFoundError:
        print(f"Input folder not found: {input_dir}")
        return events

    for filename in filenames:
        if not filename.lower().endswith(".csv"):
            continue

        file_path = os.path.join(input_dir, filename)
        name = filename.lower()

        if "prefetch" in name:
            parsed = prefetch_parser.parse(file_path, verbose=verbose)
            print(f"  [prefetch] {filename} -> {len(parsed)} events")
        elif "mft" in name:
            parsed = mft_parser.parse(file_path, verbose=verbose)
            print(f"  [mft]      {filename} -> {len(parsed)} events")
        elif "browser" in name:
            parsed = browser_parser.parse(file_path, verbose=verbose)
            print(f"  [browser]  {filename} -> {len(parsed)} events")
        else:
            print(f"  [skipped]  {filename} (no matching parser)")
            continue

        events.extend(parsed)

    return events


def main():
    arg_parser = argparse.ArgumentParser(
        description="Windows forensic timeline reconstruction tool"
    )
    arg_parser.add_argument(
        "--input",
        default="data/teste",
        help="Path to folder containing exported artifacts (default: data/teste)",
    )
    arg_parser.add_argument(
        "--output",
        default="data/output",
        help="Path to folder where timeline files will be written (default: data/output)",
    )
    arg_parser.add_argument(
        "--window",
        type=int,
        default=4,
        help="Deprecated; grouping now uses a fixed 4-minute core-event gap",
    )
    arg_parser.add_argument(
        "--sources",
        nargs="+",
        metavar="SOURCE",
        help="Only include events from these sources, e.g. --sources prefetch browser mft",
    )
    arg_parser.add_argument(
        "--start",
        type=_parse_datetime,
        metavar="DATETIME",
        help="Only include events at or after this time, e.g. --start 2024-03-10T08:00:00",
    )
    arg_parser.add_argument(
        "--end",
        type=_parse_datetime,
        metavar="DATETIME",
        help="Only include events at or before this time, e.g. --end 2024-03-10T10:00:00",
    )
    arg_parser.add_argument(
        "--include-paths",
        nargs="+",
        default=[
            r"Users\crist\Desktop\licenta_vm_test",
            r"Users\crist\Downloads",
            r"Users\crist\AppData\Roaming\Microsoft\Windows\Recent",
        ],
        help="Only include file/local-path events matching these path fragments",
    )
    arg_parser.add_argument(
        "--include-extensions",
        nargs="+",
        help="Only include file events with these extensions, e.g. --include-extensions .pdf .lnk",
    )
    arg_parser.add_argument(
        "--exclude-processes",
        nargs="+",
        default=[
            "SVCHOST.EXE", "RUNTIMEBROKER.EXE", "DLLHOST.EXE", "TASKHOSTW.EXE",
            "SEARCHFILTERHOST.EXE", "SEARCHPROTOCOLHOST.EXE",
        ],
        help="Process names to exclude after parsing",
    )
    arg_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print warnings for skipped rows and other debug information",
    )
    args = arg_parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # --- Parse ---
    print(f"Loading artifacts from: {args.input}")
    events = load_events(args.input, verbose=args.verbose)
    print(f"  Total loaded: {len(events)} events")

    if not events:
        print("No events found. Check that the input folder contains prefetch, mft, or browser CSV files.")
        return

    # --- Normalize ---
    normalize_events(events)

    # --- Filter ---
    filtered = filter_events(events, config={
        "sources": args.sources,
        "start": args.start,
        "end": args.end,
        "include_paths": args.include_paths,
        "include_extensions": args.include_extensions,
        "exclude_processes": args.exclude_processes,
    })
    excluded = len(events) - len(filtered)
    print(f"  After filtering: {len(filtered)} events ({excluded} excluded by heuristics)")

    if not filtered:
        print("No events remaining after filtering. Try relaxing --sources, --start, or --end.")
        return

    # --- Build timeline ---
    timeline = build_timeline(filtered)
    groups = build_sessions(timeline)

    # --- Correlate ---
    correlate_all(groups)

    # --- Export ---
    json_path        = os.path.join(args.output, "timeline.json")
    csv_path         = os.path.join(args.output, "timeline.csv")
    groups_json_path = os.path.join(args.output, "timeline_groups.json")
    export_json(timeline, json_path)
    export_csv(timeline, csv_path)
    export_groups_json(groups, groups_json_path)

    # --- Summary ---
    high = sum(1 for g in groups if g.confidence == "HIGH")
    low  = sum(1 for g in groups if g.confidence == "LOW")
    total_findings = sum(len(g.findings) for g in groups)

    print()
    print(f"Events   : {len(timeline)}")
    print(f"Findings : {total_findings}")
    print(f"Groups   : {len(groups)}  (HIGH: {high}  LOW: {low})")
    print(f"Range    : {timeline[0].timestamp} to {timeline[-1].timestamp}")
    print(f"Exported : {json_path}")
    print(f"         : {csv_path}")
    print(f"         : {groups_json_path}")


if __name__ == "__main__":
    main()
