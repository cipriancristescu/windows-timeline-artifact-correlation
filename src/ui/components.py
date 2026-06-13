"""
Reusable rendering helpers for the Timeline Reconstruction UI.
No backend logic here — only display functions.
"""
import json
import streamlit as st
import pandas as pd
from src.models.event import Event
from src.models.event_group import EventGroup
from src.models.correlation_finding import CorrelationFinding


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_LABEL = {
    "browser":  "Browser",
    "mft":      "MFT",
    "prefetch": "Prefetch",
}

SOURCE_COLOR = {
    "browser":  "#1a73e8",
    "mft":      "#34a853",
    "prefetch": "#b45309",
}

RULE_LABEL = {
    "cross_source_confirmation":   "Cross-source confirmation",
    "same_executable_correlation": "Same executable",
    "download_correlation":        "Download detected",
    "download_and_execution":      "Download + execution",
    "search_then_action":          "Search then local action",
    "local_file_workflow":         "Local file workflow",
}


# ---------------------------------------------------------------------------
# Small reusable pieces
# ---------------------------------------------------------------------------

def source_badge(source: str) -> str:
    """Return a colored text-only HTML badge for a source label."""
    label = SOURCE_LABEL.get(source, source.upper())
    color = SOURCE_COLOR.get(source, "#888")
    return (
        f'<span style="background:{color}18; color:{color}; '
        f'border:1px solid {color}66; border-radius:3px; '
        f'padding:1px 7px; font-size:0.75rem; font-weight:700; '
        f'letter-spacing:0.03em; margin-right:4px;">{label}</span>'
    )


def confidence_badge(confidence: str) -> str:
    if confidence == "HIGH":
        return (
            '<span style="background:#e6f4ea; color:#1e7e34; '
            'border:1px solid #a8d5b5; border-radius:3px; '
            'padding:1px 8px; font-size:0.75rem; font-weight:700; '
            'letter-spacing:0.03em;">HIGH</span>'
        )
    if confidence == "MEDIUM":
        return (
            '<span style="background:#fff3e0; color:#b45309; '
            'border:1px solid #fcd38466; border-radius:3px; '
            'padding:1px 8px; font-size:0.75rem; font-weight:700; '
            'letter-spacing:0.03em;">MEDIUM</span>'
        )
    return (
        '<span style="background:#f5f5f5; color:#666; '
        'border:1px solid #d1d5db; border-radius:3px; '
        'padding:1px 8px; font-size:0.75rem; font-weight:600; '
        'letter-spacing:0.03em;">LOW</span>'
    )


def format_time_range(events: list[Event]) -> str:
    if not events:
        return "—"
    ts = sorted(e.timestamp for e in events)
    if ts[0].date() == ts[-1].date():
        return (
            f"{ts[0].strftime('%H:%M:%S')} – {ts[-1].strftime('%H:%M:%S')}"
            f"  ({ts[0].strftime('%Y-%m-%d')})"
        )
    return f"{ts[0].strftime('%Y-%m-%d %H:%M:%S')} – {ts[-1].strftime('%Y-%m-%d %H:%M:%S')}"


def _compact_time_range(events: list[Event]) -> str:
    """Short form for the overview metric card — avoids truncation."""
    if not events:
        return "—"
    ts = sorted(e.timestamp for e in events)
    if ts[0].date() == ts[-1].date():
        return (
            f"{ts[0].strftime('%H:%M')} – {ts[-1].strftime('%H:%M')}"
            f"\n({ts[0].strftime('%Y-%m-%d')})"
        )
    return (
        f"{ts[0].strftime('%Y-%m-%d')}\n– {ts[-1].strftime('%Y-%m-%d')}"
    )


# ---------------------------------------------------------------------------
# Overview metrics bar
# ---------------------------------------------------------------------------

def render_overview(groups: list[EventGroup]) -> None:
    all_events = [e for g in groups for e in g.events]
    total_findings = sum(len(g.findings) for g in groups)
    high_count = sum(1 for g in groups if g.confidence == "HIGH")
    med_count  = sum(1 for g in groups if g.confidence == "MEDIUM")

    c1, c2, c3, c4, c5, c6 = st.columns([1, 1, 1, 1.25, 1.35, 2.1])
    c1.metric("Events",          len(all_events))
    c2.metric("Groups",          len(groups))
    c3.metric("Findings",        total_findings)
    c4.metric("HIGH confidence", high_count)
    c5.metric("MEDIUM confidence", med_count)
    c6.metric("Time range",      _compact_time_range(all_events))


# ---------------------------------------------------------------------------
# All-events table
# ---------------------------------------------------------------------------

def _build_events_df(groups: list[EventGroup]) -> pd.DataFrame:
    """Convert a list of groups into a flat sorted DataFrame."""
    rows = []
    for group_idx, group in enumerate(groups):
        for event in group.events:
            rows.append({
                "Timestamp":   event.timestamp,
                "Role":        event.raw_data.get("role", "support"),
                "Family":      event.raw_data.get("activity_family_estimate", ""),
                "Source":      SOURCE_LABEL.get(event.source, event.source.upper()),
                "Type":        event.event_type,
                "Description": event.description,
                "Group":       group_idx + 1,
                "Confidence":  group.confidence,
            })
    if not rows:
        return pd.DataFrame(columns=["Timestamp", "Role", "Family", "Source", "Type",
                                     "Description", "Group", "Confidence"])
    df = pd.DataFrame(rows).sort_values("Timestamp").reset_index(drop=True)
    df["Timestamp"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df


def _build_all_events_df(events: list[Event], groups: list[EventGroup]) -> pd.DataFrame:
    group_lookup = {}
    for group_idx, group in enumerate(groups):
        for event in group.events:
            group_lookup[id(event)] = (group_idx + 1, group.confidence)

    rows = []
    for event in events:
        group_idx, confidence = group_lookup.get(id(event), ("", ""))
        rows.append({
            "Timestamp":   event.timestamp,
            "Role":        event.raw_data.get("role", "support"),
            "Family":      event.raw_data.get("activity_family_estimate", ""),
            "Source":      SOURCE_LABEL.get(event.source, event.source.upper()),
            "Type":        event.event_type,
            "Description": event.description,
            "Group":       group_idx,
            "Confidence":  confidence,
        })

    if not rows:
        return pd.DataFrame(columns=["Timestamp", "Role", "Family", "Source", "Type",
                                     "Description", "Group", "Confidence"])
    df = pd.DataFrame(rows).sort_values("Timestamp").reset_index(drop=True)
    df["Timestamp"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df


def render_all_events_table(
    all_groups: list[EventGroup],
    visible_groups: list[EventGroup],
    all_events: list[Event] | None = None,
) -> None:
    """Render the events table with scope toggle and lightweight inline filters."""

    # --- Scope toggle ---
    scope = st.radio(
        "Show events from",
        options=["Visible groups only", "All filtered events"],
        index=0,
        horizontal=True,
        help=(
            "'Visible groups only' respects the display filters set in the sidebar. "
            "'All filtered events' shows everything that passed the pipeline filter."
        ),
    )
    if scope == "Visible groups only":
        df = _build_events_df(visible_groups)
    elif all_events is not None:
        df = _build_all_events_df(all_events, all_groups)
    else:
        df = _build_events_df(all_groups)

    if df.empty:
        st.info("No events to display.")
        return

    # --- Inline table filters ---
    fc1, fc2, fc3 = st.columns([1, 1, 2])

    all_sources = sorted(df["Source"].unique())
    selected_sources = fc1.multiselect(
        "Source", options=all_sources, default=all_sources, key="evt_src_filter"
    )

    all_types = sorted(df["Type"].unique())
    selected_types = fc2.multiselect(
        "Event type", options=all_types, default=all_types, key="evt_type_filter"
    )

    search_text = fc3.text_input(
        "Search description", value="", placeholder="e.g. cmd.exe", key="evt_search"
    )

    # Apply filters to the DataFrame — pipeline is not touched
    mask = (
        df["Source"].isin(selected_sources)
        & df["Type"].isin(selected_types)
    )
    if search_text.strip():
        mask &= df["Description"].str.contains(search_text.strip(), case=False, na=False)
    df_view = df[mask].reset_index(drop=True)

    st.dataframe(
        df_view,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Timestamp":   st.column_config.TextColumn("Timestamp",   width="medium"),
            "Role":        st.column_config.TextColumn("Role",        width="small"),
            "Family":      st.column_config.TextColumn("Family",      width="medium"),
            "Source":      st.column_config.TextColumn("Source",      width="small"),
            "Type":        st.column_config.TextColumn("Type",        width="medium"),
            "Description": st.column_config.TextColumn("Description", width="large"),
            "Group":       st.column_config.NumberColumn("Group",     width="small"),
            "Confidence":  st.column_config.TextColumn("Confidence",  width="small"),
        },
    )

    total = len(df_view)
    note = f"{total} event{'s' if total != 1 else ''}"
    if len(df_view) < len(df):
        note += f" (filtered from {len(df)})"
    st.caption(note)


# ---------------------------------------------------------------------------
# Finding rendering
# ---------------------------------------------------------------------------

def _render_findings(findings: list[CorrelationFinding]) -> None:
    if not findings:
        st.caption("No findings for this group.")
        return

    for f in findings:
        label = RULE_LABEL.get(f.rule_name, f.rule_name)
        with st.container():
            st.markdown(f"**{label}**")
            st.markdown(
                f"<span style='color:#444; font-size:0.9rem'>{f.explanation}</span>",
                unsafe_allow_html=True,
            )
            if f.matched_sources:
                badges = "".join(source_badge(s) for s in f.matched_sources)
                st.markdown(badges, unsafe_allow_html=True)
            if f.matched_entities:
                st.markdown(
                    "<span style='font-size:0.8rem; color:#888'>"
                    + " · ".join(f.matched_entities[:5])
                    + "</span>",
                    unsafe_allow_html=True,
                )
            st.markdown("<hr style='margin:6px 0; border-color:#eee'>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Timeline (vertical event list)
# ---------------------------------------------------------------------------

def _render_timeline(events: list[Event]) -> None:
    for event in sorted(events, key=lambda e: e.timestamp):
        color = SOURCE_COLOR.get(event.source, "#888")
        time_str = event.timestamp.strftime("%H:%M:%S")
        badge_html = source_badge(event.source)

        st.markdown(
            f"""<div style="display:flex; align-items:flex-start; gap:10px;
                            margin-bottom:8px; padding:8px 10px;
                            background:#fafafa; border-left:3px solid {color};
                            border-radius:4px;">
                <span style="font-family:monospace; font-size:0.85rem;
                              color:#555; white-space:nowrap; padding-top:2px;">
                    {time_str}
                </span>
                <div>
                    {badge_html}
                    <span style="font-size:0.88rem; color:#222;">
                        {event.description}
                    </span>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Group events table (compact, inside expander)
# ---------------------------------------------------------------------------

def _render_group_events_table(events: list[Event]) -> None:
    rows = [
        {
            "Time":        e.timestamp.strftime("%H:%M:%S"),
            "Role":        e.raw_data.get("role", "support"),
            "Family":      e.raw_data.get("activity_family_estimate", ""),
            "Source":      SOURCE_LABEL.get(e.source, e.source.upper()),
            "Type":        e.event_type,
            "Description": e.description,
        }
        for e in sorted(events, key=lambda e: e.timestamp)
    ]
    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Time":        st.column_config.TextColumn("Time",        width="small"),
            "Role":        st.column_config.TextColumn("Role",        width="small"),
            "Family":      st.column_config.TextColumn("Family",      width="medium"),
            "Source":      st.column_config.TextColumn("Source",      width="small"),
            "Type":        st.column_config.TextColumn("Type",        width="medium"),
            "Description": st.column_config.TextColumn("Description", width="large"),
        },
    )


# ---------------------------------------------------------------------------
# Raw data section
# ---------------------------------------------------------------------------

def _render_raw_data(events: list[Event]) -> None:
    for event in sorted(events, key=lambda e: e.timestamp):
        st.markdown(
            f"**{event.timestamp.strftime('%H:%M:%S')}** &nbsp;·&nbsp; "
            f"`{SOURCE_LABEL.get(event.source, event.source)}`",
            unsafe_allow_html=True,
        )
        if event.raw_data:
            st.json(event.raw_data, expanded=False)
        else:
            st.caption("No raw data.")
        st.markdown("")


# ---------------------------------------------------------------------------
# Session metadata helpers
# ---------------------------------------------------------------------------

def _applications_involved(events: list[Event]) -> list[str]:
    return sorted({e.application for e in events if e.application != "unknown"})


def _core_events(events: list[Event]) -> list[Event]:
    return [e for e in events if e.raw_data.get("role") == "core"]


def _support_events(events: list[Event]) -> list[Event]:
    return [e for e in events if e.raw_data.get("role") != "core"]


def _activity_families(events: list[Event]) -> list[str]:
    """Return sorted list of distinct known activity families in the group."""
    return sorted({e.activity_family for e in events if e.activity_family != "unknown"})


# ---------------------------------------------------------------------------
# Group summary sentence
# ---------------------------------------------------------------------------

def _build_summary(group: EventGroup) -> str:
    sources = sorted({e.source for e in group.events})
    rule_names = [f.rule_name for f in group.findings]

    if group.short_title and group.short_title != "Activity group":
        return group.short_title
    if "download_and_execution" in rule_names:
        return "A file was likely downloaded and executed during this session."
    if "download_correlation" in rule_names:
        return "A file download appears to have occurred during this session."
    if "search_then_action" in rule_names:
        return "A web search was followed by local file or program activity."
    if "local_file_workflow" in rule_names:
        return "A program was used alongside related local file activity."
    if "cross_source_confirmation" in rule_names:
        return f"Activity confirmed by multiple sources: {', '.join(sources)}."
    if sources:
        return f"Activity recorded from: {', '.join(sources)}."
    return "Activity recorded in this time window."


# ---------------------------------------------------------------------------
# Full group card
# ---------------------------------------------------------------------------

def render_group(group: EventGroup, index: int) -> None:
    sources = sorted({e.source for e in group.events})
    core_events = _core_events(group.events)
    support_events = _support_events(group.events)
    display_events = core_events or group.events
    time_range = format_time_range(display_events)
    finding_count = len(group.findings)

    badges_html = "".join(source_badge(s) for s in sources)
    conf_html = confidence_badge(group.confidence)

    finding_hint = (
        f"  ·  {finding_count} finding{'s' if finding_count != 1 else ''}"
        if finding_count else ""
    )
    title = group.short_title or "Activity group"
    label = (
        f"Group {index + 1}  ·  {title}  ·  "
        f"{group.core_event_count} core / {group.support_event_count} support  ·  "
        f"{time_range}{finding_hint}"
    )

    apps = group.important_apps or _applications_involved(core_events)
    families     = _activity_families(group.events)

    app_hint = (
        f"&nbsp;·&nbsp;<span style='font-size:0.78rem; color:#555;'>"
        f"apps: <b>{', '.join(apps)}</b></span>"
        if apps else ""
    )
    family_hint = (
        f"&nbsp;·&nbsp;<span style='font-size:0.78rem; color:#888;'>"
        + " / ".join(families)
        + "</span>"
        if families else ""
    )

    with st.expander(label, expanded=False):
        st.markdown(
            f"{conf_html}&nbsp;&nbsp;{badges_html}{app_hint}{family_hint}",
            unsafe_allow_html=True,
        )
        c1, c2, c3, c4, c5 = st.columns([2, 1.2, 1, 1, 2])
        c1.caption(f"Interval: {time_range}")
        c2.caption(f"Sources: {', '.join(sources)}")
        c3.caption(f"Confidence: {group.confidence}")
        c4.caption(f"Events: {group.core_event_count} core, {group.support_event_count} support")
        c5.caption(f"Applications: {', '.join(apps) if apps else 'unknown'}")
        st.caption(f"Activity family estimate: {group.activity_family_estimate}")
        st.markdown(
            f"<p style='color:#555; font-size:0.88rem; margin:6px 0 14px 0;'>"
            f"{_build_summary(group)}</p>",
            unsafe_allow_html=True,
        )

        tab_findings, tab_timeline, tab_support, tab_table, tab_raw = st.tabs(
            ["Findings", "Core events", "Supporting/noise events", "Events table", "Raw data"]
        )

        with tab_findings:
            _render_findings(group.findings)
        with tab_timeline:
            _render_timeline(core_events)
        with tab_support:
            if support_events:
                _render_group_events_table(support_events)
            else:
                st.caption("No supporting/noise events attached to this group.")
        with tab_table:
            _render_group_events_table(group.events)
        with tab_raw:
            _render_raw_data(group.events)


# ---------------------------------------------------------------------------
# Export section
# ---------------------------------------------------------------------------

def render_export_section(
    output_dir: str,
    groups: list[EventGroup],
    input_dir: str = "",
    run_time=None,
    analyzed_files: list[str] | None = None,
) -> None:
    """Render download buttons for the current run's output.

    Downloads are always generated from the in-memory `groups` produced by
    the current analysis run — stale files on disk are never served.
    The run is also persisted to a timestamped sub-folder inside output_dir.
    """
    import os
    import csv
    import io
    from datetime import datetime as _dt

    analyzed_files = analyzed_files or []
    exported_at = (run_time or _dt.now()).isoformat(timespec="seconds")
    input_basename = os.path.basename(os.path.normpath(input_dir)) if input_dir else "unknown"

    # --- Run info header ---
    st.markdown("#### Export results")
    run_label = f"`{input_dir}`" if input_dir else "—"
    ts_label  = exported_at.replace("T", " ")
    st.markdown(
        f"<div style='background:#f0f4ff; border:1px solid #c7d2fe; border-radius:6px; "
        f"padding:8px 14px; margin-bottom:12px; font-size:0.85rem; color:#3730a3;'>"
        f"<b>Current run</b> &nbsp;·&nbsp; input: {run_label}"
        f"&nbsp;·&nbsp; analyzed at: <b>{ts_label}</b>"
        + (f"&nbsp;·&nbsp; files: {', '.join(analyzed_files)}" if analyzed_files else "")
        + "</div>",
        unsafe_allow_html=True,
    )

    # --- In-memory generators (always from current groups) ---

    meta = {
        "exported_at":     exported_at,
        "input_dir":       input_dir,
        "analyzed_files":  analyzed_files,
        "event_count":     sum(len(g.events) for g in groups),
        "group_count":     len(groups),
    }

    def _make_timeline_json() -> bytes:
        records = []
        for group in groups:
            for e in group.events:
                records.append({
                    "timestamp":       e.timestamp.isoformat(),
                    "source":          e.source,
                    "event_type":      e.event_type,
                    "description":     e.description,
                    "application":     e.application,
                    "activity_family": e.activity_family,
                    "activity_family_estimate": e.raw_data.get("activity_family_estimate", ""),
                    "role":            e.raw_data.get("role", ""),
                    "raw_data":        e.raw_data,
                })
        records.sort(key=lambda r: r["timestamp"])
        return json.dumps({"meta": meta, "events": records}, indent=2).encode("utf-8")

    def _make_timeline_csv() -> bytes:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=["timestamp", "source", "event_type",
                             "role", "activity_family_estimate",
                             "application", "activity_family", "description", "raw_data"]
        )
        writer.writeheader()
        rows = []
        for group in groups:
            for e in group.events:
                rows.append({
                    "timestamp":       e.timestamp.isoformat(),
                    "source":          e.source,
                    "event_type":      e.event_type,
                    "role":            e.raw_data.get("role", ""),
                    "activity_family_estimate": e.raw_data.get("activity_family_estimate", ""),
                    "application":     e.application,
                    "activity_family": e.activity_family,
                    "description":     e.description,
                    "raw_data":        json.dumps(e.raw_data) if e.raw_data else "",
                })
        rows.sort(key=lambda r: r["timestamp"])
        writer.writerows(rows)
        return buf.getvalue().encode("utf-8")

    def _make_groups_json() -> bytes:
        records = []
        for group in groups:
            records.append({
                "confidence":  group.confidence,
                "event_count": len(group.events),
                "core_event_count": group.core_event_count,
                "support_event_count": group.support_event_count,
                "primary_activity": group.primary_activity,
                "activity_family_estimate": group.activity_family_estimate,
                "important_apps": group.important_apps,
                "short_title": group.short_title,
                "sources":     sorted({e.source for e in group.events}),
                "findings": [
                    {
                        "rule_name":        f.rule_name,
                        "explanation":      f.explanation,
                        "matched_sources":  f.matched_sources,
                        "matched_entities": f.matched_entities,
                    }
                    for f in group.findings
                ],
                "events": [
                    {
                        "timestamp":       e.timestamp.isoformat(),
                        "source":          e.source,
                        "event_type":      e.event_type,
                        "role":            e.raw_data.get("role", ""),
                        "activity_family_estimate": e.raw_data.get("activity_family_estimate", ""),
                        "application":     e.application,
                        "activity_family": e.activity_family,
                        "description":     e.description,
                        "raw_data":        e.raw_data,
                    }
                    for e in group.events
                ],
            })
        return json.dumps({"meta": meta, "groups": records}, indent=2).encode("utf-8")

    # --- Build all payloads once so we can both download and write to disk ---
    run_ts = (run_time or _dt.now()).strftime("%Y-%m-%d_%H-%M-%S")
    run_subdir = os.path.join(output_dir, f"{input_basename}_{run_ts}")

    payloads = [
        ("timeline.json",        "application/json", _make_timeline_json()),
        ("timeline.csv",         "text/csv",         _make_timeline_csv()),
        ("timeline_groups.json", "application/json", _make_groups_json()),
    ]

    # Write per-run copies to disk (best-effort; never blocks the UI).
    try:
        os.makedirs(run_subdir, exist_ok=True)
        for filename, _, data in payloads:
            with open(os.path.join(run_subdir, filename), "wb") as fh:
                fh.write(data)
    except OSError:
        pass

    # --- Download buttons (always in-memory, never from stale disk files) ---
    cols = st.columns(len(payloads))
    for col, (filename, mime, data) in zip(cols, payloads):
        col.download_button(
            label=f"Download {filename}",
            data=data,
            file_name=filename,
            mime=mime,
            use_container_width=True,
        )
