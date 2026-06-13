"""
Windows Timeline Reconstruction Tool — Streamlit UI
Entry point: streamlit run app.py
"""
from datetime import datetime, time

import streamlit as st

from src.correlator.event_correlator import correlate_all
from src.correlator.event_filter import filter_events
from src.correlator.event_normalizer import normalize_events
from src.correlator.timeline_builder import build_sessions, build_timeline
from src.models.event import Event
from src.models.event_group import EventGroup
from src.parsers import browser_parser, mft_parser, prefetch_parser
from src.services.ai_analysis_service import generate_group_analysis, load_ai_config
from src.services.pdf_report_service import generate_pdf_report
from src.ui.components import (
    render_all_events_table,
    render_export_section,
    render_group,
    render_overview,
)


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Timeline Reconstruction",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 2rem; }
    div[data-testid="metric-container"] {
        background: #fafafa;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 12px 16px;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        overflow: visible;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] > div {
        white-space: pre-wrap;
        overflow: visible;
        text-overflow: clip;
        line-height: 1.15;
    }
    .stTabs [data-baseweb="tab"] { font-size: 0.85rem; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Backend helpers
# ---------------------------------------------------------------------------

def _load_events_from_folder(input_dir: str, verbose: bool = False) -> list[Event]:
    """Scan the input folder and route files to the correct parser."""
    import os
    events: list[Event] = []

    try:
        filenames = sorted(os.listdir(input_dir))
    except FileNotFoundError:
        st.error(f"Folder not found: `{input_dir}`")
        return events

    for filename in filenames:
        if not filename.lower().endswith(".csv"):
            continue
        path = os.path.join(input_dir, filename)
        name = filename.lower()

        if "prefetch" in name:
            events.extend(prefetch_parser.parse(path, verbose=verbose))
        elif "mft" in name:
            events.extend(mft_parser.parse(path, verbose=verbose))
        elif "browser" in name:
            events.extend(browser_parser.parse(path, verbose=verbose))

    return events


@st.cache_data(show_spinner=False)
def run_pipeline(
    input_dir: str,
    selected_sources: tuple[str, ...],
    start_dt: datetime | None,
    end_dt: datetime | None,
    include_paths: tuple[str, ...],
    include_extensions: tuple[str, ...],
    exclude_processes: tuple[str, ...],
) -> tuple[list[EventGroup], list[Event]]:
    """Full pipeline: parse → filter → sort → group → correlate."""
    raw = _load_events_from_folder(input_dir)
    normalize_events(raw)
    filtered = filter_events(raw, config={
        "sources": list(selected_sources) if selected_sources else None,
        "start": start_dt,
        "end": end_dt,
        "include_paths": list(include_paths),
        "include_extensions": list(include_extensions),
        "exclude_processes": list(exclude_processes),
    })
    timeline = build_timeline(filtered)
    groups = build_sessions(timeline)
    correlate_all(groups)
    return groups, timeline


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("Windows Timeline Reconstruction Tool")
st.markdown(
    "<p style='color:#555; margin-top:-10px;'>"
    "Forensic artifact analysis — parse, correlate, and explore activity timelines."
    "</p>",
    unsafe_allow_html=True,
)
st.divider()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Configuration")

    input_dir = st.text_input(
        "Artifact folder",
        value="data/teste",
        help="Path to the folder containing exported CSV artifacts.",
    )
    output_dir = st.text_input(
        "Output folder",
        value="data/output",
        help="Path where timeline exports are written (used for download buttons).",
    )

    st.markdown("**Sources to include**")
    src_prefetch = st.checkbox("Prefetch", value=True)
    src_mft      = st.checkbox("MFT",     value=True)
    src_browser  = st.checkbox("Browser", value=True)

    st.markdown("**Time range** *(optional)*")
    use_start  = st.checkbox("Filter start time")
    start_date = st.date_input("Start date", value=None, disabled=not use_start)
    start_time = st.time_input("Start time", value=time(0, 0), disabled=not use_start)

    use_end  = st.checkbox("Filter end time")
    end_date = st.date_input("End date", value=None, disabled=not use_end)
    end_time = st.time_input("End time", value=time(23, 59), disabled=not use_end)

    st.markdown("**Display filters**")
    only_with_findings = st.checkbox("Show only groups with findings")
    only_high          = st.checkbox("Show only HIGH confidence groups")

    st.markdown("**Artifact filters**")
    include_paths_raw = st.text_area(
        "Include paths",
        value=(
            "Users\\crist\\Desktop\\licenta_vm_test\n"
            "Users\\crist\\Downloads\n"
            "Users\\crist\\AppData\\Roaming\\Microsoft\\Windows\\Recent"
        ),
        help="One path fragment per line. Empty keeps every emitted path.",
    )
    include_extensions_raw = st.text_input(
        "Include extensions",
        value="",
        help="Comma-separated list, e.g. .pdf,.docx,.lnk. Empty keeps all extensions.",
    )
    exclude_processes_raw = st.text_input(
        "Exclude processes",
        value="SVCHOST.EXE,RUNTIMEBROKER.EXE,DLLHOST.EXE,TASKHOSTW.EXE,SEARCHFILTERHOST.EXE,SEARCHPROTOCOLHOST.EXE",
        help="Comma-separated process names excluded after parsing.",
    )

    st.markdown("**Grouping**")
    st.caption("Core events only. New group if gap > 4 minutes, or family changes after 90 seconds.")

    analyze = st.button("Analyze Timeline", use_container_width=True, type="primary")


# ---------------------------------------------------------------------------
# Build input values whenever Analyze is pressed
# ---------------------------------------------------------------------------

if analyze:
    selected_sources: tuple[str, ...] = tuple(
        s for s, checked in [
            ("prefetch", src_prefetch),
            ("mft",      src_mft),
            ("browser",  src_browser),
        ]
        if checked
    )

    start_dt: datetime | None = None
    end_dt:   datetime | None = None

    if use_start and start_date:
        start_dt = datetime.combine(start_date, start_time)
    if use_end and end_date:
        end_dt = datetime.combine(end_date, end_time)

    include_paths = tuple(
        line.strip() for line in include_paths_raw.splitlines() if line.strip()
    )
    include_extensions = tuple(
        item.strip() for item in include_extensions_raw.split(",") if item.strip()
    )
    exclude_processes = tuple(
        item.strip() for item in exclude_processes_raw.split(",") if item.strip()
    )

    import os as _os
    run_pipeline.clear()
    with st.spinner("Parsing and analysing artifacts…"):
        groups, filtered_events = run_pipeline(
            input_dir=input_dir,
            selected_sources=selected_sources,
            start_dt=start_dt,
            end_dt=end_dt,
            include_paths=include_paths,
            include_extensions=include_extensions,
            exclude_processes=exclude_processes,
        )

    analyzed_files = sorted(
        f for f in _os.listdir(input_dir) if f.lower().endswith(".csv")
    ) if _os.path.isdir(input_dir) else []

    st.session_state["groups"]         = groups
    st.session_state["filtered_events"] = filtered_events
    st.session_state["output_dir"]     = output_dir
    st.session_state["input_dir"]      = input_dir
    st.session_state["run_time"]       = datetime.now()
    st.session_state["analyzed_files"] = analyzed_files
    st.session_state["analyzed"]       = True
    # Clear stale report/AI results so they don't bleed into the new analysis.
    st.session_state.pop("report_selected_groups", None)
    st.session_state.pop("report_ai_analyses", None)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

if st.session_state.get("analyzed") and "groups" in st.session_state:
    groups: list[EventGroup]   = st.session_state["groups"]
    filtered_events: list[Event] = st.session_state.get("filtered_events", [])
    out_dir: str               = st.session_state.get("output_dir", "data/output")

    if not groups:
        st.warning("No events found. Check the artifact folder and selected sources.")
        st.stop()

    # Apply display filters — these control both the Groups tab and the
    # default scope of the All Events tab.
    visible = groups
    if only_with_findings:
        visible = [g for g in visible if g.findings]
    if only_high:
        visible = [g for g in visible if g.confidence == "HIGH"]

    # --- Overview metrics (always full result set) ---
    st.subheader("Overview")
    render_overview(groups)
    st.markdown("")

    # --- Tabbed results area ---
    tab_groups, tab_events = st.tabs(["Activity Groups", "All Events"])

    with tab_groups:
        filtered_note = ""
        if len(visible) < len(groups):
            filtered_note = f" *(showing {len(visible)} of {len(groups)} after display filters)*"
        st.markdown(f"#### Activity Groups{filtered_note}")

        if not visible:
            st.info("No groups match the current display filters.")
        else:
            selected = st.session_state.setdefault("report_selected_groups", {})
            analyses = st.session_state.setdefault("report_ai_analyses", {})
            ai_config = load_ai_config()

            visible_items = [(idx, group) for idx, group in enumerate(groups) if group in visible]
            for original_idx, group in visible_items:
                include = st.checkbox(
                    "Include in report",
                    key=f"report_include_{original_idx}",
                    value=selected.get(original_idx, False),
                )
                selected[original_idx] = include
                st.session_state["report_selected_groups"] = selected
                if include:
                    if st.button("Generate AI analysis", key=f"ai_generate_{original_idx}"):
                        with st.spinner("Generating local AI analysis..."):
                            text, error = generate_group_analysis(
                                group,
                                model=ai_config.get("model", "llama3.2:3b"),
                                timeout_seconds=int(ai_config.get("timeout_seconds", 60)),
                                max_core_events=int(ai_config.get("max_core_events", 15)),
                                max_support_events=int(ai_config.get("max_support_events", 5)),
                            )
                        if error:
                            st.warning(error)
                        if text:
                            analyses[original_idx] = text
                            st.session_state["report_ai_analyses"] = analyses
                    if original_idx in analyses:
                        with st.expander("AI analysis", expanded=False):
                            st.markdown(analyses[original_idx])
                render_group(group, original_idx)

    with tab_events:
        st.markdown("#### Events")
        # Pass both full and visible groups so the toggle inside the component works.
        render_all_events_table(
            all_groups=groups,
            visible_groups=visible,
            all_events=filtered_events,
        )

    # --- Export ---
    st.divider()
    st.markdown("#### Report")
    if st.button("Export selected groups to PDF", use_container_width=True):
        selected = st.session_state.get("report_selected_groups", {})
        selected_indices = [idx for idx, include in selected.items() if include]
        selected_groups = [groups[idx] for idx in selected_indices if 0 <= idx < len(groups)]
        if not selected_groups:
            st.warning("Please select at least one group to export.")
        else:
            analyses_by_idx = st.session_state.get("report_ai_analyses", {})
            analyses_by_group_id = {
                id(groups[idx]): analyses_by_idx[idx]
                for idx in selected_indices
                if idx in analyses_by_idx and 0 <= idx < len(groups)
            }
            ai_config = load_ai_config()
            pdf_bytes = generate_pdf_report(
                selected_groups,
                ai_analyses=analyses_by_group_id,
                metadata={
                    "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
                    "input_dir": st.session_state.get("input_dir", ""),
                    "ai_model": ai_config.get("model", "llama3.2:3b"),
                },
            )
            st.download_button(
                label="Download PDF report",
                data=pdf_bytes,
                file_name="windows_forensic_timeline_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    st.divider()
    render_export_section(
        output_dir=out_dir,
        groups=groups,
        input_dir=st.session_state.get("input_dir", out_dir),
        run_time=st.session_state.get("run_time"),
        analyzed_files=st.session_state.get("analyzed_files", []),
    )

else:
    # Landing state
    st.info(
        "Configure the artifact folder and sources in the sidebar, "
        "then click **Analyze Timeline** to start."
    )
    st.markdown("""
**Supported input files** (place CSV exports in the artifact folder):

| Filename pattern | Artifact |
|---|---|
| `*prefetch*.csv` | Prefetch export (PECmd / WinPrefetchView) |
| `*mft*.csv` | MFT export (MFTECmd / AnalyzeMFT) |
| `*browser*.csv` | Browser history export (BrowsingHistoryView) |
""")
