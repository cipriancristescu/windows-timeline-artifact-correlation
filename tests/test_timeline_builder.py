from datetime import datetime, timedelta
from src.models.event import Event
from src.correlator.timeline_builder import (
    build_timeline,
    build_sessions,
    group_by_time_window,
)

BASE_TIME = datetime(2024, 1, 1, 8, 0, 0)


def make_event(minutes_offset: int, source: str = "mft") -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(minutes=minutes_offset),
        source=source,
        event_type="test_event",
        description="test",
    )


# --- build_timeline ---

def test_build_timeline_sorts_chronologically():
    events = [make_event(10), make_event(0), make_event(5)]
    result = build_timeline(events)
    timestamps = [e.timestamp for e in result]
    assert timestamps == sorted(timestamps)


def test_build_timeline_empty_input():
    assert build_timeline([]) == []


# --- group_by_time_window ---

def test_group_events_within_window_into_one_group():
    events = [make_event(0), make_event(2), make_event(4)]
    groups = group_by_time_window(events, window_minutes=5)
    assert len(groups) == 1
    assert len(groups[0].events) == 3


def test_group_splits_on_gap_exceeding_window():
    events = [make_event(0), make_event(2), make_event(20), make_event(22)]
    groups = group_by_time_window(events, window_minutes=5)
    assert len(groups) == 2
    assert len(groups[0].events) == 2
    assert len(groups[1].events) == 2


def test_group_empty_input():
    assert group_by_time_window([], window_minutes=5) == []


def test_group_boundary_event_stays_in_same_group():
    # Event exactly at the window boundary should NOT start a new group
    events = [make_event(0), make_event(5)]
    groups = group_by_time_window(events, window_minutes=5)
    assert len(groups) == 1


def test_group_event_just_over_boundary_starts_new_group():
    events = [make_event(0), make_event(6)]
    groups = group_by_time_window(events, window_minutes=5)
    assert len(groups) == 2


# --- confidence ---

def test_confidence_high_when_multiple_sources_in_group():
    events = [make_event(0, source="mft"), make_event(2, source="prefetch")]
    groups = group_by_time_window(events, window_minutes=5)
    assert groups[0].confidence == "HIGH"


def test_confidence_low_when_single_source_in_group():
    events = [make_event(0, source="mft"), make_event(2, source="mft")]
    groups = group_by_time_window(events, window_minutes=5)
    assert groups[0].confidence == "LOW"


def test_confidence_computed_independently_per_group():
    # Group 1 (offset 0-2): single source -> LOW
    # Group 2 (offset 20-22): two sources -> HIGH
    events = [
        make_event(0,  source="mft"),
        make_event(2,  source="mft"),
        make_event(20, source="mft"),
        make_event(22, source="prefetch"),
    ]
    groups = group_by_time_window(events, window_minutes=5)
    assert groups[0].confidence == "LOW"
    assert groups[1].confidence == "HIGH"


# --- build_sessions: MEDIUM confidence ---

def test_confidence_medium_when_single_source_with_three_or_more_events():
    events = [make_event(0), make_event(1), make_event(2)]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1
    assert groups[0].confidence == "MEDIUM"


def test_confidence_low_when_single_source_with_two_events():
    events = [make_event(0), make_event(1)]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert groups[0].confidence == "LOW"


def test_confidence_high_overrides_medium_when_multiple_sources():
    events = [make_event(0, "mft"), make_event(1, "prefetch"), make_event(2, "mft")]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert groups[0].confidence == "HIGH"


# --- build_sessions: semantic compatibility merging ---

def make_browser_event(minutes_offset: int, application: str = "chrome",
                        domain: str = "", browser_kind: str = "web") -> Event:
    e = Event(
        timestamp=BASE_TIME + timedelta(minutes=minutes_offset),
        source="browser",
        event_type="url_visit",
        description="test",
        raw_data={"domain": domain, "browser_kind": browser_kind},
    )
    if browser_kind == "app_protocol":
        e.raw_data["url"] = "ms-photos:spareprocess-viewer"
    e.application = application
    e.activity_family = "browser"
    # Mirror what normalize_events would set so mode-split rules work in tests.
    if browser_kind == "local_file":
        e.activity_mode = "local_file_open"
    elif browser_kind == "app_protocol":
        e.activity_mode = "app_protocol"
    else:
        e.activity_mode = "web_browsing"
    return e


_BG_CATS = frozenset({"system_background", "system_ui", "browser_component"})
_FOREGROUND_CATS = frozenset({"viewer_editor", "dev_tool"})
_INSTALLER_CATS = frozenset({"installer", "uninstaller"})
_BROWSER_APPS = frozenset({"chrome", "msedge", "firefox", "opera", "brave"})


def make_prefetch_event(minutes_offset: int, application: str = "unknown",
                        process_category: str = "generic") -> Event:
    e = Event(
        timestamp=BASE_TIME + timedelta(minutes=minutes_offset),
        source="prefetch",
        event_type="program_execution",
        description="test",
        raw_data={"process_category": process_category},
    )
    e.application = application
    e.activity_family = "execution"
    # Mirror what normalize_events would set.
    if process_category in _BG_CATS:
        e.activity_mode = "background_system"
    elif process_category in _INSTALLER_CATS:
        e.activity_mode = "installer_flow"
    elif process_category in _FOREGROUND_CATS:
        e.activity_mode = "foreground_app_use"
    elif application in _BROWSER_APPS or application != "unknown":
        e.activity_mode = "foreground_app_use"
    else:
        e.activity_mode = "background_system"
    return e


# --- same application → merge in extended gap ---

def test_confidence_ignores_background_prefetch_source():
    browser = make_browser_event(0, domain="example.com")
    bg = make_prefetch_event(1, process_category="system_background")
    groups = build_sessions([browser, bg], soft_gap_minutes=5)
    assert groups[0].confidence == "LOW"


def test_session_merges_same_domain_across_extended_gap():
    # Gap 8 min > soft_max(5), same domain → browser compatible → merge.
    events = [
        make_browser_event(0, "chrome", domain="www.e3.ro"),
        make_browser_event(8, "chrome", domain="www.e3.ro"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1


def test_session_splits_different_domains_regardless_of_same_browser():
    # Gap 8 min, same Chrome browser but different domains → split.
    # For browser events, domain coherence overrides application match.
    events = [
        make_browser_event(0, "chrome", domain="www.e3.ro"),
        make_browser_event(8, "chrome", domain="www.digi24.ro"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2


def test_session_splits_incompatible_events_in_extended_gap():
    # Gap 8 min, both application and family unknown → incompatible.
    events = [make_event(0), make_event(8)]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2


def test_session_always_splits_above_hard_max():
    # Gap 20 min > hard_max(15) regardless of compatibility.
    events = [make_browser_event(0), make_browser_event(20)]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2


# --- activity_family alone is NO LONGER sufficient for extended gap ---

def test_session_does_not_merge_same_family_only_in_extended_gap():
    # Two prefetch events with same execution family but unknown application
    # at 9 min gap — family alone is not enough since the fix.
    events = [make_prefetch_event(0), make_prefetch_event(9)]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2  # was 1 before the fix


# --- browser domain coherence ---

def test_browser_same_domain_merges_in_extended_gap():
    events = [
        make_browser_event(0, domain="www.e3.ro"),
        make_browser_event(8, domain="www.e3.ro"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1


def test_browser_same_registrable_domain_merges_in_extended_gap():
    # www.e3.ro and e3.ro share the registrable domain "e3.ro".
    events = [
        make_browser_event(0, domain="www.e3.ro"),
        make_browser_event(8, domain="e3.ro"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1


def test_browser_different_domains_split_in_extended_gap():
    # e3.ro and digi24.ro → different registrable domains → split.
    events = [
        make_browser_event(0, domain="www.e3.ro"),
        make_browser_event(8, domain="www.digi24.ro"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2


def test_browser_local_files_merge_in_extended_gap():
    # Two local file visits → same browser_kind → compatible.
    events = [
        make_browser_event(0, browser_kind="local_file"),
        make_browser_event(8, browser_kind="local_file"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1


def test_browser_web_and_local_file_split_in_extended_gap():
    # web and local_file → different kinds → incompatible.
    events = [
        make_browser_event(0, browser_kind="web"),
        make_browser_event(8, browser_kind="local_file"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2


# --- prefetch process_category ---

def test_prefetch_installer_steps_merge_in_extended_gap():
    # Two installer events → same category → merge.
    events = [
        make_prefetch_event(0, process_category="installer"),
        make_prefetch_event(8, process_category="installer"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1


def test_prefetch_different_categories_split_in_extended_gap():
    # installer + generic → different categories → split.
    events = [
        make_prefetch_event(0, process_category="installer"),
        make_prefetch_event(8, process_category="generic"),
    ]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2


# --- background events don't anchor the session ---

def test_background_events_do_not_form_pure_background_groups():
    # Two SEARCHAPP (system_ui = background) events within soft_max.
    # Neither is a real anchor, so the second should NOT join the first.
    bg1 = make_prefetch_event(0, process_category="system_ui")
    bg2 = make_prefetch_event(2, process_category="system_ui")
    groups = build_sessions([bg1, bg2], soft_gap_minutes=5)
    assert len(groups) == 2  # both remain singletons


def test_background_event_joins_group_with_real_anchor():
    # A SEARCHAPP after a Chrome browser visit → anchor exists → should join.
    anchor = make_browser_event(0, "chrome", domain="example.com")
    bg = make_prefetch_event(3, process_category="system_ui")
    groups = build_sessions([anchor, bg], soft_gap_minutes=5)
    assert len(groups) == 1


def test_background_event_does_not_extend_anchor_window():
    # Anchor event at T=0, background process at T=3 (within soft_max → added),
    # new meaningful event at T=9 (> soft_max from anchor at T=0, not compatible).
    anchor = make_browser_event(0, "chrome", domain="e3.ro")
    bg = make_prefetch_event(3, process_category="system_background")
    new_event = make_browser_event(9, "chrome", domain="digi24.ro")
    # anchor_gap for new_event = 9 - 0 = 9 min (uses anchor, not bg)
    # 9 > soft_max(5), not compatible domains → new group
    events = [anchor, bg, new_event]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 2
    assert len(groups[0].events) == 2  # anchor + bg in first group


def test_background_tail_does_not_hide_browser_compatibility():
    anchor = make_browser_event(0, "chrome", domain="example.com")
    bg = make_prefetch_event(3, process_category="system_background")
    same_site = make_browser_event(8, "chrome", domain="www.example.com")
    groups = build_sessions([anchor, bg, same_site], soft_gap_minutes=5)
    assert len(groups) == 1


# --- browser_component events need a browser anchor ---

def test_browser_component_does_not_join_generic_prefetch_group():
    # MSEDGEWEBVIEW2 (browser_component) + PTSRV (generic) — no browser anchor.
    generic = make_prefetch_event(0, process_category="generic")
    webview = make_prefetch_event(2, process_category="browser_component")
    groups = build_sessions([generic, webview], soft_gap_minutes=5)
    assert len(groups) == 2


def test_browser_component_joins_group_with_browser_event():
    # MSEDGEWEBVIEW2 after a real browser visit → should join.
    anchor = make_browser_event(0, "msedge", domain="example.com")
    webview = make_prefetch_event(3, process_category="browser_component")
    groups = build_sessions([anchor, webview], soft_gap_minutes=5)
    assert len(groups) == 1


# --- activity_mode hard splits ---

def test_mode_web_browsing_rejects_installer_within_soft_gap():
    # Installer event appears 2 min after browser web event → mode split, new group.
    web = make_browser_event(0, domain="example.com", browser_kind="web")
    setup = make_prefetch_event(2, process_category="installer")
    groups = build_sessions([web, setup], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_web_browsing_rejects_unrelated_foreground_process():
    web = make_browser_event(0, application="chrome", domain="example.com")
    chatgpt = make_prefetch_event(1, application="chatgpt", process_category="generic")
    groups = build_sessions([web, chatgpt], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_web_browsing_accepts_matching_browser_executable():
    web = make_browser_event(0, application="chrome", domain="example.com")
    chrome = make_prefetch_event(1, application="chrome", process_category="generic")
    groups = build_sessions([web, chrome], soft_gap_minutes=5)
    assert len(groups) == 1


def test_mode_web_browsing_rejects_local_file_open_within_soft_gap():
    # Opening a local file (file:///) while in a web-browsing group → new group.
    web = make_browser_event(0, domain="example.com", browser_kind="web")
    local = make_browser_event(2, browser_kind="local_file")
    groups = build_sessions([web, local], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_local_file_open_rejects_web_browsing():
    # Returning to web browsing from a local-file session → new group.
    local = make_browser_event(0, browser_kind="local_file")
    web = make_browser_event(2, domain="example.com", browser_kind="web")
    groups = build_sessions([local, web], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_app_protocol_rejects_web_browsing():
    ap = make_browser_event(0, browser_kind="app_protocol")
    web = make_browser_event(2, domain="example.com", browser_kind="web")
    groups = build_sessions([ap, web], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_installer_flow_rejects_web_browsing():
    setup = make_prefetch_event(0, process_category="installer")
    web = make_browser_event(2, domain="example.com", browser_kind="web")
    groups = build_sessions([setup, web], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_local_file_and_viewer_stay_together():
    # file:/// browser event + ACROBAT.EXE (viewer_editor) → same semantic unit.
    local = make_browser_event(0, browser_kind="local_file")
    acrobat = make_prefetch_event(1, application="acrobat", process_category="viewer_editor")
    groups = build_sessions([local, acrobat], soft_gap_minutes=5)
    assert len(groups) == 1


def test_mode_local_file_rejects_unrelated_foreground_process():
    local = make_browser_event(0, browser_kind="local_file")
    chatgpt = make_prefetch_event(1, application="chatgpt", process_category="generic")
    groups = build_sessions([local, chatgpt], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_app_protocol_and_viewer_stay_together():
    # ms-photos: browser event + PHOTOS.EXE (viewer_editor) → same semantic unit.
    ap = make_browser_event(0, browser_kind="app_protocol")
    photos = make_prefetch_event(1, application="photos", process_category="viewer_editor")
    groups = build_sessions([ap, photos], soft_gap_minutes=5)
    assert len(groups) == 1


def test_mode_app_protocol_rejects_unrelated_foreground_process():
    ap = make_browser_event(0, browser_kind="app_protocol")
    vscode = make_prefetch_event(1, application="vscode", process_category="dev_tool")
    groups = build_sessions([ap, vscode], soft_gap_minutes=5)
    assert len(groups) == 2


def test_mode_same_web_browsing_always_extends():
    # Three web events within soft_max → all in one group.
    events = [make_browser_event(i, domain="example.com") for i in range(3)]
    groups = build_sessions(events, soft_gap_minutes=5)
    assert len(groups) == 1


def test_mode_background_does_not_split_web_group():
    # A system_ui event does not cause a mode split for a web-browsing group.
    web = make_browser_event(0, domain="example.com")
    bg = make_prefetch_event(2, process_category="system_ui")
    web2 = make_browser_event(4, domain="example.com")
    groups = build_sessions([web, bg, web2], soft_gap_minutes=5)
    # bg joins (anchor exists), web2 is same mode → single group
    assert len(groups) == 1


# --- max group span ---

def test_group_never_exceeds_max_span():
    # Events every 4 minutes over 100 minutes — max span (90 min) must cut the chain.
    events = [make_browser_event(i * 4, "chrome", domain="example.com")
              for i in range(30)]  # spans 116 min
    groups = build_sessions(events, soft_gap_minutes=5)
    for g in groups:
        first_ts = min(e.timestamp for e in g.events)
        last_ts  = max(e.timestamp for e in g.events)
        assert (last_ts - first_ts).total_seconds() <= 90 * 60 + 1


# --- startup noise / real-anchor guard (new fixes) ---

def test_generic_unknown_does_not_anchor_session():
    # Several generic+unknown prefetch events (startup noise) followed by a real
    # browser event.  Each noise process goes into its own solo group; the browser
    # event starts a fresh group rather than being absorbed by the noise chain.
    noise = [make_prefetch_event(i, application="unknown", process_category="generic")
             for i in range(3)]
    real = make_browser_event(4, domain="example.com")
    groups = build_sessions(noise + [real], soft_gap_minutes=5)
    # Every noise event is solo (no real anchor → each starts its own group).
    # The real browser event also starts its own clean group.
    assert len(groups) == 4
    # The last group contains only the browser event.
    assert groups[-1].events == [real]


def test_real_event_creates_own_group_after_startup_noise():
    # Startup noise chain followed by the first real user action.
    # The real event must NOT be absorbed into any of the noise groups.
    startup = [
        make_prefetch_event(0, application="unknown", process_category="generic"),
        make_prefetch_event(1, application="unknown", process_category="generic"),
    ]
    real = make_prefetch_event(2, application="vscode", process_category="dev_tool")
    groups = build_sessions(startup + [real], soft_gap_minutes=5)
    # The dev_tool event must land in its own group, not in a noise group.
    assert any(real in g.events for g in groups)
    real_group = next(g for g in groups if real in g.events)
    assert len(real_group.events) == 1


def test_dev_tool_stays_as_real_anchor():
    # git/wsl/node are now dev_tool → foreground_app_use → they anchor sessions
    # and subsequent events should join them.
    git_ev  = make_prefetch_event(0, application="git",  process_category="dev_tool")
    node_ev = make_prefetch_event(2, application="node", process_category="dev_tool")
    groups  = build_sessions([git_ev, node_ev], soft_gap_minutes=5)
    assert len(groups) == 1


def test_ambiguous_process_joins_existing_session():
    # A generic+unknown process (e.g. chatgpt.exe before whitelisting) may join
    # an existing session that already has a real anchor within soft_max.
    real  = make_prefetch_event(0, application="vscode", process_category="dev_tool")
    ambig = make_prefetch_event(2, application="unknown", process_category="generic")
    groups = build_sessions([real, ambig], soft_gap_minutes=5)
    assert len(groups) == 1


def test_generic_known_app_remains_anchor():
    # A process with category=generic but a known application name is foreground,
    # not background — it should anchor sessions normally.
    notepad = make_prefetch_event(0, application="notepad", process_category="generic")
    follow  = make_prefetch_event(2, application="notepad", process_category="generic")
    groups  = build_sessions([notepad, follow], soft_gap_minutes=5)
    assert len(groups) == 1


# ---------------------------------------------------------------------------
# Fix 1: browser_component self-anchor via resolved application name
# ---------------------------------------------------------------------------

def test_browser_component_with_browser_app_name_does_not_self_anchor():
    # MSEDGEWEBVIEW2 resolves to application="msedge" but source is prefetch
    # and process_category is browser_component.  Multiple such events must NOT
    # form a group — the resolved application name is not a real browser anchor.
    wv1 = make_prefetch_event(0, application="msedge", process_category="browser_component")
    wv2 = make_prefetch_event(2, application="msedge", process_category="browser_component")
    groups = build_sessions([wv1, wv2], soft_gap_minutes=5)
    assert len(groups) == 2


def test_browser_component_joins_real_browser_source_not_prefetch_browser():
    # A real browser source event is the only valid anchor for browser_component.
    # A browser-app prefetch (non-component) also counts; browser_component alone does not.
    real_browser = make_browser_event(0, "msedge", domain="example.com")
    webview = make_prefetch_event(2, application="msedge", process_category="browser_component")
    groups = build_sessions([real_browser, webview], soft_gap_minutes=5)
    assert len(groups) == 1  # real browser source anchors the group


def test_browser_component_chain_of_three_does_not_self_anchor():
    # Even 3+ browser_component events at the same timestamp must not form a valid group.
    wvs = [make_prefetch_event(0, application="msedge", process_category="browser_component")
           for _ in range(3)]
    groups = build_sessions(wvs, soft_gap_minutes=5)
    # All are browser_component with no real anchor → each is a singleton.
    assert len(groups) == 3


# ---------------------------------------------------------------------------
# Fix 2: well-known foreground apps recognized by normalizer
# ---------------------------------------------------------------------------

def test_zoom_normalizes_to_foreground_app():
    from src.models.event import Event
    from src.correlator.event_normalizer import normalize_events
    e = Event(
        timestamp=BASE_TIME, source="prefetch",
        event_type="program_execution", description="ZOOM.EXE executed",
        raw_data={"executable": "ZOOM.EXE"},
    )
    normalize_events([e])
    assert e.application == "zoom"
    assert e.activity_mode == "foreground_app_use"


def test_teams_normalizes_to_foreground_app():
    from src.models.event import Event
    from src.correlator.event_normalizer import normalize_events
    e = Event(
        timestamp=BASE_TIME, source="prefetch",
        event_type="program_execution", description="TEAMS.EXE executed",
        raw_data={"executable": "TEAMS.EXE"},
    )
    normalize_events([e])
    assert e.application == "teams"
    assert e.activity_mode == "foreground_app_use"


def test_known_foreground_app_events_merge_within_soft_gap():
    # After fix, zoom has a known application → foreground_app_use → can anchor and group.
    z1 = make_prefetch_event(0, application="zoom", process_category="generic")
    z2 = make_prefetch_event(3, application="zoom", process_category="generic")
    groups = build_sessions([z1, z2], soft_gap_minutes=5)
    assert len(groups) == 1


def test_known_foreground_app_events_merge_in_extended_gap_by_same_app():
    # Same known app within extended gap → _is_compatible() returns True via same-app rule.
    z1 = make_prefetch_event(0, application="zoom", process_category="generic")
    z2 = make_prefetch_event(8, application="zoom", process_category="generic")
    groups = build_sessions([z1, z2], soft_gap_minutes=5)
    assert len(groups) == 1


# ---------------------------------------------------------------------------
# Fix 3: codeblocks prefix collision with "code" → vscode
# ---------------------------------------------------------------------------

def test_codeblocks_not_mapped_to_vscode():
    from src.models.event import Event
    from src.correlator.event_normalizer import normalize_events
    e = Event(
        timestamp=BASE_TIME, source="prefetch",
        event_type="program_execution", description="CODEBLOCKS.EXE executed",
        raw_data={"executable": "CODEBLOCKS.EXE"},
    )
    normalize_events([e])
    assert e.application == "codeblocks"
    assert e.application != "vscode"


def test_codeblocks_and_vscode_split_in_extended_gap():
    # After fix: different applications → _is_compatible() returns False → split.
    cb = make_prefetch_event(0, application="codeblocks", process_category="dev_tool")
    vs = make_prefetch_event(8, application="vscode",     process_category="dev_tool")
    groups = build_sessions([cb, vs], soft_gap_minutes=5)
    assert len(groups) == 2


def test_vscode_still_maps_correctly_after_codeblocks_fix():
    # Ensure the codeblocks entry doesn't break vscode resolution.
    from src.models.event import Event
    from src.correlator.event_normalizer import normalize_events
    e = Event(
        timestamp=BASE_TIME, source="prefetch",
        event_type="program_execution", description="CODE.EXE executed",
        raw_data={"executable": "CODE.EXE"},
    )
    normalize_events([e])
    assert e.application == "vscode"
