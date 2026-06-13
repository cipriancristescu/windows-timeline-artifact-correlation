from datetime import datetime
from src.models.event import Event
from src.correlator.event_normalizer import normalize_events

BASE_TIME = datetime(2024, 1, 1, 8, 0, 0)


def make_event(source: str, raw_data: dict) -> Event:
    return Event(
        timestamp=BASE_TIME,
        source=source,
        event_type="test",
        description="test",
        raw_data=raw_data,
    )


# --- activity_family ---

def test_browser_family():
    e = make_event("browser", {"browser": "Chrome", "url": "https://example.com"})
    normalize_events([e])
    assert e.activity_family == "browser"


def test_prefetch_family():
    e = make_event("prefetch", {"executable": "notepad.exe"})
    normalize_events([e])
    assert e.activity_family == "execution"


def test_mft_family():
    e = make_event("mft", {"file_path": "C:\\Users\\user\\Documents\\file.txt"})
    normalize_events([e])
    assert e.activity_family == "file_system"


def test_unknown_source_family_stays_unknown():
    e = make_event("custom", {})
    normalize_events([e])
    assert e.activity_family == "unknown"


# --- application from browser field ---

def test_chrome_browser_field():
    e = make_event("browser", {"browser": "Chrome"})
    normalize_events([e])
    assert e.application == "chrome"


def test_edge_browser_field():
    e = make_event("browser", {"browser": "Microsoft Edge"})
    normalize_events([e])
    assert e.application == "msedge"


def test_nirsoft_ie_edge_field():
    e = make_event("browser", {"browser": "Internet Explorer 10/11 / Edge"})
    normalize_events([e])
    assert e.application == "msedge"


def test_firefox_browser_field():
    e = make_event("browser", {"browser": "Firefox"})
    normalize_events([e])
    assert e.application == "firefox"


def test_unknown_browser_field():
    e = make_event("browser", {"browser": "SomeBrowser"})
    normalize_events([e])
    assert e.application == "unknown"


# --- application from prefetch executable ---

def test_chrome_exe():
    e = make_event("prefetch", {"executable": "chrome.exe"})
    normalize_events([e])
    assert e.application == "chrome"


def test_powershell_exe():
    e = make_event("prefetch", {"executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"})
    normalize_events([e])
    assert e.application == "powershell"


def test_versioned_python_exe():
    e = make_event("prefetch", {"executable": "python314.exe"})
    normalize_events([e])
    assert e.application == "python"


def test_unknown_exe():
    e = make_event("prefetch", {"executable": "somecustom.exe"})
    normalize_events([e])
    assert e.application == "unknown"


# --- multiple events ---

def test_normalize_multiple_events():
    events = [
        make_event("browser",  {"browser": "Chrome"}),
        make_event("prefetch", {"executable": "notepad.exe"}),
        make_event("mft",      {}),
    ]
    normalize_events(events)
    assert events[0].application == "chrome"
    assert events[1].application == "notepad"
    assert events[2].activity_family == "file_system"


# --- process_category ---

def _pf(exe: str) -> dict:
    return {"executable": exe}


def test_process_category_system_background():
    e = make_event("prefetch", _pf("BACKGROUNDTASKHOST.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "system_background"


def test_process_category_defrag_is_system_background():
    e = make_event("prefetch", _pf("DEFRAG.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "system_background"


def test_process_category_werfault_is_system_background():
    e = make_event("prefetch", _pf("WERFAULT.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "system_background"


def test_process_category_cleanmgr_is_system_background():
    e = make_event("prefetch", _pf("CLEANMGR.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "system_background"


def test_process_category_system_ui():
    e = make_event("prefetch", _pf("SEARCHAPP.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "system_ui"


def test_process_category_browser_component():
    e = make_event("prefetch", _pf("MSEDGEWEBVIEW2.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "browser_component"


def test_process_category_installer_by_name():
    e = make_event("prefetch", _pf("SETUP.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "installer"


def test_process_category_installer_tmp():
    e = make_event("prefetch", _pf("CODESETUP-STABLE-ABC123.TMP"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "installer"


def test_process_category_uninstaller_tmp():
    e = make_event("prefetch", _pf("_UNINS.TMP"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "uninstaller"


def test_process_category_uninstaller_named():
    e = make_event("prefetch", _pf("UNINS000.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "uninstaller"


def test_process_category_viewer_editor():
    e = make_event("prefetch", _pf("ACROBAT.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "viewer_editor"


def test_process_category_dev_tool():
    e = make_event("prefetch", _pf("CODE.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "dev_tool"


def test_process_category_generic_for_unknown():
    e = make_event("prefetch", _pf("SQLDEVELOPER64W.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "generic"


def test_process_category_vc_redist_is_installer():
    e = make_event("prefetch", _pf("VC_REDIST.X86.EXE"))
    normalize_events([e])
    assert e.raw_data["process_category"] == "installer"


# --- browser_kind ---

def test_browser_kind_web():
    e = make_event("browser", {"url": "https://www.google.com/search?q=test"})
    normalize_events([e])
    assert e.raw_data["browser_kind"] == "web"


def test_browser_kind_local_file():
    e = make_event("browser", {"url": "file:///C:/Users/user/docs/report.pdf"})
    normalize_events([e])
    assert e.raw_data["browser_kind"] == "local_file"


def test_browser_kind_res_protocol():
    e = make_event("browser", {"url": "res://C:\\Program Files\\HP\\HPWUCli.exe/136"})
    normalize_events([e])
    assert e.raw_data["browser_kind"] == "local_file"


def test_browser_kind_ms_photos():
    e = make_event("browser", {"url": "ms-photos:spareprocess-viewer"})
    normalize_events([e])
    assert e.raw_data["browser_kind"] == "app_protocol"


def test_browser_kind_ms_screenclip():
    e = make_event("browser", {"url": "ms-screenclip:?clippingMode=Window"})
    normalize_events([e])
    assert e.raw_data["browser_kind"] == "app_protocol"


def test_browser_kind_ms_gamingoverlay():
    e = make_event("browser", {"url": "ms-gamingoverlay://kglcheck/"})
    normalize_events([e])
    assert e.raw_data["browser_kind"] == "app_protocol"


# --- activity_mode ---

def test_activity_mode_web_browsing():
    e = make_event("browser", {"url": "https://example.com"})
    normalize_events([e])
    assert e.activity_mode == "web_browsing"


def test_activity_mode_local_file_open():
    e = make_event("browser", {"url": "file:///C:/Users/user/docs/report.pdf"})
    normalize_events([e])
    assert e.activity_mode == "local_file_open"


def test_activity_mode_app_protocol():
    e = make_event("browser", {"url": "ms-photos:spareprocess-viewer"})
    normalize_events([e])
    assert e.activity_mode == "app_protocol"


def test_activity_mode_installer_flow():
    e = make_event("prefetch", {"executable": "SETUP.EXE"})
    normalize_events([e])
    assert e.activity_mode == "installer_flow"


def test_activity_mode_foreground_viewer():
    e = make_event("prefetch", {"executable": "ACROBAT.EXE"})
    normalize_events([e])
    assert e.activity_mode == "foreground_app_use"


def test_activity_mode_foreground_dev_tool():
    e = make_event("prefetch", {"executable": "CODE.EXE"})
    normalize_events([e])
    assert e.activity_mode == "foreground_app_use"


def test_activity_mode_foreground_known_exe():
    # NOTEPAD has a known application name → foreground_app_use even if category=generic.
    e = make_event("prefetch", {"executable": "NOTEPAD.EXE"})
    normalize_events([e])
    assert e.activity_mode == "foreground_app_use"


def test_activity_mode_background_system_unknown_exe():
    # Unknown exe, generic category → background noise.
    e = make_event("prefetch", {"executable": "SOMECUSTOM.EXE"})
    normalize_events([e])
    assert e.activity_mode == "background_system"


def test_activity_mode_background_system_bg_category():
    e = make_event("prefetch", {"executable": "BACKGROUNDTASKHOST.EXE"})
    normalize_events([e])
    assert e.activity_mode == "background_system"


# --- new dev-tool / background entries ---

def test_git_recognized_as_dev_tool():
    e = make_event("prefetch", {"executable": "GIT.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "dev_tool"
    assert e.activity_mode == "foreground_app_use"
    assert e.application == "git"


def test_wsl_recognized_as_dev_tool():
    e = make_event("prefetch", {"executable": "WSL.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "dev_tool"
    assert e.activity_mode == "foreground_app_use"
    assert e.application == "wsl"


def test_node_recognized_as_dev_tool():
    e = make_event("prefetch", {"executable": "NODE.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "dev_tool"
    assert e.activity_mode == "foreground_app_use"


def test_npm_recognized_as_dev_tool():
    e = make_event("prefetch", {"executable": "NPM.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "dev_tool"
    assert e.activity_mode == "foreground_app_use"
    assert e.application == "node"


def test_streamlit_recognized_as_named_dev_tool():
    e = make_event("prefetch", {"executable": "STREAMLIT.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "dev_tool"
    assert e.activity_mode == "foreground_app_use"
    assert e.application == "streamlit"


def test_java_launchers_normalize_to_java():
    e = make_event("prefetch", {"executable": "JAVAWS.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "generic"
    assert e.activity_mode == "foreground_app_use"
    assert e.application == "java"


def test_browsinghistoryview_normalizes_to_foreground_app():
    e = make_event("prefetch", {"executable": "BROWSINGHISTORYVIEW.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "generic"
    assert e.activity_mode == "foreground_app_use"
    assert e.application == "browsinghistoryview"


def test_whatsapp_root_is_background():
    e = make_event("prefetch", {"executable": "WHATSAPP.ROOT.EXE"})
    normalize_events([e])
    assert e.raw_data["process_category"] == "system_background"
    assert e.activity_mode == "background_system"
