"""Enrich Event objects with normalised fields used by the grouping layer.

Called once after parsing, before grouping.  All changes are made in-place;
the original ``raw_data`` dict from the parser is never modified.

Fields set by this module
--------------------------
application     : str  — canonical application name ("chrome", "vscode", …)
                         or "unknown" when not determinable.
activity_family : str  — coarse source family (browser / execution / …).
process_category: str  — stored in raw_data; fine-grained exe classification
                         (prefetch events only).
browser_kind    : str  — stored in raw_data; URL scheme classification
                         (browser events only).
activity_mode   : str  — coarse activity context used by the session splitter.
"""
from src.models.event import Event


# ---------------------------------------------------------------------------
# Application name maps
# ---------------------------------------------------------------------------

# Maps executable stem (lowercase, no extension) to a canonical application
# name.  Exact-match is tried first; if that fails, the prefix fallback loop
# in _app_from_exe() is used (e.g. "msedge" prefix catches "msedge_proxy").
# Entries that would be incorrectly caught by the prefix loop (e.g. "codeblocks"
# starting with "code") must appear before the shorter key they would shadow.
_APP_FROM_EXE: dict[str, str] = {
    # Browsers
    "chrome":          "chrome",
    "chromium":        "chrome",
    "msedge":          "msedge",
    "microsoftedge":   "msedge",
    "iexplore":        "msedge",
    "firefox":         "firefox",
    "opera":           "opera",
    "brave":           "brave",
    # Editors and IDEs — codeblocks must precede "code" to avoid prefix match
    "codeblocks":      "codeblocks",
    "code":            "vscode",
    "notepad":         "notepad",
    "notepad++":       "notepad++",
    # Office / document viewers
    "winword":         "word",
    "excel":           "excel",
    "powerpnt":        "powerpoint",
    "acrord32":        "acrobat",
    "acrobat":         "acrobat",
    "mspaint":         "mspaint",
    "vlc":             "vlc",
    # Archives
    "winrar":          "winrar",
    "7zfm":            "7zip",
    "7z":              "7zip",
    # System / shell
    "explorer":        "explorer",
    "powershell":      "powershell",
    "pwsh":            "powershell",
    "cmd":             "cmd",
    "openconsole":     "terminal",
    "mmc":             "mmc",
    # Developer tools
    "python":          "python",
    "python3":         "python",
    "git":             "git",
    "wsl":             "wsl",
    "bash":            "bash",
    "node":            "node",
    "npm":             "node",
    "rg":              "rg",
    "streamlit":       "streamlit",
    "javaws":          "java",
    "jp2launcher":     "java",
    # AI assistants
    "chatgpt":         "chatgpt",
    "claude":          "claude",
    # Communication / productivity
    "zoom":            "zoom",
    "teams":           "teams",
    # Other known foreground applications
    "virtualbox":      "virtualbox",
    "geogebra":        "geogebra",
    "sqldeveloper64w": "sqldeveloper",
    "sqldeveloper":    "sqldeveloper",
    "browsinghistoryview": "browsinghistoryview",
}

_APP_FROM_BROWSER_FIELD: dict[str, str] = {
    "chrome":                          "chrome",
    "google chrome":                   "chrome",
    "microsoft edge":                  "msedge",
    "msedge":                          "msedge",
    "internet explorer 10/11 / edge":  "msedge",
    "internet explorer":               "msedge",
    "firefox":                         "firefox",
    "mozilla firefox":                 "firefox",
    "opera":                           "opera",
    "brave":                           "brave",
}

_FAMILY_FROM_SOURCE: dict[str, str] = {
    "browser":  "browser",
    "prefetch": "execution",
    "mft":      "file_system",
}


# ---------------------------------------------------------------------------
# Process-category sets (prefetch events only)
# ---------------------------------------------------------------------------

# OS services and maintenance processes — run silently, never user-initiated.
_BACKGROUND_PROCESSES = frozenset({
    "backgroundtaskhost", "mobsync", "filecoauth", "rundll32", "svchost",
    "wmiprvse", "wmiapsrv", "tiworker", "trustedinstaller", "compattelrunner",
    "usoclient", "ngen", "ngentask", "mrt", "waasmedicagent", "sppextcomobj",
    "sppsvc", "smartscreen", "consent", "dllhost", "taskhostw", "conhost",
    "audiodg", "fontdrvhost", "searchindexer", "runtimebroker", "wmiadap",
    "mpcmdrun", "searchprotocolhost", "searchfilterhost", "backgroundtransferhost",
    "crlogtransport", "crwindowsclientservice", "fulltrustnotifier", "icacls",
    "msiexec", "hpwucli", "hpwuschd2", "nvtray", "adobearmhelper", "adobearm",
    "acrocef", "identity_helper", "caudiofilteragent64", "castsrv",
    "adobecollabsync", "figma_agent", "psexpressstartupservice", "bdagent",
    "m365copilot_autostarter", "elevation_service", "bdredline",
    "psexpressbroker", "psexpresscore", "expressprtscbackgroundapp",
    "watchdog", "update", "sihclient", "slui", "gfxdownloadwrapper",
    "ms-teamsupdate", "upfc", "avfree.migration",
    "vsce-sign", "hpprintscandoctorext", "testinitsigs", "agentctrl",
    "windowspackagemanager.dll", "pet", "mighost",
    "online application updater",
    # Disk and system maintenance
    "defrag", "cleanmgr", "dismhost", "dismsvc",
    # Windows Error Reporting (triggered by crashes, not user actions)
    "werfault", "werhost", "wermgr",
    # Task Scheduler infrastructure
    "taskeng", "taskschd",
    # Messaging agents that auto-start at login
    "whatsapp.root",
})

# Shell / UI chrome — not user-initiated work.
_SYSTEM_UI_PROCESSES = frozenset({
    "searchapp", "shellexperiencehost", "startmenuexperiencehost", "lockapp",
    "textinputhost", "applicationframehost", "phoneexperiencehost", "gamebar",
    "gamebarftserver", "wwahost", "useroobebroker", "logonui",
    "storedesktopextension", "screenclippinghost",
})

# WebView2 and browser update helpers — browser infrastructure, not direct use.
_BROWSER_COMPONENT_PROCESSES = frozenset({
    "msedgewebview2", "microsoftedgeupdate", "zwebview2agent",
    "mscopilot_proxy", "webviewhost",
})

# Document and media viewers / editors.
_VIEWER_EDITOR_PROCESSES = frozenset({
    "acrobat", "acrord32", "photos", "winword", "excel", "powerpnt",
    "mspaint", "vlc", "shotcut", "clipchamp", "obs64",
})

# Developer tooling.
_DEV_TOOL_PROCESSES = frozenset({
    "code", "code-tunnel", "devenv", "claude", "streamlit",
    "git", "wsl", "bash", "node", "npm", "rg", "openconsole",
})

# Substrings in the executable stem that indicate an installer.
_INSTALLER_PATTERNS = (
    "setup", "install", "vc_redist", "dotnet", "setuphost",
    "mediacreationtool", "setuppackage", "bootstrapper",
    "updater", "downloader", "inno_updater",
)

# Substrings that indicate an uninstaller.
_UNINSTALLER_PATTERNS = ("_unins", "unins000")

# Windows app-protocol URL schemes handled by _browser_kind().
_APP_PROTOCOL_SCHEMES = (
    "ms-photos:", "ms-screenclip:", "ms-gamingoverlay:",
    "msteams:", "ms-settings:", "ms-teamsupdate:",
)

# Browser application names (used in activity_mode derivation).
_BROWSER_APPS = frozenset({"chrome", "msedge", "firefox", "opera", "brave"})


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _stem(path: str) -> str:
    """Return the lowercase filename stem, stripping path and extension."""
    base = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0].lower()


def _app_from_exe(executable: str) -> str:
    """Map an executable path to a canonical application name.

    Tries an exact stem match first, then a prefix match as a fallback for
    versioned or variant executables (e.g. ``msedge_proxy`` → ``msedge``).
    Returns ``"unknown"`` when no match is found.
    """
    s = _stem(executable)
    if s in _APP_FROM_EXE:
        return _APP_FROM_EXE[s]
    for key, val in _APP_FROM_EXE.items():
        if s.startswith(key):
            return val
    return "unknown"


def _app_from_browser_field(browser: str) -> str:
    return _APP_FROM_BROWSER_FIELD.get(browser.strip().lower(), "unknown")


def _process_category(executable: str) -> str:
    """Classify a prefetch executable into a coarse process category."""
    s        = _stem(executable)
    basename = executable.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()

    if s in _BACKGROUND_PROCESSES:
        return "system_background"
    if s in _SYSTEM_UI_PROCESSES:
        return "system_ui"
    if s in _BROWSER_COMPONENT_PROCESSES:
        return "browser_component"
    if s in _VIEWER_EDITOR_PROCESSES:
        return "viewer_editor"
    if s in _DEV_TOOL_PROCESSES:
        return "dev_tool"

    # .TMP executables are almost always temporary installer/uninstaller copies.
    if basename.endswith(".tmp"):
        return "uninstaller" if any(p in s for p in _UNINSTALLER_PATTERNS) else "installer"

    if any(p in s for p in _UNINSTALLER_PATTERNS):
        return "uninstaller"
    if any(p in s for p in _INSTALLER_PATTERNS):
        return "installer"

    return "generic"


def _browser_kind(url: str) -> str:
    """Classify a browser URL as ``web``, ``local_file``, or ``app_protocol``."""
    u = url.lower()
    if u.startswith(("file:///", "file://", "res://")):
        return "local_file"
    if any(u.startswith(p) for p in _APP_PROTOCOL_SCHEMES):
        return "app_protocol"
    return "web"


def _activity_mode(event: Event) -> str:
    """Derive the coarse activity mode from the event's source and enriched fields.

    Possible modes
    --------------
    background_system  — OS noise; never anchors a session.
    web_browsing       — HTTPS/HTTP browser navigation.
    local_file_open    — file:/// or res:// URL opened in the browser.
    app_protocol       — Windows app-protocol URL (ms-photos:, msteams:, …).
    installer_flow     — prefetch installer or uninstaller executable.
    foreground_app_use — prefetch viewer, dev tool, or any known named application.
    unknown            — sources other than browser or prefetch (for example mft).
    """
    if event.source == "browser":
        bk = event.raw_data.get("browser_kind", "web")
        if bk == "local_file":
            return "local_file_open"
        if bk == "app_protocol":
            return "app_protocol"
        return "web_browsing"

    if event.source == "prefetch":
        cat = event.raw_data.get("process_category", "generic")
        if cat in ("system_background", "system_ui", "browser_component"):
            return "background_system"
        if cat in ("installer", "uninstaller"):
            return "installer_flow"
        if cat in ("viewer_editor", "dev_tool"):
            return "foreground_app_use"
        # generic category: treat as foreground if the application is known.
        if event.application in _BROWSER_APPS or event.application != "unknown":
            return "foreground_app_use"
        # generic + unknown executable — indistinguishable from background noise.
        return "background_system"

    return "unknown"


def _normalize(event: Event) -> None:
    event.activity_family = _FAMILY_FROM_SOURCE.get(event.source, "unknown")

    if event.source == "browser":
        browser = event.raw_data.get("browser", "")
        if browser:
            event.application = _app_from_browser_field(browser)
        # Fallback: a file:// URL opened without a browser field is Explorer.
        if event.application == "unknown":
            if event.raw_data.get("url", "").lower().startswith("file://"):
                event.application = "explorer"
        event.raw_data["browser_kind"] = _browser_kind(event.raw_data.get("url", ""))

    elif event.source == "prefetch":
        exe = event.raw_data.get("executable", "")
        if exe:
            event.application = _app_from_exe(exe)
        event.raw_data["process_category"] = _process_category(exe)

    elif event.source == "mft":
        path = event.raw_data.get("file_path", "")
        if path:
            event.application = _app_from_exe(path)

    event.activity_mode = _activity_mode(event)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_events(events: list[Event]) -> None:
    """Enrich every event with application, activity_family, and activity_mode.

    Also stores ``process_category`` (prefetch) and ``browser_kind`` (browser)
    in each event's ``raw_data`` dict for downstream use by the grouper.
    All modifications are made in-place; the function returns nothing.
    """
    for event in events:
        _normalize(event)
