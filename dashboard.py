"""
SecretGuard — Security Dashboard

Run:
    streamlit run dashboard.py

Presentation-only layer. Detection remains inside src/.
"""

from __future__ import annotations

from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from src.models import SeverityEnum
from src.reporter import to_json
from src.scanner import scan_directory


# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecretGuard | Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------
BG = "#050814"
SURFACE = "#0A1020"
SURFACE_2 = "#0E172A"
BORDER = "#18243A"
TEXT = "#F5F7FB"
MUTED = "#7F8CA5"
BLUE = "#3B82F6"
BLUE_BRIGHT = "#60A5FA"
RED = "#FF4D67"
RED_BRIGHT = "#FF6B81"
AMBER = "#F59E0B"
GRAY = "#64748B"

SEVERITY_COLORS = {
    SeverityEnum.CRITICAL: RED,
    SeverityEnum.HIGH: AMBER,
    SeverityEnum.MEDIUM: BLUE_BRIGHT,
    SeverityEnum.LOW: GRAY,
}

SEVERITY_ORDER = [
    SeverityEnum.CRITICAL,
    SeverityEnum.HIGH,
    SeverityEnum.MEDIUM,
    SeverityEnum.LOW,
]

SEVERITY_RANK = {severity: i for i, severity in enumerate(SEVERITY_ORDER)}


# ---------------------------------------------------------------------------
# CSS — dark, restrained, blue-to-red security state
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    :root {{
        --sg-bg: {BG};
        --sg-surface: {SURFACE};
        --sg-surface-2: {SURFACE_2};
        --sg-border: {BORDER};
        --sg-text: {TEXT};
        --sg-muted: {MUTED};
        --sg-blue: {BLUE};
        --sg-blue-bright: {BLUE_BRIGHT};
        --sg-red: {RED};
        --sg-red-bright: {RED_BRIGHT};
    }}

    html, body, [data-testid="stAppViewContainer"] {{
        background: var(--sg-bg) !important;
        color: var(--sg-text);
        font-family: Inter, sans-serif;
    }}

    [data-testid="stHeader"] {{
        background: transparent !important;
    }}

    [data-testid="stMainBlockContainer"] {{
        max-width: 1480px;
        padding-top: 1.5rem;
        padding-bottom: 4rem;
    }}

    [data-testid="stSidebar"] {{
        display: none !important;
    }}

    [data-testid="stMain"] {{
        margin-left: 0 !important;
    }}

    h1, h2, h3, h4 {{
        font-family: "Space Grotesk", sans-serif !important;
    }}

    /* Main-canvas scan console */
    .sg-topbar {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        margin: .15rem 0 1.05rem;
    }}
    .sg-topbar-tag {{
        color: var(--sg-muted);
        font: 500 .64rem "DM Mono", monospace;
        letter-spacing: .13em;
        text-transform: uppercase;
        border: 1px solid var(--sg-border);
        border-radius: 999px;
        padding: .42rem .7rem;
        background: rgba(255,255,255,.018);
    }}
    .sg-scan-console {{
        border: 1px solid var(--sg-border);
        border-radius: 17px;
        background: linear-gradient(135deg, rgba(59,130,246,.055), transparent 55%), var(--sg-surface);
        padding: 1.05rem 1.15rem .85rem;
        margin-bottom: .35rem;
    }}
    .sg-console-heading {{
        color: var(--sg-text);
        font: 600 1rem "Space Grotesk", sans-serif;
        margin-bottom: .15rem;
    }}
    .sg-console-copy {{
        color: var(--sg-muted);
        font-size: .73rem;
        margin-bottom: .7rem;
    }}
    .sg-engine-strip {{
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: .5rem;
        margin-top: .35rem;
        margin-bottom: 1rem;
        color: var(--sg-muted);
        font-size: .67rem;
    }}
    .sg-engine-chip {{
        border: 1px solid var(--sg-border);
        border-radius: 999px;
        padding: .24rem .55rem;
        background: rgba(255,255,255,.018);
        color: #AFCFFF;
        font: 500 .62rem "DM Mono", monospace;
        letter-spacing: .04em;
    }}

    /* ---------------------------------------------------------------
       Brand
       --------------------------------------------------------------- */
    .sg-brand {{
        display: flex;
        align-items: center;
        gap: .7rem;
        margin-bottom: .15rem;
    }}

    .sg-brand-mark {{
        width: 38px;
        height: 38px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 11px;
        background: rgba(59,130,246,.10);
        border: 1px solid rgba(96,165,250,.30);
        color: #CFE4FF;
        box-shadow: 0 0 26px rgba(59,130,246,.12);
        font-size: 1.15rem;
    }}

    .sg-brand-name {{
        font: 700 1.55rem "Space Grotesk", sans-serif;
        letter-spacing: -.04em;
        color: var(--sg-text);
    }}

    .sg-brand-name span {{
        color: var(--sg-blue-bright);
    }}

    .sg-brand-sub {{
        margin: 0 0 1.4rem 2.95rem;
        color: var(--sg-muted);
        font-size: .70rem;
        letter-spacing: .04em;
    }}

    /* ---------------------------------------------------------------
       Hero / system state — wide, wave-shaped glow with a grain
       texture, contained to this card. Color reads the live scan
       state via --state-glow (blue = safe, red = alert).
       --------------------------------------------------------------- */
    .sg-hero {{
        position: relative;
        overflow: hidden;
        min-height: 300px;
        border: 1px solid var(--sg-border);
        border-radius: 22px;
        background: #05070F;
        padding: 1.35rem 1.5rem 1.2rem;
        margin-bottom: 1rem;
        isolation: isolate;
    }}

    /* the wave itself: a single blurred ribbon shape, brightest at
       center and fading at the horizontal edges, clipped to this
       card's rounded corners by the hero's own overflow:hidden */
    .sg-hero-wave {{
        position: absolute;
        inset: 0;
        z-index: 0;
        width: 100%;
        height: 100%;
        filter: blur(34px);
        opacity: .9;
        transition: opacity .6s ease;
        pointer-events: none;
    }}

    .sg-hero-wave path {{
        fill: var(--state-glow);
        transition: fill .6s ease;
    }}

    /* fine grain layer to match the noisy texture in the reference */
    .sg-hero-grain {{
        position: absolute;
        inset: 0;
        z-index: 1;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.05'/%3E%3C/svg%3E");
        mix-blend-mode: overlay;
        opacity: .3;
        pointer-events: none;
    }}

    .sg-hero.safe {{ --state-glow: {BLUE}; }}
    .sg-hero.alert {{ --state-glow: {RED}; }}

    .sg-hero-top {{
        position: relative;
        z-index: 2;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 1rem;
    }}

    .sg-kicker {{
        color: var(--state-color);
        font: 500 .67rem "DM Mono", monospace;
        text-transform: uppercase;
        letter-spacing: .16em;
    }}

    .sg-hero-title {{
        margin-top: .35rem;
        font: 700 1.65rem "Space Grotesk", sans-serif;
        letter-spacing: -.035em;
        color: var(--sg-text);
    }}

    .sg-hero-copy {{
        max-width: 650px;
        color: var(--sg-muted);
        font-size: .82rem;
        line-height: 1.55;
        margin-top: .25rem;
    }}

    .sg-state-pill {{
        flex: 0 0 auto;
        display: flex;
        align-items: center;
        gap: .45rem;
        border: 1px solid var(--state-border);
        background: var(--state-bg);
        color: var(--state-color);
        border-radius: 999px;
        padding: .42rem .68rem;
        font: 500 .67rem "DM Mono", monospace;
        text-transform: uppercase;
        letter-spacing: .05em;
        backdrop-filter: blur(6px);
    }}

    .sg-state-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--state-color);
        box-shadow: 0 0 13px var(--state-color);
    }}

    .sg-orb-wrap {{
        position: relative;
        z-index: 2;
        height: 128px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-top: .25rem;
    }}

    .sg-orb {{
        width: 92px;
        height: 92px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        color: var(--state-color);
        font-size: 2.1rem;
        border: 1px solid var(--state-border);
        background: radial-gradient(circle at 50% 42%, var(--state-core), rgba(0,0,0,0) 68%);
        box-shadow:
            0 0 24px var(--state-shadow),
            0 0 75px var(--state-shadow),
            inset 0 0 24px var(--state-shadow);
        animation: sgPulse 3.2s ease-in-out infinite;
    }}

    @keyframes sgPulse {{
        0%, 100% {{ transform: scale(.98); opacity: .88; }}
        50% {{ transform: scale(1.025); opacity: 1; }}
    }}

    .sg-state-text {{
        position: relative;
        z-index: 2;
        text-align: center;
        margin-top: -.15rem;
    }}

    .sg-state-main {{
        color: var(--state-color);
        font: 700 .84rem "Space Grotesk", sans-serif;
        letter-spacing: .13em;
        text-transform: uppercase;
    }}

    .sg-state-detail {{
        color: var(--sg-muted);
        font-size: .72rem;
        margin-top: .22rem;
    }}

    /* ---------------------------------------------------------------
       Cards / metrics
       --------------------------------------------------------------- */
    .sg-metric {{
        border: 1px solid var(--sg-border);
        border-radius: 15px;
        background: var(--sg-surface);
        padding: .95rem 1rem;
        min-height: 96px;
    }}

    .sg-metric-label {{
        color: var(--sg-muted);
        font-size: .67rem;
        text-transform: uppercase;
        letter-spacing: .10em;
    }}

    .sg-metric-value {{
        margin-top: .25rem;
        color: var(--sg-text);
        font: 600 1.75rem "Space Grotesk", sans-serif;
    }}

    .sg-metric-value.alert {{ color: var(--sg-red-bright); }}
    .sg-metric-value.blue {{ color: var(--sg-blue-bright); }}

    .sg-metric-note {{
        color: #59677E;
        font-size: .69rem;
        margin-top: .08rem;
    }}

    .sg-section-head {{
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        gap: 1rem;
        margin: 1.45rem 0 .7rem;
    }}

    .sg-section-title {{
        color: var(--sg-text);
        font: 600 1rem "Space Grotesk", sans-serif;
    }}

    .sg-section-caption {{
        color: var(--sg-muted);
        font-size: .70rem;
    }}

    .sg-panel {{
        border: 1px solid var(--sg-border);
        border-radius: 15px;
        background: var(--sg-surface);
        padding: .7rem;
    }}

    /* ---------------------------------------------------------------
       Findings
       --------------------------------------------------------------- */
    .sg-finding {{
        position: relative;
        border: 1px solid var(--sg-border);
        border-left: 3px solid var(--finding-color);
        border-radius: 13px;
        background: linear-gradient(90deg, var(--finding-wash), rgba(255,255,255,0) 48%), var(--sg-surface);
        padding: .82rem .95rem;
        margin-bottom: .55rem;
    }}

    .sg-finding-top {{
        display: flex;
        align-items: center;
        gap: .48rem;
        flex-wrap: wrap;
    }}

    .sg-badge {{
        color: #06101E;
        border-radius: 999px;
        padding: .20rem .48rem;
        font-size: .60rem;
        font-weight: 800;
        letter-spacing: .07em;
    }}

    .sg-finding-name {{
        color: var(--sg-text);
        font-size: .83rem;
        font-weight: 600;
    }}

    .sg-confidence {{
        margin-left: auto;
        color: var(--sg-muted);
        font: 400 .68rem "DM Mono", monospace;
    }}

    .sg-location {{
        color: #7DB4FF;
        font: 400 .68rem "DM Mono", monospace;
        margin-top: .42rem;
        overflow-wrap: anywhere;
    }}

    .sg-secret {{
        display: inline-block;
        margin-top: .42rem;
        border: 1px solid var(--sg-border);
        border-radius: 7px;
        background: #070D19;
        color: #AEB9CC;
        padding: .25rem .48rem;
        font: 400 .67rem "DM Mono", monospace;
    }}

    .sg-fix {{
        color: var(--sg-muted);
        font-size: .71rem;
        line-height: 1.45;
        margin-top: .42rem;
    }}

    /* ---------------------------------------------------------------
       Empty state
       --------------------------------------------------------------- */
    .sg-empty {{
        border: 1px dashed #24334E;
        border-radius: 15px;
        background: rgba(255,255,255,.008);
        text-align: center;
        padding: 2rem 1rem;
    }}

    .sg-empty-icon {{
        font-size: 1.8rem;
        color: var(--sg-blue-bright);
        text-shadow: 0 0 25px rgba(59,130,246,.55);
    }}

    .sg-empty-title {{
        color: var(--sg-text);
        font: 600 1rem "Space Grotesk", sans-serif;
        margin-top: .3rem;
    }}

    .sg-empty-copy {{
        color: var(--sg-muted);
        font-size: .74rem;
        margin-top: .25rem;
    }}

    /* ---------------------------------------------------------------
       Streamlit widgets
       --------------------------------------------------------------- */
    [data-testid="stTextInput"] input {{
        background: var(--sg-surface-2) !important;
        color: var(--sg-text) !important;
        border: 1px solid var(--sg-border) !important;
        border-radius: 9px !important;
    }}

    [data-testid="stTextInput"] input:focus {{
        border-color: rgba(59,130,246,.70) !important;
        box-shadow: 0 0 0 1px rgba(59,130,246,.18) !important;
    }}

    .stButton > button[kind="primary"] {{
        width: 100%;
        border: 1px solid rgba(96,165,250,.35) !important;
        border-radius: 9px !important;
        background: linear-gradient(135deg, #2563EB, #3B82F6) !important;
        color: white !important;
        font-weight: 700 !important;
        box-shadow: 0 8px 26px rgba(37,99,235,.16);
    }}

    .stButton > button[kind="primary"]:hover {{
        border-color: rgba(147,197,253,.65) !important;
        box-shadow: 0 8px 30px rgba(37,99,235,.24);
    }}

    .stDownloadButton > button {{
        width: 100%;
        border: 1px solid var(--sg-border) !important;
        border-radius: 9px !important;
        background: var(--sg-surface-2) !important;
        color: var(--sg-text) !important;
    }}

    [data-baseweb="select"] > div {{
        background: var(--sg-surface-2) !important;
        border-color: var(--sg-border) !important;
    }}

    [data-testid="stSidebar"] hr {{
        border-color: var(--sg-border) !important;
    }}

    .sg-sidebar-note {{
        color: #59677E;
        font-size: .66rem;
        line-height: 1.5;
    }}

    .sg-footer {{
        border-top: 1px solid var(--sg-border);
        margin-top: 2rem;
        padding-top: .8rem;
        text-align: center;
        color: #4D5A70;
        font-size: .64rem;
        letter-spacing: .02em;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


def state_styles(has_scan: bool, findings: int) -> dict[str, str]:
    """Return the visual state for the hero panel."""
    if not has_scan:
        return {
            "class": "safe",
            "color": BLUE_BRIGHT,
            "border": "rgba(96,165,250,.25)",
            "bg": "rgba(59,130,246,.06)",
            "core": "rgba(59,130,246,.16)",
            "shadow": "rgba(59,130,246,.20)",
            "label": "SYSTEM READY",
            "detail": "Waiting for a project scan",
        }
    if findings > 0:
        return {
            "class": "alert",
            "color": RED_BRIGHT,
            "border": "rgba(255,77,103,.30)",
            "bg": "rgba(255,77,103,.065)",
            "core": "rgba(255,77,103,.16)",
            "shadow": "rgba(255,77,103,.22)",
            "label": "THREATS DETECTED",
            "detail": f"{findings} finding(s) require review",
        }
    return {
        "class": "safe",
        "color": BLUE_BRIGHT,
        "border": "rgba(96,165,250,.25)",
        "bg": "rgba(59,130,246,.06)",
        "core": "rgba(59,130,246,.16)",
        "shadow": "rgba(59,130,246,.20)",
        "label": "SCAN CLEAR",
        "detail": "No configured secrets detected",
    }


def render_finding(finding) -> None:
    color = SEVERITY_COLORS[finding.severity]
    wash = (
        "rgba(255,77,103,.045)"
        if finding.severity == SeverityEnum.CRITICAL
        else "rgba(59,130,246,.025)"
    )
    entropy = (
        f" · entropy {finding.entropy_score:.2f}"
        if finding.entropy_score is not None
        else ""
    )

    st.markdown(
        f"""
        <div class="sg-finding"
             style="--finding-color:{color};--finding-wash:{wash};">
            <div class="sg-finding-top">
                <span class="sg-badge" style="background:{color};">
                    {finding.severity.value.upper()}
                </span>
                <span class="sg-finding-name">{finding.secret_type}</span>
                <span class="sg-confidence">
                    confidence {finding.confidence_score:.2f}
                </span>
            </div>
            <div class="sg-location">
                {finding.location} · {finding.detection_method.value}{entropy}
            </div>
            <div class="sg-secret">{finding.redacted_value}</div>
            <div class="sg-fix">{finding.recommendation}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Main workspace header + wide scan console
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="sg-topbar">
        <div>
            <div class="sg-brand">
                <div class="sg-brand-mark">🛡</div>
                <div class="sg-brand-name">Secret<span>Guard</span></div>
            </div>
            <div class="sg-brand-sub">SOURCE CODE SECURITY SCANNER</div>
        </div>
        <div class="sg-topbar-tag">LOCAL ANALYSIS · PRIVACY FIRST</div>
    </div>
    <div class="sg-scan-console">
        <div class="sg-console-heading">Scan Console</div>
        <div class="sg-console-copy">
            Select a project folder to inspect source and configuration files for exposed credentials.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

path_col, action_col = st.columns([5.2, 1.35], gap="medium")
with path_col:
    target_path = st.text_input(
        "Project folder path",
        value=".",
        placeholder="C:/Projects/MyApp",
        help="Enter the folder to scan recursively. You can paste a full path here.",
    )
with action_col:
    st.markdown("<div style='height:1.82rem'></div>", unsafe_allow_html=True)
    scan_clicked = st.button("🔍  Run Security Scan", type="primary", use_container_width=True)

st.markdown(
    """
    <div class="sg-engine-strip">
        <span>DETECTION ENGINE</span>
        <span class="sg-engine-chip">REGEX · known patterns</span>
        <span class="sg-engine-chip">ENTROPY · random values</span>
        <span class="sg-engine-chip">CONTEXT · false-positive checks</span>
        <span style="margin-left:auto">Matched values remain redacted in the UI</span>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Scan state
# ---------------------------------------------------------------------------
if "summary" not in st.session_state:
    st.session_state.summary = None

if scan_clicked:
    # Strip whitespace and any surrounding quotes — Windows' "Copy as
    # path" wraps the value in quotes, which would otherwise become
    # part of the path and never match a real folder.
    cleaned_path = target_path.strip().strip('"').strip("'")
    resolved_path = Path(cleaned_path).expanduser().resolve()

    if not resolved_path.exists():
        st.error(
            f"Path does not exist: `{resolved_path}`\n\n"
            f"You entered: `{target_path}`"
        )
        st.stop()

    if not resolved_path.is_dir():
        st.error(f"Please select a directory: `{resolved_path}`")
        st.stop()

    with st.spinner("Scanning source files · analysing patterns · checking context..."):
        st.session_state.summary = scan_directory(resolved_path)

    st.toast("Scan complete", icon="🛡️")

summary = st.session_state.summary
has_scan = summary is not None
finding_count = summary.total_findings if summary else 0
state = state_styles(has_scan, finding_count)


# ---------------------------------------------------------------------------
# Hero
# ---------------------------------------------------------------------------
state_css = (
    f"--state-color:{state['color']};"
    f"--state-border:{state['border']};"
    f"--state-bg:{state['bg']};"
    f"--state-core:{state['core']};"
    f"--state-shadow:{state['shadow']};"
)

hero_detail = state["detail"]
if summary is not None and summary.total_findings > 0:
    hero_detail = (
        f"{summary.total_findings} finding(s) · "
        f"{summary.severity_breakdown[SeverityEnum.CRITICAL]} critical"
    )

st.markdown(
    f"""
    <div class="sg-hero {state['class']}" style="{state_css}">
        <svg class="sg-hero-wave" viewBox="0 0 1000 300" preserveAspectRatio="none">
            <defs>
                <linearGradient id="sgWaveFade" x1="0" x2="1" y1="0" y2="0">
                    <stop offset="0" stop-color="#fff" stop-opacity="0"/>
                    <stop offset="0.18" stop-color="#fff" stop-opacity="1"/>
                    <stop offset="0.82" stop-color="#fff" stop-opacity="1"/>
                    <stop offset="1" stop-color="#fff" stop-opacity="0"/>
                </linearGradient>
                <mask id="sgWaveMask">
                    <rect width="1000" height="300" fill="url(#sgWaveFade)"/>
                </mask>
            </defs>
            <path
                mask="url(#sgWaveMask)"
                d="M0,205 C90,150 170,255 260,215 C350,175 420,250 510,210
                   C600,170 660,260 760,220 C850,185 910,235 1000,205
                   L1000,300 L0,300 Z"
            />
        </svg>
        <div class="sg-hero-grain"></div>
        <div class="sg-hero-top">
            <div>
                <div class="sg-kicker">SECURITY WORKSPACE</div>
                <div class="sg-hero-title">Scan. Detect. Protect.</div>
                <div class="sg-hero-copy">
                    Inspect source and configuration files for recognizable credentials,
                    high-randomness values and suspicious secret-like context.
                </div>
            </div>
            <div class="sg-state-pill">
                <span class="sg-state-dot"></span>{state['label']}
            </div>
        </div>
        <div class="sg-orb-wrap">
            <div class="sg-orb">🛡</div>
        </div>
        <div class="sg-state-text">
            <div class="sg-state-main">{state['label']}</div>
            <div class="sg-state-detail">{hero_detail}</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# No scan yet
# ---------------------------------------------------------------------------
if summary is None:
    st.markdown(
        """
        <div class="sg-empty">
            <div class="sg-empty-icon">◈</div>
            <div class="sg-empty-title">Ready for your first scan</div>
            <div class="sg-empty-copy">
                Choose a project folder in the Scan Console, then run the security scan.
            </div>
        </div>
        <div class="sg-footer">SecretGuard · Source Code Secret & API Key Scanner</div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
breakdown = summary.severity_breakdown
critical = breakdown[SeverityEnum.CRITICAL]

st.markdown(
    """
    <div class="sg-section-head">
        <div class="sg-section-title">Scan Overview</div>
        <div class="sg-section-caption">Live results from the selected project</div>
    </div>
    """,
    unsafe_allow_html=True,
)

metrics = st.columns(4)
metric_data = [
    ("FILES SCANNED", str(summary.files_scanned), "source/config files inspected", ""),
    ("FINDINGS", str(summary.total_findings), "detected values", "alert" if summary.total_findings else "blue"),
    ("CRITICAL", str(critical), "highest severity", "alert" if critical else ""),
    (
        "SCAN TIME",
        f"{summary.duration_seconds:.3f}s" if summary.duration_seconds is not None else "—",
        "analysis duration",
        "",
    ),
]

for col, (label, value, note, value_class) in zip(metrics, metric_data):
    col.markdown(
        f"""
        <div class="sg-metric">
            <div class="sg-metric-label">{label}</div>
            <div class="sg-metric-value {value_class}">{value}</div>
            <div class="sg-metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Clean result state
# ---------------------------------------------------------------------------
if summary.total_findings == 0:
    st.markdown(
        """
        <div class="sg-section-head">
            <div class="sg-section-title">Security Result</div>
            <div class="sg-section-caption">No findings returned by the detection engine</div>
        </div>
        <div class="sg-empty">
            <div class="sg-empty-icon">✓</div>
            <div class="sg-empty-title">No secrets detected</div>
            <div class="sg-empty-copy">
                The scanned files produced no configured regex or entropy findings.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.download_button(
        "↓  Download JSON report",
        data=to_json(summary),
        file_name="secretguard_report.json",
        mime="application/json",
    )
    st.markdown(
        '<div class="sg-footer">SecretGuard · Scan complete · No findings</div>',
        unsafe_allow_html=True,
    )
    st.stop()


# ---------------------------------------------------------------------------
# Detection overview charts
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="sg-section-head">
        <div class="sg-section-title">Detection Overview</div>
        <div class="sg-section-caption">Where the findings came from</div>
    </div>
    """,
    unsafe_allow_html=True,
)

chart_left, chart_right = st.columns(2)

with chart_left:
    labels = [s.value for s in SEVERITY_ORDER if breakdown[s] > 0]
    values = [breakdown[s] for s in SEVERITY_ORDER if breakdown[s] > 0]
    colors = [SEVERITY_COLORS[s] for s in SEVERITY_ORDER if breakdown[s] > 0]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=.78,
            sort=False,
            marker=dict(colors=colors, line=dict(color=SURFACE, width=3)),
            textinfo="none",
            hovertemplate="%{label}: %{value}<extra></extra>",
        )
    )
    fig.update_layout(
        height=260,
        margin=dict(t=5, b=5, l=5, r=5),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(
            orientation="h",
            y=-.02,
            x=.5,
            xanchor="center",
            font=dict(color=MUTED, size=10),
        ),
        annotations=[
            dict(
                text=f"<b>{summary.total_findings}</b><br><span style='font-size:10px'>findings</span>",
                x=.5,
                y=.5,
                showarrow=False,
                font=dict(family="Space Grotesk", size=23, color=TEXT),
            )
        ],
    )
    st.markdown('<div class="sg-panel">', unsafe_allow_html=True)
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)

with chart_right:
    method_counts: dict[str, int] = {}
    for finding in summary.findings:
        method = finding.detection_method.value
        method_counts[method] = method_counts.get(method, 0) + 1

    method_labels = list(method_counts.keys())
    method_values = list(method_counts.values())

    fig2 = go.Figure(
        go.Bar(
            x=method_values,
            y=method_labels,
            orientation="h",
            marker=dict(color=BLUE, line=dict(width=0)),
            hovertemplate="%{y}: %{x}<extra></extra>",
        )
    )
    fig2.update_layout(
        height=260,
        margin=dict(t=22, b=18, l=10, r=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, zeroline=False, color=MUTED, dtick=1),
        yaxis=dict(showgrid=False, zeroline=False, color=TEXT),
    )
    st.markdown('<div class="sg-panel">', unsafe_allow_html=True)
    st.plotly_chart(fig2, width="stretch", config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Findings list
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="sg-section-head">
        <div class="sg-section-title">Findings</div>
        <div class="sg-section-caption">Raw matched values stay hidden</div>
    </div>
    """,
    unsafe_allow_html=True,
)

filter_a, filter_b, filter_c = st.columns([1, 1, 1.8])

available_severities = [s.value for s in SEVERITY_ORDER if breakdown[s] > 0]
available_methods = sorted({finding.detection_method.value for finding in summary.findings})

selected_severities = filter_a.multiselect(
    "Severity",
    available_severities,
    default=available_severities,
    placeholder="All severities",
    label_visibility="collapsed",
)
selected_methods = filter_b.multiselect(
    "Detection method",
    available_methods,
    default=available_methods,
    placeholder="All methods",
    label_visibility="collapsed",
)
search_term = filter_c.text_input(
    "Search",
    placeholder="Search file path or finding type...",
    label_visibility="collapsed",
)

filtered = [
    finding
    for finding in summary.findings
    if finding.severity.value in selected_severities
    and finding.detection_method.value in selected_methods
    and (
        not search_term
        or search_term.lower() in str(finding.file_path).lower()
        or search_term.lower() in finding.secret_type.lower()
    )
]
filtered.sort(key=lambda f: (SEVERITY_RANK[f.severity], str(f.file_path), f.line_number))

st.caption(f"Showing {len(filtered)} of {summary.total_findings} findings")

if not filtered:
    st.info("No findings match the current filters.")
else:
    with st.container(height=500):
        for finding in filtered:
            render_finding(finding)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="sg-section-head">
        <div class="sg-section-title">Export</div>
        <div class="sg-section-caption">Save this scan as a JSON report</div>
    </div>
    """,
    unsafe_allow_html=True,
)

export_left, export_right = st.columns([1, 3])
with export_left:
    st.download_button(
        "↓  Download JSON report",
        data=to_json(summary),
        file_name="secretguard_report.json",
        mime="application/json",
        width="stretch",
    )
with export_right:
    st.caption(
        "The dashboard displays redacted values. The exported report uses the scanner's existing JSON reporter."
    )

st.markdown(
    '<div class="sg-footer">SecretGuard · Source Code Secret & API Key Scanner · Local analysis</div>',
    unsafe_allow_html=True,
)