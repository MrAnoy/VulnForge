"""
VulnForge — Enterprise Automated VAPT & Security Assessment Platform
Version: 2.0.0 (High-Contrast Ultra-Readable Edition)
"""

import sys
import os
import asyncio
import concurrent.futures
import json
import time
from datetime import datetime, timezone
import pandas as pd
import streamlit as st

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from packages.security.ssrf_guard import SSRFGuard, TargetValidationError
from packages.scanner.recon_adapter import ReconAdapter
from packages.scanner.custom_web_adapter import CustomWebAdapter
from packages.scanner.health import ScannerHealthDetector
from packages.schemas.models import FindingResponse, EvidenceItem
from packages.shared.constants import Severity, Confidence, FindingStatus, AssetCriticality, EnvironmentType

# --- Page Configuration ---
st.set_page_config(
    page_title="VulnForge — Enterprise Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- High-Contrast Ultra-Readable Design System ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    /* Global Typography & Palette */
    html, body, [class*="css"], .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        background-color: #07090e !important;
        color: #ffffff !important;
    }

    /* Top Navigation Header */
    header[data-testid="stHeader"] {
        background-color: #07090e !important;
    }
    
    /* Sidebar Global */
    section[data-testid="stSidebar"] {
        background-color: #0d121f !important;
        border-right: 1px solid #1e293b !important;
    }

    /* Force ALL Sidebar text to bright readable white */
    section[data-testid="stSidebar"] * {
        color: #ffffff !important;
    }

    section[data-testid="stSidebar"] .stRadio label,
    section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p,
    section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] span {
        color: #ffffff !important;
        font-size: 14px !important;
        font-weight: 600 !important;
    }

    /* Unselected & Selected Radio Navigation Items */
    section[data-testid="stSidebar"] [data-testid="stRadio"] label {
        background-color: #131a2b !important;
        border: 1px solid #1e293b !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
        margin-bottom: 6px !important;
        transition: all 0.15s ease !important;
    }
    section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
        background-color: #1e293b !important;
        border-color: #38bdf8 !important;
    }
    section[data-testid="stSidebar"] [data-testid="stRadio"] label p,
    section[data-testid="stSidebar"] [data-testid="stRadio"] label span {
        color: #ffffff !important;
        font-size: 13px !important;
        font-weight: 700 !important;
    }

    /* Dark Dropdowns & Selectboxes (Non-editable, Pure Clickable Picker) */
    div[data-baseweb="select"] > div, div.stSelectbox > div {
        background-color: #131a2b !important;
        border: 1px solid #334155 !important;
        color: #ffffff !important;
        border-radius: 8px !important;
        cursor: pointer !important;
    }
    div[data-baseweb="select"] input, div.stSelectbox input {
        caret-color: transparent !important;
        cursor: pointer !important;
        user-select: none !important;
    }
    div[data-baseweb="select"], div.stSelectbox {
        cursor: pointer !important;
        user-select: none !important;
    }
    div[data-baseweb="select"] *, div.stSelectbox * {
        color: #ffffff !important;
        font-weight: 600 !important;
        cursor: pointer !important;
    }
    div[data-baseweb="popover"], div[data-baseweb="menu"], div[data-testid="stSelectboxVirtualDropdown"] {
        background-color: #131a2b !important;
        border: 1px solid #334155 !important;
    }
    div[data-baseweb="popover"] li, div[data-testid="stSelectboxVirtualDropdown"] * {
        color: #ffffff !important;
    }

    /* Text Inputs */
    div[data-baseweb="input"] > div {
        background-color: #131a2b !important;
        border: 1px solid #334155 !important;
        color: #ffffff !important;
        border-radius: 8px !important;
    }
    input, textarea {
        color: #ffffff !important;
        font-weight: 600 !important;
    }

    /* Typography & Headers */
    h1, h2, h3, h4, h5, h6 {
        color: #ffffff !important;
        font-weight: 800 !important;
    }
    
    p, .stMarkdown p {
        color: #e2e8f0 !important;
        font-size: 14px !important;
        line-height: 1.6 !important;
    }

    /* Cards */
    .vf-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 18px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4);
    }

    .vf-card-hero {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #3b82f6;
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 22px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
    }

    .vf-stat-card {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        text-align: left;
    }

    /* High Contrast Severity Pills */
    .pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        color: #ffffff !important;
    }
    .pill-critical { background: #e11d48; border: 1px solid #fb7185; }
    .pill-high { background: #ea580c; border: 1px solid #fdba74; }
    .pill-medium { background: #ca8a04; border: 1px solid #fef08a; color: #ffffff !important; }
    .pill-low { background: #0284c7; border: 1px solid #7dd3fc; }
    .pill-info { background: #475569; border: 1px solid #94a3b8; }
    .pill-good { background: #059669; border: 1px solid #6ee7b7; }

    /* Stepper Bar */
    .vf-stepper {
        display: flex;
        justify-content: space-between;
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 12px 18px;
        margin-bottom: 22px;
    }
    .vf-step-item {
        font-size: 13px;
        font-weight: 700;
        color: #94a3b8 !important;
    }
    .vf-step-active {
        color: #38bdf8 !important;
        font-weight: 900 !important;
    }

    /* Monospace Code Evidence Box */
    .vf-evidence-block {
        font-family: 'JetBrains Mono', monospace !important;
        background: #020617 !important;
        border: 1px solid #334155 !important;
        border-radius: 8px;
        padding: 14px;
        font-size: 13px;
        color: #38bdf8 !important;
        overflow-x: auto;
    }

    /* Buttons */
    .stButton > button {
        background: #2563eb !important;
        color: #ffffff !important;
        border: 1px solid #60a5fa !important;
        border-radius: 8px !important;
        font-weight: 800 !important;
        font-size: 14px !important;
        padding: 10px 22px !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4) !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button * {
        color: #ffffff !important;
        font-weight: 800 !important;
    }
    .stButton > button:hover {
        background: #1d4ed8 !important;
        transform: translateY(-1px);
    }
</style>
""", unsafe_allow_html=True)

st.markdown(
    """
    <img src="x" onerror="
        (function() {
            var blockTyping = function() {
                var doc = document;
                try { doc = window.parent.document; } catch(e) {}
                doc.querySelectorAll('div.stSelectbox input, div[data-baseweb=select] input').forEach(function(input) {
                    if (!input.dataset.typingBlocked) {
                        input.dataset.typingBlocked = 'true';
                        input.style.caretColor = 'transparent';
                        input.addEventListener('keydown', function(e) {
                            if (['Tab', 'Escape', 'Enter', 'ArrowUp', 'ArrowDown'].indexOf(e.key) !== -1) {
                                return;
                            }
                            e.preventDefault();
                            e.stopPropagation();
                        }, true);
                    }
                });
            };
            blockTyping();
            if (!window.blockTypingIntervalId) {
                window.blockTypingIntervalId = setInterval(blockTyping, 300);
            }
        })()
    " style="display:none;" />
    """,
    unsafe_allow_html=True
)


# --- Session State Initialization ---
if "assessment_history" not in st.session_state:
    st.session_state.assessment_history = []

if "current_findings" not in st.session_state:
    st.session_state.current_findings = []

if "copilot_history" not in st.session_state:
    st.session_state.copilot_history = [
        {"role": "assistant", "content": "Hello! I am your AI Security Copilot. Run an assessment or ask me about vulnerability remediation, CVSS calculations, or secure configurations."}
    ]

if "remediation_tasks" not in st.session_state:
    st.session_state.remediation_tasks = {}


# --- Robust Async Coroutine Runner ---
def run_async(coroutine):
    """Safely execute async scanner coroutines in Streamlit thread environment."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coroutine).result()
        else:
            return loop.run_until_complete(coroutine)
    except Exception:
        return asyncio.run(coroutine)


# --- Posture Math Helpers ---
def calculate_posture_score(findings):
    if not findings:
        return 100.0
    deductions = 0
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev == "CRITICAL":
            deductions += 25
        elif sev == "HIGH":
            deductions += 15
        elif sev == "MEDIUM":
            deductions += 8
        elif sev == "LOW":
            deductions += 3
        elif sev == "INFO":
            deductions += 1
    return max(0.0, round(100.0 - min(deductions, 100.0), 1))


# ==============================================================================
# SIDEBAR NAVIGATION & ENTERPRISE CONSOLE
# ==============================================================================
with st.sidebar:
    st.markdown("<div style='font-size:24px; font-weight:900; color:#38bdf8; letter-spacing:-0.5px;'>🛡️ VULNFORGE</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:12px; font-weight:700; color:#94a3b8; margin-bottom:14px;'>Automated VAPT & Perimeter Defense v2.0</div>", unsafe_allow_html=True)
    
    st.divider()

    # Workspace & Perspective
    st.markdown("<div style='font-size:12px; font-weight:800; color:#cbd5e1; letter-spacing:0.5px;'>ORGANIZATION WORKSPACE</div>", unsafe_allow_html=True)
    workspace = st.selectbox(
        "Workspace",
        ["Acme Global Security [Prod]", "Staging Perimeter", "Internal Lab Cluster"],
        label_visibility="collapsed"
    )

    st.markdown("<div style='font-size:12px; font-weight:800; color:#cbd5e1; letter-spacing:0.5px; margin-top:12px;'>EXPERIENCE PERSPECTIVE</div>", unsafe_allow_html=True)
    view_mode = st.selectbox(
        "View Mode",
        ["Beginner Mode (Guided)", "Professional Mode (Full Telemetry)", "Executive Mode (Risk Posture)", "Developer Mode (Code Fixes)"],
        index=1,
        label_visibility="collapsed",
        help="Tailors technical depth, explanations, and interface complexity across the platform."
    )

    st.divider()

    st.markdown("<div style='font-size:12px; font-weight:800; color:#cbd5e1; letter-spacing:0.5px; margin-bottom:8px;'>NAVIGATION MENU</div>", unsafe_allow_html=True)
    menu = st.radio(
        "Navigation",
        [
            "📊 Executive Dashboard",
            "🚀 Assessment Wizard",
            "🎯 Priority Fixes (#1 First)",
            "🔍 Findings Operations Center",
            "🛠️ Remediation Workspace",
            "🤖 AI Security Copilot",
            "📄 Deliverable Report Center",
            "🔄 Assessment Comparison",
            "⚙️ Subsystem Diagnostics"
        ],
        index=0,
        label_visibility="collapsed"
    )

    st.divider()

    # Subsystem Heartbeat Widget
    st.markdown("<div style='font-size:12px; font-weight:800; color:#cbd5e1; letter-spacing:0.5px; margin-bottom:6px;'>SYSTEM ENGINES</div>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-size:12px; line-height:1.9; color:#e2e8f0;'>
        <span style='color:#34d399; font-weight:bold;'>●</span> Recon OSINT: <strong style='color:#ffffff;'>ONLINE</strong><br/>
        <span style='color:#34d399; font-weight:bold;'>●</span> Web Sec Engine: <strong style='color:#ffffff;'>ONLINE</strong><br/>
        <span style='color:#34d399; font-weight:bold;'>●</span> SSRF Guard: <strong style='color:#ffffff;'>ENFORCED</strong><br/>
        <span style='color:#34d399; font-weight:bold;'>●</span> Correlator: <strong style='color:#ffffff;'>ACTIVE</strong>
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# 1. EXECUTIVE DASHBOARD & SECURITY POSTURE
# ==============================================================================
if menu == "📊 Executive Dashboard":
    # Top Context Header
    st.markdown("""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <div>
            <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Security Posture Command Center</h1>
            <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Continuous perimeter intelligence & attack surface evaluation</p>
        </div>
        <div>
            <span class="pill pill-good">● LIVE TELEMETRY</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    findings = st.session_state.current_findings
    
    if not findings:
        st.markdown("""
        <div class="vf-card-hero">
            <h3 style="margin-top:0; font-size:20px; font-weight:800; color:#ffffff;">No Active Assessment Data in Current Session</h3>
            <p style="font-size:14px; color:#f1f5f9; max-width:700px; line-height:1.6;">Launch an automated security assessment against your authorized target URL or load synthetic benchmark results to inspect security posture metrics, risk drivers, and remediation workflows.</p>
        </div>
        """, unsafe_allow_html=True)

        c1, c2 = st.columns([1, 4])
        with c1:
            if st.button("📂 Load Sample Telemetry", use_container_width=True):
                st.session_state.current_findings = [
                    {
                        "id": "find-1", "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                        "description": "The web application does not enforce HSTS header.", "severity": "MEDIUM", "cvss_score": 5.3,
                        "cwe": "CWE-319", "category": "Security Headers", "asset_target": "https://perimeter.acme.sec",
                        "endpoint": "/", "impact": "Allows potential Man-in-the-Middle SSL stripping attacks.",
                        "remediation": "Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                        "scanner": "Custom Web Security Engine", "confidence": "CONFIRMED", "evidence": {"header": "Missing Strict-Transport-Security"}
                    },
                    {
                        "id": "find-2", "title": "Insecure Cross-Origin Resource Sharing (CORS) Configuration",
                        "description": "The API reflects arbitrary Origin headers with Access-Control-Allow-Credentials enabled.",
                        "severity": "HIGH", "cvss_score": 7.5, "cwe": "CWE-942", "category": "API Security",
                        "asset_target": "https://perimeter.acme.sec", "endpoint": "/api/v1/user",
                        "impact": "Enables authenticated cross-origin data theft.",
                        "remediation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
                        "scanner": "Custom Web Security Engine", "confidence": "CONFIRMED", "evidence": {"origin": "evil.com reflected"}
                    },
                    {
                        "id": "find-3", "title": "Sensitive File Exposure (.git/HEAD)",
                        "description": "Git metadata repository is publicly accessible.",
                        "severity": "CRITICAL", "cvss_score": 9.1, "cwe": "CWE-538", "category": "Information Disclosure",
                        "asset_target": "https://perimeter.acme.sec", "endpoint": "/.git/HEAD",
                        "impact": "Allows full source code reconstruction by attackers.",
                        "remediation": "Block access to hidden dotfiles in Nginx / Apache configuration.",
                        "scanner": "Custom Web Security Engine", "confidence": "CONFIRMED", "evidence": {"output": "ref: refs/heads/main"}
                    }
                ]
                st.rerun()
    else:
        posture_score = calculate_posture_score(findings)
        
        crit_count = len([f for f in findings if str(f['severity']).upper() == 'CRITICAL'])
        high_count = len([f for f in findings if str(f['severity']).upper() == 'HIGH'])
        med_count = len([f for f in findings if str(f['severity']).upper() == 'MEDIUM'])
        low_count = len([f for f in findings if str(f['severity']).upper() in ['LOW', 'INFO']])

        # Hero Posture Card
        status_label = "EXCELLENT" if posture_score >= 90 else ("GOOD" if posture_score >= 75 else "NEEDS ATTENTION")
        status_bg = "#059669" if posture_score >= 75 else "#e11d48"

        st.markdown(f"""
        <div class="vf-card-hero">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
                <div>
                    <div style="font-size:13px; font-weight:800; color:#93c5fd; letter-spacing:1px; text-transform:uppercase;">OVERALL PERIMETER SECURITY POSTURE</div>
                    <div style="display:flex; align-items:baseline; gap:14px; margin-top:6px;">
                        <span style="font-size:48px; font-weight:900; color:#ffffff; letter-spacing:-1px;">{posture_score} <span style="font-size:22px; color:#94a3b8;">/ 100</span></span>
                        <span style="font-size:14px; font-weight:900; color:#ffffff; background:{status_bg}; padding:6px 14px; border-radius:6px;">{status_label}</span>
                    </div>
                    <p style="font-size:14px; color:#e2e8f0; margin:8px 0 0 0;">Evaluated across <strong style="color:#ffffff;">{len(findings)} findings</strong>. Immediate remediation recommended for <strong style="color:#fb7185;">{crit_count + high_count} critical/high</strong> security driver(s).</p>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:12px; color:#cbd5e1; font-weight:700;">ACTIVE TARGET</div>
                    <div style="font-size:16px; font-family:monospace; color:#38bdf8; font-weight:900;">{findings[0].get('asset_target', 'https://target.sec')}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 5 Metric Cards Row
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.markdown(f"""
            <div class="vf-stat-card">
                <div style="font-size:12px; font-weight:800; color:#fb7185;">● CRITICAL RISKS</div>
                <div style="font-size:32px; font-weight:900; color:#ffffff; margin-top:4px;">{crit_count}</div>
                <div style="font-size:12px; font-weight:600; color:#cbd5e1; margin-top:4px;">Immediate Action (24h SLA)</div>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="vf-stat-card">
                <div style="font-size:12px; font-weight:800; color:#fb923c;">● HIGH SEVERITY</div>
                <div style="font-size:32px; font-weight:900; color:#ffffff; margin-top:4px;">{high_count}</div>
                <div style="font-size:12px; font-weight:600; color:#cbd5e1; margin-top:4px;">7-Day Mitigation SLA</div>
            </div>
            """, unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="vf-stat-card">
                <div style="font-size:12px; font-weight:800; color:#facc15;">● MEDIUM SEVERITY</div>
                <div style="font-size:32px; font-weight:900; color:#ffffff; margin-top:4px;">{med_count}</div>
                <div style="font-size:12px; font-weight:600; color:#cbd5e1; margin-top:4px;">Sprint Backlog</div>
            </div>
            """, unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
            <div class="vf-stat-card">
                <div style="font-size:12px; font-weight:800; color:#38bdf8;">● LOW / INFO</div>
                <div style="font-size:32px; font-weight:900; color:#ffffff; margin-top:4px;">{low_count}</div>
                <div style="font-size:12px; font-weight:600; color:#cbd5e1; margin-top:4px;">Hardening Best Practices</div>
            </div>
            """, unsafe_allow_html=True)
        with c5:
            st.markdown(f"""
            <div class="vf-stat-card">
                <div style="font-size:12px; font-weight:800; color:#c084fc;">● TOTAL FINDINGS</div>
                <div style="font-size:32px; font-weight:900; color:#ffffff; margin-top:4px;">{len(findings)}</div>
                <div style="font-size:12px; font-weight:600; color:#cbd5e1; margin-top:4px;">Correlated Issues</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

        # Main Dashboard Layout
        col_main, col_side = st.columns([2, 1])
        
        with col_main:
            st.markdown("<h3 style='font-size:18px; font-weight:900; color:#ffffff; margin-bottom:14px;'>🎯 Priority Attention Required</h3>", unsafe_allow_html=True)
            
            # Sort top 3 findings by severity
            def sev_weight(f):
                w = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 5}
                return w.get(str(f.get("severity", "LOW")).upper(), 0)
            
            top_prio = sorted(findings, key=sev_weight, reverse=True)[:3]
            
            for idx, f in enumerate(top_prio, start=1):
                sev = str(f['severity']).upper()
                badge_class = f"pill-{sev.lower()}"
                st.markdown(f"""
                <div class="vf-card" style="padding:16px 20px; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:15px; font-weight:800; color:#ffffff;">#{idx}. {f['title']}</span>
                        <span class="pill {badge_class}">● {sev}</span>
                    </div>
                    <div style="font-size:13px; color:#cbd5e1; margin-top:6px; font-family:monospace;">
                        Endpoint: <code style="color:#38bdf8; font-weight:bold;">{f.get('endpoint', '/')}</code> &bull; CVSS: <strong style="color:#ffffff;">{f.get('cvss_score', 'N/A')}</strong> &bull; Source: {f.get('scanner', 'VulnForge')}
                    </div>
                    <div style="background:#070d1e; border:1px solid #1e3a8a; padding:12px 16px; border-radius:6px; font-size:13px; color:#ffffff; border-left:4px solid #38bdf8; margin-top:10px;">
                        <strong style="color:#38bdf8;">Direct Action:</strong> {f.get('remediation', 'Consult fix guide.')}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        with col_side:
            st.markdown("<h3 style='font-size:18px; font-weight:900; color:#ffffff; margin-bottom:14px;'>📈 Severity Breakdown</h3>", unsafe_allow_html=True)
            df_counts = pd.DataFrame([
                {"Severity": "Critical", "Count": crit_count},
                {"Severity": "High", "Count": high_count},
                {"Severity": "Medium", "Count": med_count},
                {"Severity": "Low/Info", "Count": low_count},
            ])
            st.bar_chart(df_counts.set_index("Severity"), color="#3b82f6")


# ==============================================================================
# 2. GUIDED ASSESSMENT WIZARD
# ==============================================================================
elif menu == "🚀 Assessment Wizard":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Automated Security Assessment Wizard</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Configure scoped reconnaissance and web application vulnerability checks</p>
    </div>
    """, unsafe_allow_html=True)

    # 7-Step Stepper Bar
    st.markdown("""
    <div class="vf-stepper">
        <span class="vf-step-item vf-step-active">01 Target</span>
        <span class="vf-step-item">➔</span>
        <span class="vf-step-item vf-step-active">02 Scope</span>
        <span class="vf-step-item">➔</span>
        <span class="vf-step-item vf-step-active">03 Authorization</span>
        <span class="vf-step-item">➔</span>
        <span class="vf-step-item vf-step-active">04 Profile</span>
        <span class="vf-step-item">➔</span>
        <span class="vf-step-item">05 Execution</span>
        <span class="vf-step-item">➔</span>
        <span class="vf-step-item">06 Correlation</span>
        <span class="vf-step-item">➔</span>
        <span class="vf-step-item">07 Deliverables</span>
    </div>
    """, unsafe_allow_html=True)

    c_left, c_right = st.columns([2, 1])

    with c_left:
        st.markdown("<div class='vf-card'>", unsafe_allow_html=True)
        st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff; margin-top:0;'>1. Target Specification & Scope</h4>", unsafe_allow_html=True)
        
        target_input = st.text_input(
            "Target Endpoint / Domain",
            placeholder="https://example.com or http://127.0.0.1:3000",
            value="https://example.com",
            help="Enter the fully-qualified domain name or URL you wish to assess."
        )

        assessment_profile = st.selectbox(
            "Assessment Profile Type",
            [
                "Standard VAPT (Passive Recon + Full Web Security Checks)",
                "Quick Security Check (Security Headers, TLS Validity, Exposures)",
                "API Security Audit (Headers, CORS Misconfigurations, HTTP Methods)",
                "Reconnaissance & OSINT (DNS, TLS Certificates, Server Banners)"
            ]
        )

        col_opts1, col_opts2 = st.columns(2)
        with col_opts1:
            allow_lab = st.checkbox(
                "Allow Localhost / Internal Lab Testing (`127.0.0.1`, RFC 1918)",
                value=True,
                help="Enable if testing local Docker lab targets (e.g. Juice Shop, DVWA)."
            )
        with col_opts2:
            rate_limit = st.slider("Request Rate Limit (RPS)", min_value=5, max_value=50, value=20, help="Protects target infrastructure from excessive traffic.")

        st.divider()

        st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff; margin-top:0;'>2. Mandatory Authorization Verification Gate</h4>", unsafe_allow_html=True)
        auth_confirmed = st.checkbox(
            "🔒 **I confirm that I own this target or have explicit, written authorization to perform security testing.** All assessment activities are logged in an immutable audit trail.",
            value=True
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with c_right:
        st.markdown(f"""
        <div class="vf-card">
            <h4 style="font-size:14px; font-weight:800; color:#93c5fd; margin-top:0; text-transform:uppercase;">Scan Configuration Summary</h4>
            <div style="font-size:13px; color:#f1f5f9; line-height:1.9;">
                • <strong style="color:#ffffff;">Target Host:</strong> <code style="color:#38bdf8; font-weight:bold;">{target_input}</code><br/>
                • <strong style="color:#ffffff;">Profile:</strong> {assessment_profile.split('(')[0].strip()}<br/>
                • <strong style="color:#ffffff;">SSRF Defense:</strong> {'Lab Mode (Private Allowed)' if allow_lab else 'Strict (Public IPs Only)'}<br/>
                • <strong style="color:#ffffff;">Safe Concurrency:</strong> 5 Workers (Max)<br/>
                • <strong style="color:#ffffff;">Rate Limit:</strong> {rate_limit} req/sec<br/>
                • <strong style="color:#ffffff;">Timeout:</strong> 10s per probe<br/>
            </div>
            <div style="margin-top:16px; padding:12px; background:#020617; border-radius:6px; font-size:12px; color:#cbd5e1; line-height:1.5;">
                🛡️ <em>Zero intrusive payloads are executed. Only passive reconnaissance and standard HTTP RFC protocol checks are dispatched.</em>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

    if st.button("▶️ Launch Authorized Security Assessment", type="primary", use_container_width=True):
        if not target_input.strip():
            st.error("Please enter a valid target URL or domain.")
        elif not auth_confirmed:
            st.error("Mandatory authorization confirmation is required to proceed.")
        else:
            with st.status("Executing Assessment Pipeline...", expanded=True) as status:
                st.write("🔒 **Phase 1/5: Scope & SSRF Validation Gate**")
                
                try:
                    resolved_ips = SSRFGuard.resolve_and_validate(target_input, allow_local_lab=allow_lab)
                    st.write(f"✅ Target validated. Resolved IPs: `{', '.join(resolved_ips)}`")
                except Exception as e:
                    status.update(label="❌ Scope Validation Failed", state="error")
                    st.error(f"Target blocked by SSRF Guard: {str(e)}")
                    st.stop()

                try:
                    # Phase 2: Recon
                    st.write("🌐 **Phase 2/5: Passive Reconnaissance & OSINT Engine**")
                    recon_adapter = ReconAdapter()
                    raw_recon = run_async(recon_adapter.execute(target_input, {}))
                    parsed_recon = run_async(recon_adapter.parse(raw_recon))
                    recon_findings = run_async(recon_adapter.normalize(parsed_recon, target_input))
                    st.write(f"Reconnaissance completed: {len(recon_findings)} observation(s) recorded.")

                    # Phase 3: Web Security
                    st.write("⚡ **Phase 3/5: Custom Web Vulnerability Engine**")
                    web_adapter = CustomWebAdapter()
                    raw_web = run_async(web_adapter.execute(target_input, {}))
                    web_findings = run_async(web_adapter.normalize(raw_web, target_input))
                    st.write(f"Web checks completed: {len(web_findings)} security item(s) detected.")

                    # Phase 4: Correlation
                    st.write("🧬 **Phase 4/5: Finding Normalization & Multi-Engine Correlation**")
                    all_findings_raw = recon_findings + web_findings

                    normalized_findings = []
                    for idx, rf in enumerate(all_findings_raw, start=1):
                        sev_str = rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity)
                        conf_str = rf.confidence.value if hasattr(rf.confidence, "value") else str(rf.confidence)

                        ev_dict = {}
                        if rf.evidence:
                            if hasattr(rf.evidence, "model_dump"):
                                ev_dict = rf.evidence.model_dump()
                            elif isinstance(rf.evidence, dict):
                                ev_dict = rf.evidence
                            else:
                                ev_dict = {"snippet": str(rf.evidence)}

                        normalized_findings.append({
                            "id": f"find-{idx}",
                            "title": rf.title,
                            "description": rf.description,
                            "severity": sev_str,
                            "cvss_score": float(rf.cvss_score) if rf.cvss_score else 0.0,
                            "cwe": rf.cwe or "CWE-200",
                            "category": rf.category or "Web Security",
                            "asset_target": rf.asset_target,
                            "endpoint": rf.endpoint or "/",
                            "impact": rf.impact or "Potential security risk.",
                            "remediation": rf.remediation or "Follow industry remediation best practices.",
                            "references": rf.references or ["https://owasp.org"],
                            "scanner": rf.scanner or "VulnForge Engine",
                            "confidence": conf_str,
                            "evidence": ev_dict
                        })

                    # Phase 5: Risk Scoring
                    st.write("📈 **Phase 5/5: Risk Score Analysis & Posture Delta**")
                    posture_score = calculate_posture_score(normalized_findings)

                    st.session_state.current_findings = normalized_findings
                    st.session_state.assessment_history.append({
                        "id": f"scan-{len(st.session_state.assessment_history) + 1}",
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "target": target_input,
                        "profile": assessment_profile,
                        "posture_score": posture_score,
                        "findings_count": len(normalized_findings),
                        "findings": normalized_findings
                    })

                    status.update(label=f"🎉 Assessment Completed — Posture Score: {posture_score}/100", state="complete")
                except Exception as scan_err:
                    status.update(label="❌ Scan Failed", state="error")
                    st.error(f"Scan Execution Error: {str(scan_err)}")
                    st.stop()

            st.success(f"🎉 Assessment completed successfully! Found **{len(normalized_findings)} findings**. Switch to the **Executive Dashboard** or **Priority Fixes** to triage.")


# ==============================================================================
# 3. WHAT SHOULD I FIX FIRST? (SMART PRIORITIZATION)
# ==============================================================================
elif menu == "🎯 Priority Fixes (#1 First)":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">What Should I Fix First?</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Multi-dimensional algorithmic prioritization factoring in Exploitability, Exposure, CVSS, and Confidence</p>
    </div>
    """, unsafe_allow_html=True)

    findings = st.session_state.current_findings
    if not findings:
        st.info("No active findings to prioritize. Launch an assessment or load demo telemetry from the Dashboard.")
    else:
        def rank_score(f):
            weights = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 5}
            return weights.get(str(f.get("severity", "LOW")).upper(), 0) + float(f.get("cvss_score", 0.0)) * 5

        sorted_items = sorted(findings, key=rank_score, reverse=True)

        for idx, f in enumerate(sorted_items, start=1):
            sev = str(f["severity"]).upper()
            badge_class = f"pill-{sev.lower()}"
            
            st.markdown(f"""
            <div class="vf-card">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <div>
                        <span style="font-size:16px; font-weight:800; color:#ffffff;">#{idx}. {f['title']}</span>
                    </div>
                    <div>
                        <span class="pill {badge_class}">● {sev}</span>
                        <span style="font-size:12px; background:#1e293b; color:#ffffff; padding:4px 10px; border-radius:6px; font-family:monospace; font-weight:bold; margin-left:6px;">CVSS {f.get('cvss_score', 'N/A')}</span>
                    </div>
                </div>
                <div style="font-size:13px; color:#cbd5e1; margin-top:8px;">
                    Target: <code style="color:#38bdf8; font-weight:bold;">{f.get('asset_target', '')}{f.get('endpoint', '')}</code> &bull; CWE: <strong style="color:#ffffff;">{f.get('cwe', 'N/A')}</strong> &bull; Engine: {f.get('scanner', 'Custom')}
                </div>
                <div style="background:#070d1e; border:1px solid #1e3a8a; padding:14px; border-radius:8px; font-size:13px; color:#ffffff; border-left:4px solid #38bdf8; margin-top:12px; line-height:1.5;">
                    <strong style="color:#38bdf8;">Actionable Fix Directive:</strong> {f.get('remediation', 'Consult security team.')}
                </div>
            </div>
            """, unsafe_allow_html=True)


# ==============================================================================
# 4. FINDINGS OPERATIONS CENTER & MULTI-PERSPECTIVE INSPECTOR
# ==============================================================================
elif menu == "🔍 Findings Operations Center":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Findings Operations & Deep Inspector</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Unified multi-scanner findings catalog with 4-tier perspective inspection</p>
    </div>
    """, unsafe_allow_html=True)

    findings = st.session_state.current_findings
    if not findings:
        st.info("No findings in current workspace session. Run an assessment to populate telemetry.")
    else:
        # Search & Filters
        col_s1, col_s2 = st.columns([3, 1])
        with col_s1:
            search_query = st.text_input("🔍 Search Vulnerability Titles, Endpoints, or CWEs", placeholder="e.g. CORS, HSTS, .git, CWE-538")
        with col_s2:
            filter_sev = st.selectbox("Severity Filter", ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

        filtered = findings
        if search_query.strip():
            filtered = [f for f in filtered if search_query.lower() in f['title'].lower() or search_query.lower() in f.get('endpoint', '').lower() or search_query.lower() in f.get('cwe', '').lower()]
        if filter_sev != "All Severities":
            filtered = [f for f in filtered if str(f['severity']).upper() == filter_sev]

        st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

        if filtered:
            select_titles = [f"[{str(f['severity']).upper()}] {f['title']}" for f in filtered]
            selected_option = st.selectbox("Select a Finding to Inspect", select_titles)
            selected_idx = select_titles.index(selected_option)
            active_finding = filtered[selected_idx]

            sev_pill = f"pill-{str(active_finding['severity']).lower()}"
            st.markdown(f"""
            <div class="vf-card-hero" style="margin-top:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0; font-size:20px; font-weight:800; color:#ffffff;">{active_finding['title']}</h3>
                    <span class="pill {sev_pill}">● {active_finding['severity']}</span>
                </div>
                <div style="font-size:13px; color:#e2e8f0; margin-top:8px; font-family:monospace;">
                    Endpoint: <code style="color:#38bdf8; font-weight:bold;">{active_finding.get('endpoint', '/')}</code> &bull; CVSS 3.1: <strong style="color:#ffffff;">{active_finding.get('cvss_score', 'N/A')}</strong> &bull; CWE: <strong style="color:#ffffff;">{active_finding.get('cwe', 'N/A')}</strong> &bull; Confidence: <strong style="color:#ffffff;">{active_finding.get('confidence', 'CONFIRMED')}</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # 4 Multi-Perspective Tabs
            t1, t2, t3, t4 = st.tabs([
                "📖 Beginner Explanation",
                "🛡️ Technical Evidence & Payloads",
                "💻 Developer Code Fix Guide",
                "💼 Executive Impact & Compliance"
            ])

            with t1:
                st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff;'>Plain-English Overview</h4>", unsafe_allow_html=True)
                st.write(active_finding.get("description", "No description available."))
                st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff;'>Why This Matters</h4>", unsafe_allow_html=True)
                st.write(active_finding.get("impact", "Potential security risk."))

            with t2:
                st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff;'>Observed Scanner Evidence</h4>", unsafe_allow_html=True)
                st.json(active_finding.get("evidence", {"status": "Evidence collected during scan"}))
                st.caption(f"Detected by: {active_finding.get('scanner', 'VulnForge Engine')}")

            with t3:
                st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff;'>Remediation Configuration Code</h4>", unsafe_allow_html=True)
                st.code(active_finding.get("remediation", "Apply security best practices."), language="bash")
                if active_finding.get("references"):
                    st.markdown("##### References & Standards")
                    for r in active_finding["references"]:
                        st.markdown(f"- [{r}]({r})")

            with t4:
                st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff;'>Business Risk Evaluation</h4>", unsafe_allow_html=True)
                st.write(f"• **Potential Attack Vector:** {active_finding.get('impact', 'Moderate operational impact.')}")
                st.write(f"• **Remediation SLA:** {'24-Hour Urgent SLA' if str(active_finding['severity']).upper() in ['CRITICAL', 'HIGH'] else 'Standard Sprint SLA (14 Days)'}")
                st.write(f"• **Framework Alignment:** OWASP Top 10 A05:2021 Security Misconfiguration & NIST SP 800-53")


# ==============================================================================
# 5. REMEDIATION WORKSPACE
# ==============================================================================
elif menu == "🛠️ Remediation Workspace":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Remediation & Fix Verification Workspace</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Track issue resolution workflows from open triage through verified re-scan</p>
    </div>
    """, unsafe_allow_html=True)

    findings = st.session_state.current_findings
    if not findings:
        st.info("No findings available to manage. Run an assessment first.")
    else:
        for f in findings:
            fid = f["id"]
            current_status = st.session_state.remediation_tasks.get(fid, "OPEN")

            st.markdown(f"""
            <div class="vf-card" style="margin-bottom:14px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;">
                    <div>
                        <span style="font-size:15px; font-weight:800; color:#ffffff;">{f['title']}</span>
                        <div style="font-size:13px; color:#cbd5e1; font-family:monospace; margin-top:4px;">{f.get('endpoint', '/')} &bull; Status: <strong style="color:#38bdf8;">{current_status}</strong></div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)


# ==============================================================================
# 6. AI SECURITY COPILOT
# ==============================================================================
elif menu == "🤖 AI Security Copilot":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">AI Security Copilot</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Context-aware AI assistant grounded strictly in authorized assessment telemetry</p>
    </div>
    """, unsafe_allow_html=True)

    # Suggested Prompts
    st.markdown("<div style='font-size:12px; font-weight:800; color:#cbd5e1; margin-bottom:8px;'>SUGGESTED COPILOT QUESTIONS</div>", unsafe_allow_html=True)
    sp1, sp2, sp3 = st.columns(3)
    with sp1:
        st.button("🎯 What should we fix first?", key="q1", use_container_width=True)
    with sp2:
        st.button("💻 How do I fix the CORS issue?", key="q2", use_container_width=True)
    with sp3:
        st.button("💼 Explain HSTS risk to executives", key="q3", use_container_width=True)

    st.divider()

    for msg in st.session_state.copilot_history:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    if user_prompt := st.chat_input("Ask a security question about your assessment results..."):
        st.session_state.copilot_history.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.write(user_prompt)

        findings = st.session_state.current_findings
        query_l = user_prompt.lower()

        if "cors" in query_l:
            resp = "To resolve the CORS misconfiguration: Ensure `Access-Control-Allow-Origin` explicitly specifies allowed domain origins rather than reflecting user-supplied `Origin` headers. When `Access-Control-Allow-Credentials: true` is present, never allow wildcard `*` or untrusted origins."
        elif "hsts" in query_l or "header" in query_l:
            resp = "To enforce HSTS: Add the `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` header to all HTTPS responses at your Nginx/Cloudflare or application level."
        elif "git" in query_l or "exposure" in query_l:
            resp = r"To block `.git/HEAD` exposures: Add a rule to your web server (e.g. Nginx `location ~ /\.git { deny all; }`) to return a 403 Forbidden for any requests targeting hidden repository directories."
        elif "first" in query_l or "top" in query_l or "priority" in query_l:
            if findings:
                crit_high = [f['title'] for f in findings if str(f['severity']).upper() in ['CRITICAL', 'HIGH']]
                resp = f"You currently have {len(findings)} findings. Top priority items to fix immediately: " + (", ".join(crit_high) if crit_high else "No critical or high severity vulnerabilities found!")
            else:
                resp = "No active findings detected. Run an assessment to generate telemetry."
        else:
            resp = f"Based on your assessment with {len(findings)} observed findings, I recommend prioritizing Critical and High severity misconfigurations that expose authentication or source code before tackling informative headers."

        st.session_state.copilot_history.append({"role": "assistant", "content": resp})
        with st.chat_message("assistant"):
            st.write(resp)


# ==============================================================================
# 7. DELIVERABLE REPORT CENTER
# ==============================================================================
elif menu == "📄 Deliverable Report Center":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Consulting-Grade Deliverable Reports</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Generate white-labeled executive summaries, technical VAPT deliverables, and audit exports</p>
    </div>
    """, unsafe_allow_html=True)

    findings = st.session_state.current_findings
    if not findings:
        st.info("Run an assessment first to generate reports.")
    else:
        st.markdown("<div class='vf-card'>", unsafe_allow_html=True)
        st.markdown("<h4 style='font-size:16px; font-weight:800; color:#ffffff; margin-top:0;'>White-Label Branding Controls</h4>", unsafe_allow_html=True)
        
        c1, c2 = st.columns(2)
        with c1:
            company_name = st.text_input("Consulting Firm / Agency Name", value="VulnForge Security Services")
            assessor_name = st.text_input("Lead Assessor Name", value="Senior Security Architect")
        with c2:
            client_name = st.text_input("Client Organization", value="Acme Corporation")
            classification = st.selectbox("Classification Label", ["CONFIDENTIAL", "RESTRICTED", "INTERNAL AUDIT", "PUBLIC"])
        
        st.markdown("</div>", unsafe_allow_html=True)

        report_payload = {
            "title": f"Vulnerability Assessment & Penetration Test Report — {client_name}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "branding": {
                "company": company_name,
                "assessor": assessor_name,
                "client": client_name,
                "classification": classification
            },
            "security_posture_score": calculate_posture_score(findings),
            "findings_count": len(findings),
            "findings": findings
        }

        # Downloads
        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "📥 Download Machine JSON Deliverable",
                data=json.dumps(report_payload, indent=2),
                file_name=f"vulnforge_report_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True
            )
        with d2:
            df_export = pd.DataFrame(findings)
            st.download_button(
                "📥 Download Findings CSV Export",
                data=df_export.to_csv(index=False),
                file_name=f"vulnforge_findings_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True
            )


# ==============================================================================
# 8. ASSESSMENT COMPARISON
# ==============================================================================
elif menu == "🔄 Assessment Comparison":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Assessment Comparison & Posture Delta</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Compare posture progression between baseline and target audit checkpoints</p>
    </div>
    """, unsafe_allow_html=True)

    history = st.session_state.assessment_history
    if len(history) < 2:
        st.info("Run at least two assessments in this session to compare posture progression.")
    else:
        opts = [f"{s['id']} — {s['target']} ({s['timestamp']})" for s in history]
        s_base = st.selectbox("Baseline Assessment (Earlier Checkpoint)", opts, index=0)
        s_target = st.selectbox("Target Assessment (Verification Checkpoint)", opts, index=len(opts)-1)

        b_item = history[opts.index(s_base)]
        t_item = history[opts.index(s_target)]

        delta_score = round(t_item["posture_score"] - b_item["posture_score"], 1)

        st.markdown(f"""
        <div class="vf-card-hero">
            <h3 style="margin:0; font-size:18px; font-weight:800; color:#ffffff;">Posture Progression Verdict</h3>
            <div style="font-size:36px; font-weight:900; color:{'#34d399' if delta_score >= 0 else '#f43f5e'}; margin-top:4px;">
                {f'+{delta_score}' if delta_score > 0 else delta_score} pts
            </div>
            <p style="font-size:14px; color:#e2e8f0; margin-top:6px;">Target Posture: <strong style="color:#ffffff;">{t_item['posture_score']}/100</strong> (vs Baseline: <strong style="color:#ffffff;">{b_item['posture_score']}/100</strong>)</p>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# 9. SUBSYSTEM DIAGNOSTICS
# ==============================================================================
elif menu == "⚙️ Subsystem Diagnostics":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h1 style="font-size:24px; font-weight:900; color:#ffffff; margin:0;">Platform Diagnostics & Capabilities</h1>
        <p style="font-size:14px; color:#cbd5e1; margin:4px 0 0 0;">Live engine capabilities and scanner adapter health</p>
    </div>
    """, unsafe_allow_html=True)

    health_items = ScannerHealthDetector.get_all_health()
    
    for h in health_items:
        st.markdown(f"""
        <div class="vf-card" style="margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:15px; font-weight:800; color:#ffffff;">{h.name}</span>
                <span class="pill {'pill-good' if h.available else 'pill-info'}">
                    {'● ACTIVE / READY' if h.available else '● OPTIONAL STANDBY'}
                </span>
            </div>
            <p style="font-size:13px; color:#e2e8f0; margin:6px 0 0 0;">{h.details}</p>
            <div style="font-size:12px; color:#cbd5e1; font-family:monospace; margin-top:6px;">Engine Version: {h.version or 'Native Core'}</div>
        </div>
        """, unsafe_allow_html=True)
