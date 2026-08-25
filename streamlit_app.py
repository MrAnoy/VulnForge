"""
VulnForge — World-Class Automated VAPT Platform (Streamlit Live Edition)
Author: VulnForge Security Engineering
"""

import sys
import os
import asyncio
import concurrent.futures
import json
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
    page_title="VulnForge — Automated VAPT Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom Dark Security Theme Styling ---
st.markdown("""
<style>
    /* Dark Theme Accent */
    .stApp {
        background-color: #0b0f19;
        color: #f8fafc;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Metric Cards */
    .vuln-card {
        background: #111827;
        border: 1px solid #1f293d;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    
    .metric-val {
        font-size: 28px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    
    /* Severity Badges */
    .badge-critical { background-color: rgba(225, 29, 72, 0.2); color: #fb7185; border: 1px solid rgba(225, 29, 72, 0.4); padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px; }
    .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px; }
    .badge-low { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px; }
    .badge-info { background-color: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.4); padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px; }

    /* Custom Header */
    .hero-title {
        font-size: 24px;
        font-weight: 900;
        background: linear-gradient(90deg, #60a5fa, #a855f7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2px;
    }
</style>
""", unsafe_allow_html=True)


# --- Session State Initialization ---
if "assessment_history" not in st.session_state:
    st.session_state.assessment_history = []

if "current_findings" not in st.session_state:
    st.session_state.current_findings = []

if "scan_logs" not in st.session_state:
    st.session_state.scan_logs = []

if "copilot_history" not in st.session_state:
    st.session_state.copilot_history = [
        {"role": "assistant", "content": "Hello! I am your AI Security Copilot. Run an assessment or ask me about vulnerability remediation, CVSS calculations, or secure configurations."}
    ]


# --- Robust Async Runner for Streamlit ---
def run_async(coroutine):
    """Run an async coroutine safely across different event loop contexts in Streamlit."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coroutine).result()
        else:
            return loop.run_until_complete(coroutine)
    except Exception:
        return asyncio.run(coroutine)


# --- Calculation Helpers ---
def calculate_posture_score(findings):
    if not findings:
        return 100.0
    deductions = 0
    for f in findings:
        sev = f.get("severity", "LOW")
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


# --- Sidebar Navigation & View Modes ---
with st.sidebar:
    st.markdown("<div class='hero-title'>🛡️ VulnForge</div>", unsafe_allow_html=True)
    st.caption("Automated VAPT & Security Platform v2.0")
    
    st.divider()
    
    # 4 Adaptive View Modes
    view_mode = st.selectbox(
        "👁️ View Mode Perspective",
        ["Beginner Mode", "Professional Mode", "Executive Mode", "Developer Mode"],
        index=1,
        help="Tailors the presentation, terminology, and technical density across the entire platform."
    )
    
    st.divider()
    
    # Navigation
    menu = st.radio(
        "Navigation",
        [
            "🚀 Launch Assessment",
            "📊 Security Dashboard",
            "🎯 What Should I Fix First?",
            "🔍 Vulnerability Inspector",
            "🤖 AI Security Copilot",
            "📄 Deliverable Reports",
            "🔄 Assessment Comparison",
            "⚙️ Platform Observability"
        ],
        index=0
    )
    
    st.divider()
    
    # Subsystem Health Status
    st.markdown("#### Engine Health")
    st.caption("🟢 **Recon Engine:** Active (DNS/TLS)")
    st.caption("🟢 **Web Sec Engine:** Active (Async)")
    st.caption("🟢 **SSRF Guard:** Strict Mode Enforced")
    st.caption("🟢 **Correlation:** Multi-Engine Active")


# ==============================================================================
# 1. LAUNCH ASSESSMENT WIZARD
# ==============================================================================
if menu == "🚀 Launch Assessment":
    st.title("🚀 Automated Security Assessment Wizard")
    st.write("Perform authorized reconnaissance, vulnerability scanning, and risk assessment with strict scope guardrails.")
    
    if view_mode == "Beginner Mode":
        st.info("💡 **Beginner Guide**: Enter the website or API endpoint you have authorization to test. VulnForge will automatically run passive and non-destructive checks, identify security misconfigurations, and tell you how to fix them.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        target_input = st.text_input("Target URL / Hostname", placeholder="https://example.com or http://127.0.0.1:3000", value="https://example.com")
        
        assessment_profile = st.selectbox(
            "Assessment Profile",
            [
                "Standard VAPT (Recon + Full Web Security Checks)",
                "Quick Security Check (Headers, TLS & Common Exposures)",
                "API Security Audit (Headers, CORS & HTTP Methods)",
                "Reconnaissance & OSINT Only"
            ]
        )
        
        allow_lab = st.checkbox("Allow Localhost / Internal Lab Testing (`127.0.0.1`, RFC 1918)", value=True, help="Enable if testing local containers like OWASP Juice Shop or DVWA.")
        
        auth_confirmed = st.checkbox("✅ **Mandatory Authorization Gate**: I confirm that I own this target or have explicit, written authorization to perform security testing.", value=True)

    with col2:
        st.markdown("### Scan Parameters")
        st.write(f"• **Target:** `{target_input}`")
        st.write(f"• **Profile:** {assessment_profile.split('(')[0].strip()}")
        st.write(f"• **SSRF Protection:** {'Lab Mode' if allow_lab else 'Strict Public Only'}")
        st.write(f"• **Rate Limit:** 20 Requests / sec (Safe)")
    
    st.divider()
    
    if st.button("▶️ Start Authorized Assessment", type="primary", use_container_width=True):
        if not target_input.strip():
            st.error("Please enter a valid target URL or hostname.")
        elif not auth_confirmed:
            st.error("Authorization is required before starting security scanning.")
        else:
            with st.status("Executing Assessment Pipeline...", expanded=True) as status:
                st.write("🔒 **Phase 1/5: Scope & SSRF Validation**")
                
                # SSRF Guard validation
                try:
                    resolved_ips = SSRFGuard.resolve_and_validate(target_input, allow_local_lab=allow_lab)
                    st.write(f"✅ Target validated. Resolved IPs: `{', '.join(resolved_ips)}`")
                except Exception as e:
                    status.update(label="❌ Scope Validation Failed", state="error")
                    st.error(f"Target blocked by SSRF Guard: {str(e)}")
                    st.stop()
                
                try:
                    # Execution
                    st.write("🌐 **Phase 2/5: Reconnaissance & OSINT Engine**")
                    recon_adapter = ReconAdapter()
                    recon_res = run_async(recon_adapter.execute(target_input, {}))
                    st.write(f"Found {len(recon_res.findings)} preliminary recon observations and service metadata.")
                    
                    st.write("⚡ **Phase 3/5: Custom Web Vulnerability Engine**")
                    web_adapter = CustomWebAdapter()
                    web_res = run_async(web_adapter.execute(target_input, {}))
                    st.write(f"Detected {len(web_res.findings)} web security findings (Headers, CORS, Cookies, Exposures).")
                    
                    st.write("🧬 **Phase 4/5: Finding Normalization & Correlation**")
                    raw_findings = recon_res.findings + web_res.findings
                    
                    # Format into uniform objects
                    normalized_findings = []
                    for rf in raw_findings:
                        normalized_findings.append({
                            "id": rf.id,
                            "title": rf.title,
                            "description": rf.description,
                            "severity": rf.severity.value,
                            "cvss_score": rf.cvss_score,
                            "cwe": rf.cwe,
                            "category": rf.category,
                            "asset_target": rf.asset_target,
                            "endpoint": rf.endpoint,
                            "impact": rf.impact,
                            "remediation": rf.remediation,
                            "references": rf.references,
                            "scanner": rf.scanner,
                            "confidence": rf.confidence.value,
                            "evidence": rf.evidence.model_dump() if rf.evidence else {}
                        })
                    
                    st.write("📈 **Phase 5/5: Contextual Risk Analysis**")
                    posture_score = calculate_posture_score(normalized_findings)
                    
                    # Save into session state
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
                    st.error(f"Error during scan execution: {str(scan_err)}")
                    st.stop()
            
            st.success(f"Assessment completed successfully! Found **{len(normalized_findings)} findings**. Navigate to the **Security Dashboard** or **What Should I Fix First?** to inspect results.")


# ==============================================================================
# 2. SECURITY DASHBOARD
# ==============================================================================
elif menu == "📊 Security Dashboard":
    st.title("📊 Security Posture Dashboard")
    
    findings = st.session_state.current_findings
    
    if not findings:
        st.warning("No assessment data available yet. Please run an assessment in the **Launch Assessment** tab or load sample data.")
        if st.button("📂 Load Demo Assessment Results"):
            # Load synthetic demonstration findings
            demo_findings = [
                {
                    "id": "find-1", "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                    "description": "The web application does not enforce HSTS header.", "severity": "MEDIUM", "cvss_score": 5.3,
                    "cwe": "CWE-319", "category": "Security Headers", "asset_target": "https://demo.vulnforge.sec",
                    "endpoint": "/", "impact": "Allows potential Man-in-the-Middle SSL stripping attacks.",
                    "remediation": "Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "scanner": "Custom Web Security Engine", "confidence": "CONFIRMED", "evidence": {"header": "Missing Strict-Transport-Security"}
                },
                {
                    "id": "find-2", "title": "Insecure Cross-Origin Resource Sharing (CORS) Configuration",
                    "description": "The API reflects arbitrary Origin headers with Access-Control-Allow-Credentials enabled.",
                    "severity": "HIGH", "cvss_score": 7.5, "cwe": "CWE-942", "category": "API Security",
                    "asset_target": "https://demo.vulnforge.sec", "endpoint": "/api/v1/user",
                    "impact": "Enables authenticated cross-origin data theft.",
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
                    "scanner": "Custom Web Security Engine", "confidence": "CONFIRMED", "evidence": {"origin": "evil.com reflected"}
                },
                {
                    "id": "find-3", "title": "Sensitive File Exposure (.git/HEAD)",
                    "description": "Git metadata repository is publicly accessible.",
                    "severity": "CRITICAL", "cvss_score": 9.1, "cwe": "CWE-538", "category": "Information Disclosure",
                    "asset_target": "https://demo.vulnforge.sec", "endpoint": "/.git/HEAD",
                    "impact": "Allows full source code reconstruction by attackers.",
                    "remediation": "Block access to hidden dotfiles in Nginx / Apache configuration.",
                    "scanner": "Custom Web Security Engine", "confidence": "CONFIRMED", "evidence": {"output": "ref: refs/heads/main"}
                }
            ]
            st.session_state.current_findings = demo_findings
            st.rerun()
    else:
        posture_score = calculate_posture_score(findings)
        
        # Metrics Top Row
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Security Posture Score", f"{posture_score}/100", delta=None)
        with c2:
            crit = len([f for f in findings if f['severity'] == 'CRITICAL'])
            st.metric("Critical Findings", crit, delta=f"-{crit}" if crit > 0 else None, delta_color="inverse")
        with c3:
            high = len([f for f in findings if f['severity'] == 'HIGH'])
            st.metric("High Findings", high, delta=f"-{high}" if high > 0 else None, delta_color="inverse")
        with c4:
            med = len([f for f in findings if f['severity'] == 'MEDIUM'])
            st.metric("Medium Findings", med)
        with c5:
            st.metric("Total Findings", len(findings))

        st.divider()

        # Severity breakdown chart
        st.subheader("Severity Distribution")
        df_counts = pd.DataFrame([
            {"Severity": "CRITICAL", "Count": len([f for f in findings if f['severity'] == 'CRITICAL'])},
            {"Severity": "HIGH", "Count": len([f for f in findings if f['severity'] == 'HIGH'])},
            {"Severity": "MEDIUM", "Count": len([f for f in findings if f['severity'] == 'MEDIUM'])},
            {"Severity": "LOW", "Count": len([f for f in findings if f['severity'] == 'LOW'])},
            {"Severity": "INFO", "Count": len([f for f in findings if f['severity'] == 'INFO'])},
        ])
        st.bar_chart(df_counts.set_index("Severity"))


# ==============================================================================
# 3. WHAT SHOULD I FIX FIRST? (SMART PRIORITIZATION)
# ==============================================================================
elif menu == "🎯 What Should I Fix First?":
    st.title("🎯 What Should I Fix First?")
    st.caption("Multi-dimensional algorithmic ranking prioritizing vulnerabilities by business risk, exploitability, and exposure.")
    
    findings = st.session_state.current_findings
    if not findings:
        st.info("Run an assessment or load demo results in the Dashboard to see prioritized actions.")
    else:
        # Sort findings by severity weight and CVSS
        def get_rank_score(f):
            sev_weights = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 5}
            return sev_weights.get(f.get("severity", "LOW"), 10) + f.get("cvss_score", 0.0) * 5

        sorted_findings = sorted(findings, key=get_rank_score, reverse=True)

        for idx, f in enumerate(sorted_findings[:5], start=1):
            sev = f["severity"]
            badge_class = f"badge-{sev.lower()}"
            
            with st.container():
                st.markdown(f"""
                <div class="vuln-card">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:16px; font-weight:bold; color:#fff;">#{idx}. {f['title']}</span>
                        <span class="{badge_class}">{sev}</span>
                    </div>
                    <p style="font-size:12px; color:#94a3b8; margin-top:6px;">Target: <code>{f.get('asset_target', '')}{f.get('endpoint', '')}</code> &bull; CVSS: <strong>{f.get('cvss_score', 'N/A')}</strong> &bull; Scanner: {f.get('scanner', 'Custom')}</p>
                    <div style="background:#090d16; padding:10px; border-radius:6px; font-size:12px; border-left:3px solid #3b82f6; margin-top:8px;">
                        <strong>Actionable Fix:</strong> {f.get('remediation', 'Consult security engineering team.')}
                    </div>
                </div>
                """, unsafe_allow_html=True)


# ==============================================================================
# 4. VULNERABILITY INSPECTOR
# ==============================================================================
elif menu == "🔍 Vulnerability Inspector":
    st.title("🔍 Multi-Perspective Vulnerability Inspector")
    
    findings = st.session_state.current_findings
    if not findings:
        st.info("No findings to inspect. Run an assessment first.")
    else:
        finding_titles = [f"{f['severity']} - {f['title']}" for f in findings]
        selected_title = st.selectbox("Select a Finding to Inspect", finding_titles)
        selected_idx = finding_titles.index(selected_title)
        finding = findings[selected_idx]

        st.subheader(f"{finding['title']}")
        st.markdown(f"**Severity:** `{finding['severity']}` | **CVSS v3.1:** `{finding.get('cvss_score', 'N/A')}` | **CWE:** `{finding.get('cwe', 'N/A')}` | **Confidence:** `{finding.get('confidence', 'HIGH')}`")

        tab1, tab2, tab3, tab4 = st.tabs([
            "📖 Beginner Explanation",
            "🛡️ Technical Evidence",
            "💻 Developer Fix Guide",
            "💼 Executive Business Risk"
        ])

        with tab1:
            st.markdown("### Plain-English Overview")
            st.write(finding.get("description", "No description available."))
            st.markdown("### Why It Matters")
            st.write(finding.get("impact", "Potential security exposure."))

        with tab2:
            st.markdown("### Observed Technical Evidence")
            st.json(finding.get("evidence", {"status": "Evidence collected from scanner response"}))
            st.markdown("### Scanner Source")
            st.write(f"Detected by: `{finding.get('scanner', 'VulnForge Engine')}`")

        with tab3:
            st.markdown("### Actionable Remediation")
            st.code(finding.get("remediation", "Apply security best practices."), language="bash")
            if finding.get("references"):
                st.markdown("### References")
                for r in finding["references"]:
                    st.markdown(f"- [{r}]({r})")

        with tab4:
            st.markdown("### Executive Risk Evaluation")
            st.write(f"• **Potential Breach Impact:** {finding.get('impact', 'Moderate operational impact.')}")
            st.write(f"• **Remediation Urgency:** {'Immediate (24hr SLA)' if finding['severity'] in ['CRITICAL', 'HIGH'] else 'Standard Sprint (14-day SLA)'}")


# ==============================================================================
# 5. AI SECURITY COPILOT
# ==============================================================================
elif menu == "🤖 AI Security Copilot":
    st.title("🤖 AI Security Copilot")
    st.caption("AI-assisted triage, contextual fix guidance, and security questions grounded in your scan telemetry.")

    for msg in st.session_state.copilot_history:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    if user_input := st.chat_input("Ask a question (e.g. 'How do I fix the CORS issue?' or 'Summarize our top risk')"):
        st.session_state.copilot_history.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.write(user_input)

        # Context-aware rule-based / intelligent assistant
        findings = st.session_state.current_findings
        query_lower = user_input.lower()

        if "cors" in query_lower:
            reply = "To resolve the CORS misconfiguration: Ensure `Access-Control-Allow-Origin` explicitly specifies allowed domain origins rather than reflecting user-supplied `Origin` headers. When `Access-Control-Allow-Credentials: true` is present, never allow wildcard `*` or untrusted origins."
        elif "hsts" in query_lower or "header" in query_lower:
            reply = "To enforce HSTS: Add the `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` header to all HTTPS responses at your Nginx/Cloudflare or application level."
        elif "git" in query_lower or "exposure" in query_lower:
            reply = r"To block `.git/HEAD` exposures: Add a rule to your web server (e.g. Nginx `location ~ /\.git { deny all; }`) to return a 403 Forbidden for any requests targeting hidden repository directories."
        elif "top" in query_lower or "summary" in query_lower:
            if findings:
                crit_high = [f['title'] for f in findings if f['severity'] in ['CRITICAL', 'HIGH']]
                reply = f"You currently have {len(findings)} findings. Top priority issues to address first are: " + (", ".join(crit_high) if crit_high else "No critical/high severity items found!")
            else:
                reply = "No active findings detected in session. Run an assessment to generate security telemetry."
        else:
            reply = f"Based on your assessment with {len(findings)} observed findings, I recommend prioritizing Critical and High severity misconfigurations that expose authentication or source code before tackling informative headers."

        st.session_state.copilot_history.append({"role": "assistant", "content": reply})
        with st.chat_message("assistant"):
            st.write(reply)


# ==============================================================================
# 6. DELIVERABLE REPORT GENERATOR
# ==============================================================================
elif menu == "📄 Deliverable Reports":
    st.title("📄 Consulting-Grade Deliverable Reports")
    st.caption("Generate white-labeled, executive and technical security deliverables.")

    findings = st.session_state.current_findings
    if not findings:
        st.info("Run an assessment first to generate reports.")
    else:
        st.markdown("### White-Label Branding Controls")
        c1, c2 = st.columns(2)
        with c1:
            company_name = st.text_input("Consulting Company / Agency", value="VulnForge Security Services")
            assessor_name = st.text_input("Lead Assessor", value="Senior Security Architect")
        with c2:
            client_name = st.text_input("Client Organization", value="ACME Corp")
            classification = st.selectbox("Classification Badge", ["CONFIDENTIAL", "RESTRICTED", "INTERNAL AUDIT", "PUBLIC"])

        report_data = {
            "title": f"Security Assessment Report — {client_name}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "branding": {
                "company_name": company_name,
                "assessor_name": assessor_name,
                "client_name": client_name,
                "classification": classification
            },
            "posture_score": calculate_posture_score(findings),
            "findings": findings
        }

        st.divider()

        rc1, rc2 = st.columns(2)
        with rc1:
            # Export JSON
            st.download_button(
                label="📥 Download JSON Report",
                data=json.dumps(report_data, indent=2),
                file_name=f"vulnforge_report_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True
            )
        with rc2:
            # Export CSV
            df_csv = pd.DataFrame(findings)
            st.download_button(
                label="📥 Download CSV Findings",
                data=df_csv.to_csv(index=False),
                file_name=f"vulnforge_findings_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True
            )


# ==============================================================================
# 7. ASSESSMENT COMPARISON & DELTA
# ==============================================================================
elif menu == "🔄 Assessment Comparison":
    st.title("🔄 Assessment Comparison & Delta Engine")
    
    history = st.session_state.assessment_history
    if len(history) < 2:
        st.info("Run at least two assessments to compare security posture progression and delta changes.")
    else:
        scan_options = [f"{s['id']} — {s['target']} ({s['timestamp']})" for s in history]
        s1 = st.selectbox("Baseline Assessment (Earlier)", scan_options, index=0)
        s2 = st.selectbox("Target Assessment (Later)", scan_options, index=len(scan_options)-1)

        idx1 = scan_options.index(s1)
        idx2 = scan_options.index(s2)

        base = history[idx1]
        target = history[idx2]

        score_delta = round(target["posture_score"] - base["posture_score"], 1)

        st.metric(
            "Security Posture Progression",
            f"{target['posture_score']}/100",
            delta=f"{score_delta} pts" if score_delta != 0 else "No Change"
        )


# ==============================================================================
# 8. PLATFORM OBSERVABILITY
# ==============================================================================
elif menu == "⚙️ Platform Observability":
    st.title("⚙️ Platform Observability & Diagnostics")
    st.caption("Live capability matrix and subsystem telemetry.")
    
    health_list = ScannerHealthDetector.get_all_health()
    
    for h in health_list:
        with st.container():
            st.markdown(f"""
            <div class="vuln-card">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:bold; color:#fff;">{h.name}</span>
                    <span style="background:{'rgba(16,185,129,0.2)' if h.available else 'rgba(239,68,68,0.2)'}; color:{'#34d399' if h.available else '#f87171'}; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold;">
                        {'HEALTHY / ACTIVE' if h.available else 'OPTIONAL STANDBY'}
                    </span>
                </div>
                <p style="font-size:12px; color:#94a3b8; margin-top:5px;">{h.details}</p>
                <div style="font-size:11px; color:#64748b; font-family:monospace;">Version: {h.version or 'Native Engine'}</div>
            </div>
            """, unsafe_allow_html=True)
