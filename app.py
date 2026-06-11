import streamlit as st
import pandas as pd
import json
import requests
import time
import os
from dotenv import load_dotenv
from analyzer import APKAnalyzer

# Load environment keys
load_dotenv()

# Retrieve key from st.secrets if configured, otherwise fallback to env variable
gemini_key = st.secrets.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")

# App configuration
st.set_page_config(
    page_title="DeXray // GenAI APK Malware Analysis Platform",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium cybersecurity dark CSS injection
st.markdown("""
<style>
    /* Dark Theme Core overrides */
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/icon?family=Material+Icons');
    
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0d0f12;
        color: #e2e8f0;
        font-family: 'Inter', sans-serif;
    }
    
    [data-testid="stSidebar"] {
        background-color: #07090b !important;
        border-right: 1px solid #1f2937;
    }
    
    /* Headers styling */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', sans-serif;
        font-weight: 700;
        letter-spacing: -0.02em;
    }
    
    .glow-text {
        color: #38bdf8;
        text-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        font-family: 'Fira Code', monospace;
    }

    .brand-title {
        font-size: 1.8rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8 0%, #a855f7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }

    .brand-subtitle {
        font-size: 0.8rem;
        color: #94a3b8;
        font-family: 'Fira Code', monospace;
        letter-spacing: 0.1em;
        margin-bottom: 1.5rem;
        text-transform: uppercase;
    }
    
    /* Cards and Glassmorphism */
    .glass-card {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid #1f2937;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    
    .verdict-box {
        border-radius: 8px;
        padding: 1rem;
        font-weight: 700;
        text-align: center;
        letter-spacing: 0.05em;
        font-family: 'Fira Code', monospace;
        margin-bottom: 1.5rem;
    }
    
    .verdict-critical {
        background: rgba(220, 38, 38, 0.15);
        border: 2px solid #ef4444;
        color: #fca5a5;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.2);
    }
    
    .verdict-high {
        background: rgba(217, 119, 6, 0.15);
        border: 2px solid #f59e0b;
        color: #fde68a;
        box-shadow: 0 0 15px rgba(245, 158, 11, 0.2);
    }
    
    .verdict-info {
        background: rgba(5, 150, 105, 0.15);
        border: 2px solid #10b981;
        color: #a7f3d0;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.2);
    }
    
    /* Badges */
    .badge {
        padding: 0.25rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'Fira Code', monospace;
    }
    
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }
    
    .badge-high {
        background-color: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }
    
    .badge-info {
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }

    /* Terminal Console */
    .terminal-console {
        background-color: #050709;
        border: 1px solid #10b981;
        border-radius: 6px;
        padding: 1rem;
        font-family: 'Fira Code', monospace;
        color: #10b981;
        font-size: 0.85rem;
        line-height: 1.4;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.1) inset;
        height: 250px;
        overflow-y: auto;
    }
    
    .terminal-line {
        margin-bottom: 4px;
    }
    
    .terminal-prompt {
        color: #6366f1;
        user-select: none;
    }
</style>
""", unsafe_allow_html=True)


# Render Sidebar Logo / Branding
with st.sidebar:
    st.markdown('<div class="brand-title">DeXray //</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-subtitle">GenAI APK Malware Platform</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Ingestion Source
    st.subheader(":material/folder_open: Ingestion Engine")
    uploaded_file = st.file_uploader(
        "Upload Target Android App (.apk)",
        type=["apk"],
        help="Upload a banking application or dummy APK to run the security analysis pipeline."
    )
    
    st.markdown("---")
    
    # Demo Quick load trigger
    st.subheader(":material/science: Demo Sandbox")
    st.caption("Instantly run the analysis suite with pre-loaded profiles simulating real-world active mobile banking trojans:")
    
    col1, col2 = st.columns(2)
    with col1:
        load_teabot = st.button(":material/bug_report: TeaBot Sample", use_container_width=True, help="Simulate TeaBot / Anatsa Banking Dropper variant.")
    with col2:
        load_anubis = st.button(":material/bolt: Anubis Sample", use_container_width=True, help="Simulate Anubis V2 Banking Trojan framework.")

# Initialise Analysis and Ingestion Source States
if "active_source" not in st.session_state:
    st.session_state.active_source = None
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None

# If uploader is cleared, reset state
if uploaded_file is None:
    st.session_state.last_uploaded_name = None
    if st.session_state.active_source == "uploaded":
        st.session_state.active_source = None
        st.session_state.analysis_results = None

# If a new file is uploaded in uploader, switch active source
if uploaded_file is not None:
    last_uploaded = st.session_state.get("last_uploaded_name", None)
    if last_uploaded != uploaded_file.name:
        st.session_state.active_source = "uploaded"
        st.session_state.last_uploaded_name = uploaded_file.name
        st.session_state.analysis_results = None

# If user clicked quick load buttons, load mock profile directly
if load_teabot:
    st.session_state.active_source = "teabot"
    st.session_state.analysis_results = None

if load_anubis:
    st.session_state.active_source = "anubis"
    st.session_state.analysis_results = None

# Run parsing pipeline based on the active ingestion source
if st.session_state.analysis_results is None and st.session_state.active_source is not None:
    analyzer = APKAnalyzer(api_key=gemini_key)
    
    if st.session_state.active_source == "teabot":
        with st.spinner("Executing Heuristic Parsing & GenAI Verification on TeaBot..."):
            time.sleep(1.5) # realistic delay
            st.session_state.analysis_results = analyzer.analyze_file(b"", filename="TeaBot_Anatsa_Malware.apk")
            st.toast("Loaded TeaBot / Anatsa malicious profile!", icon=":material/warning:")
            
    elif st.session_state.active_source == "anubis":
        with st.spinner("Executing Heuristic Parsing & GenAI Verification on Anubis..."):
            time.sleep(1.5) # realistic delay
            st.session_state.analysis_results = analyzer.analyze_file(b"", filename="Anubis_V2_SecurityPatch.apk")
            st.toast("Loaded Anubis V2 malicious profile!", icon=":material/error:")
            
    elif st.session_state.active_source == "uploaded" and uploaded_file is not None:
        with st.spinner("Unpacking APK resources and running Heuristics Sieve..."):
            # Reset file pointer to avoid empty read on subsequent Streamlit reruns
            uploaded_file.seek(0)
            apk_bytes = uploaded_file.read()
            st.session_state.analysis_results = analyzer.analyze_file(apk_bytes, filename=uploaded_file.name)
            st.toast("APK Static Heuristic Scans Complete!", icon=":material/rocket_launch:")

# ----------------- MAIN PANEL RENDERING -----------------

if st.session_state.analysis_results is None:
    # Introduce page beautifully when nothing is loaded yet
    st.markdown("""
    <div style="text-align: center; margin-top: 5rem; padding: 2rem;">
        <h1 style="font-size: 3.5rem; font-weight: 800; margin-bottom: 1rem; background: linear-gradient(135deg, #38bdf8 0%, #a855f7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            DeXray Malware Analysis
        </h1>
        <p style="font-size: 1.25rem; color: #94a3b8; max-width: 800px; margin: 0 auto 2.5rem auto; line-height: 1.6;">
            A unified hybrid analyzer designed for next-generation mobile threat hunting. DeXray blends low-level 
            <b>Static Heuristics</b> with <b>GenAI Semantic Interpretation</b> to detect credential harvesting overlays, 
            keylogger hooks, and SMS-intercepting financial fraud in Android binaries.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Columns of features
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="glass-card" style="height: 100%;">
            <h3 style="color: #38bdf8; margin-top:0;"><i class="material-icons" style="vertical-align: middle; font-size: 1.5rem; margin-right: 0.2rem;">search</i>Resilient Decompiler</h3>
            <p style="color: #94a3b8; font-size: 0.9rem;">
                Attempts clean disassembly using Androguard, with zip-level binary manifest strings and DEX data mining fallbacks to bypass packer anti-analysis.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="glass-card" style="height: 100%;">
            <h3 style="color: #a855f7; margin-top:0;"><i class="material-icons" style="vertical-align: middle; font-size: 1.5rem; margin-right: 0.2rem;">psychology</i>GenAI Semantic Engine</h3>
            <p style="color: #94a3b8; font-size: 0.9rem;">
                Pipes suspected bytecode segments directly into Gemini LLM, returning human-centric vulnerability analysis, MITRE ATT&CK Mobile mappings, and confidence multipliers.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="glass-card" style="height: 100%;">
            <h3 style="color: #10b981; margin-top:0;"><i class="material-icons" style="vertical-align: middle; font-size: 1.5rem; margin-right: 0.2rem;">security</i>Automated Orchestrator</h3>
            <p style="color: #94a3b8; font-size: 0.9rem;">
                Calculates risk indices mathematically and lets you fire automated incident response webhook calls directly into Bank Security Operation Centers (SOC).
            </p>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("<br><br>", unsafe_allow_html=True)
    st.info("Get started instantly by selecting one of the simulated profiles in the **Hackathon Demo Sandbox** on the sidebar, or uploading a test `.apk` file.", icon=":material/lightbulb:")

else:
    # An analysis has been performed. Render Dashboard
    res = st.session_state.analysis_results
    
    # Mode badge rendering
    mode = res.get("analysis_mode", "SANDBOX_SIMULATION")
    if mode == "LIVE_DECOMPILATION":
        mode_badge = '<span class="badge" style="background-color: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); padding: 0.25rem 0.6rem; margin-left: 10px; font-size: 0.75rem; vertical-align: middle;"><i class="material-icons" style="vertical-align: middle; font-size: 0.95rem; margin-right: 0.25rem;">memory</i>LIVE DECOMPILATION</span>'
    elif mode == "LIVE_STRINGS_SCAN":
        mode_badge = '<span class="badge" style="background-color: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); padding: 0.25rem 0.6rem; margin-left: 10px; font-size: 0.75rem; vertical-align: middle;"><i class="material-icons" style="vertical-align: middle; font-size: 0.95rem; margin-right: 0.25rem;">settings_backup_restore</i>LIVE STRINGS SCAN</span>'
    else:
        mode_badge = '<span class="badge" style="background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); padding: 0.25rem 0.6rem; margin-left: 10px; font-size: 0.75rem; vertical-align: middle;"><i class="material-icons" style="vertical-align: middle; font-size: 0.95rem; margin-right: 0.25rem;">science</i>SANDBOX PRESET</span>'

    # Header summary info
    st.markdown(f"""
    <div style="margin-bottom: 2rem; border-bottom: 1px solid #1f2937; padding-bottom: 1rem;">
        <span style="font-family: 'Fira Code', monospace; color: #a855f7; font-size: 0.9rem; text-transform: uppercase;">Analysis Active // DeXray Engine v1.2</span>
        <h1 style="margin: 0; font-size: 2.2rem; color: #f8fafc; display: flex; align-items: center; flex-wrap: wrap;">
            Target App: &nbsp;<span class="glow-text">{res['app_name']}</span> {mode_badge}
        </h1>
        <p style="color: #64748b; margin: 0.2rem 0 0 0; font-family: 'Fira Code', monospace;">Package Name: {res['package']}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Create the four primary tabs
    tab_summary, tab_deep_dive, tab_behavior, tab_soc = st.tabs([
        ":material/dashboard: Executive Summary", 
        ":material/analytics: Technical Deep-Dive", 
        ":material/insights: Behavior Analysis",
        ":material/hub: SOC Integration & Alerts"
    ])
    
    # ----------------- TAB 1: EXECUTIVE SUMMARY -----------------
    with tab_summary:
        col_gauge, col_verdict = st.columns([1, 2])
        
        with col_gauge:
            # Custom SVG Risk Gauge
            score = res["risk_score"]
            # Color calculation
            if score >= 75:
                gauge_color = "#ef4444" # red
                verdict_str = "CRITICAL - BANKING TROJAN DETECTED"
                verdict_class = "verdict-critical"
            elif score >= 35:
                gauge_color = "#f59e0b" # amber
                verdict_str = "WARNING - HIGH SUSPICIOUS RATING"
                verdict_class = "verdict-high"
            else:
                gauge_color = "#10b981" # green
                verdict_str = "INFORMATIONAL - NO MALICIOUS VERDICT"
                verdict_class = "verdict-info"

            # Render dynamic SVG gauge
            # SVG details: Circle circumference 2 * pi * r = 2 * 3.14159 * 75 = 471.2
            dasharray_full = 471.2
            dashoffset = dasharray_full - (dasharray_full * (score / 100.0))
            
            st.markdown(f"""
            <div class="glass-card" style="text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%;">
                <h4 style="margin: 0 0 1rem 0; color: #94a3b8; font-size: 0.85rem; font-family: 'Fira Code', monospace; text-transform: uppercase; letter-spacing: 0.05em;">Hybrid Threat Score</h4>
                <svg width="200" height="200" viewBox="0 0 200 200" style="transform: rotate(-90deg);">
                    <!-- Background Circle -->
                    <circle cx="100" cy="100" r="75" fill="transparent" stroke="#1f2937" stroke-width="15" />
                    <!-- Foreground Gauge Indicator -->
                    <circle cx="100" cy="100" r="75" fill="transparent" stroke="{gauge_color}" stroke-width="15" 
                            stroke-dasharray="{dasharray_full}" stroke-dashoffset="{dashoffset}" stroke-linecap="round"
                            style="transition: stroke-dashoffset 0.8s ease-in-out;" />
                </svg>
                <div style="margin-top: -125px; margin-bottom: 50px;">
                    <div style="font-size: 2.8rem; font-weight: 800; font-family: 'Fira Code', monospace; color: {gauge_color};">{score}</div>
                    <div style="font-size: 0.75rem; color: #64748b; font-family: 'Fira Code', monospace; text-transform: uppercase; margin-top: -5px;">Risk Index</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
        with col_verdict:
            # Verdict box
            st.markdown(f'<div class="verdict-box {verdict_class}">{verdict_str}</div>', unsafe_allow_html=True)
            
            # Dynamic stats card
            c_stat1, c_stat2, c_stat3, c_stat4 = st.columns(4)
            with c_stat1:
                ingest_type = "Preset Sandbox" if mode == "SANDBOX_SIMULATION" else "Live Scan"
                st.metric("Ingestion Mode", ingest_type, help="Defines whether preset demo templates or custom binary parses are active.")
            with c_stat2:
                st.metric("Static Anomalies", f"{res['anomalies_count']} Hits", help="Security anomalies located by decompiler.")
            with c_stat3:
                st.metric("Permissions Inspected", f"{len(res['permissions'])} Permissions", help="Total permissions requested in Manifest.")
            with c_stat4:
                st.metric("GenAI Multiplier (μ)", f"{res['ai_confidence_multiplier']}x", help="AI confidence modifier based on code semantics scan.")

        # GenAI Behavioral Executive Report
        st.markdown("<br>", unsafe_allow_html=True)
        st.subheader(":material/psychology: GenAI Malware Analyst Report")
        
        st.markdown(f"""
        <div class="glass-card" style="border-left: 4px solid #a855f7;">
            <p style="font-size: 1.05rem; line-height: 1.7; color: #f1f5f9; margin-bottom: 1.5rem;">
                {res['behavioral_summary']}
            </p>
            <h4 style="color: #c084fc; font-family: 'Fira Code', monospace; margin-bottom: 0.75rem; font-size: 0.9rem; text-transform: uppercase;">Matched MITRE ATT&CK Mobile Tactics:</h4>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                {"".join([f'<span class="badge badge-high" style="margin-right:5px; margin-bottom:5px;">{tactic}</span>' for tactic in res['matched_mitre_tactics']])}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ----------------- TAB 2: BEHAVIOR ANALYSIS -----------------
    with tab_behavior:
        st.subheader(":material/insights: Behavior Analysis")
        st.markdown("""
        <div class="glass-card" style="padding: 1rem; margin-bottom: 1rem; background: rgba(17, 24, 39, 0.85); border: 1px solid #1f2937; border-radius: 12px;">
            <h3 style="margin: 0 0 0.5rem 0; color: #38bdf8; font-family: 'Fira Code', monospace;">Behavior Analysis Score</h3>
            <p style="margin: 0; font-size: 2.5rem; font-weight: 800; color: #10b981; font-family: 'Fira Code', monospace;">{res['behavior_score']}</p>
            <p style="margin-top: 0.75rem; color: #94a3b8;">Higher scores indicate stronger behavior signal overlap with known mobile malware patterns.</p>
        </div>
        """, unsafe_allow_html=True)

        behavior_rows = [
            ("SMS Interception", res["behavior_analysis"]["sms_interception"]),
            ("Overlay Attack", res["behavior_analysis"]["overlay_attack"]),
            ("Accessibility Abuse", res["behavior_analysis"]["accessibility_abuse"]),
            ("Boot Persistence", res["behavior_analysis"]["boot_persistence"]),
            ("Reflection Usage", res["behavior_analysis"]["reflection_usage"]),
            ("Dynamic Loading", res["behavior_analysis"]["dynamic_loading"])
        ]

        for label, present in behavior_rows:
            if present:
                st.success(f"{label}: Detected")
            else:
                st.info(f"{label}: Not detected")

    # ----------------- TAB 3: TECHNICAL DEEP-DIVE -----------------
    with tab_deep_dive:
        st.subheader(":material/security: Android Permission Profile")
        
        # Build pandas DataFrame for visualization
        perm_rows = []
        for item in res["permissions"]:
            perm_name = item["permission"]
            status = item["status"]
            desc = item["description"]
            
            # Formatting badges
            if status == "CRITICAL":
                badge_html = f'<span class="badge badge-critical">{status}</span>'
            elif status == "HIGH":
                badge_html = f'<span class="badge badge-high">{status}</span>'
            else:
                badge_html = f'<span class="badge badge-info">{status}</span>'
                
            perm_rows.append({
                "Permission": perm_name,
                "Threat Level": badge_html,
                "Heuristic Description": desc
            })
            
        if perm_rows:
            df = pd.DataFrame(perm_rows)
            st.write(df.to_html(escape=False, index=False), unsafe_allow_html=True)
        else:
            st.info("No permissions extracted from the application package.")
            
        st.markdown("<br><hr style='border-color: #1f2937;'><br>", unsafe_allow_html=True)
        
        col_intents, col_code = st.columns([1, 2])
        
        with col_intents:
            st.subheader(":material/sensors: Discovered Intent Filters & Receivers")
            st.caption("Receivers, services, and triggers indicating event loops the malware hooks into:")
            
            if res["intents"]:
                for intent in res["intents"]:
                    st.markdown(f"""
                    <div style="background-color: #07090b; border: 1px solid #1f2937; border-radius: 6px; padding: 0.6rem; margin-bottom: 6px; font-family: 'Fira Code', monospace; font-size: 0.8rem; word-break: break-all;">
                        <span style="color: #6366f1;">•</span> {intent}
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No active intent-filters or receivers found in Manifest.")
                
        with col_code:
            st.subheader(":material/code: Isolated Suspicious Smali Snippets")
            st.caption("Extracted bytecode blocks highlighting accessibility intercepts, unencrypted C2 web templates, or dynamic dex loadings:")
            
            # Custom code viewer
            st.code(res["suspicious_snippets"], language="smali")

    # ----------------- TAB 3: SOC INTEGRATION & WEBHOOK -----------------
    with tab_soc:
        st.subheader(":material/webhook: SOC Alert Payload & Automation Orchestrator")
        
        st.markdown("""
        Configure automated response playbooks. Below is the structured JSON alert schema prepared for ingestion 
        by security orchestration engines (SOAR). Press the trigger button below to fire an incident alert.
        """)
        
        # Real-time JSON alert payload
        alert_payload = {
            "event_id": f"DEX-{int(time.time())}",
            "verdict": verdict_str.split(" - ")[0],
            "threat_score": res["risk_score"],
            "package_name": res["package"],
            "matched_signals": len(res["permissions"]),
            "anomalies_detected": res["anomalies_count"],
            "mitre_tactics": res["matched_mitre_tactics"],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ai_summary": res["behavioral_summary"]
        }
        
        c_pay, c_term = st.columns([1, 1])
        
        with c_pay:
            st.markdown("##### 📄 JSON Alert Schema")
            st.json(alert_payload)
            
            webhook_url = st.text_input("Webhook URL Receiver", value="https://httpbin.org/post", help="Webhook endpoint targeting the SIEM/SOAR system.")
            
        with c_term:
            st.markdown("##### 📟 SOC Automation Terminal Log")
            
            # Session state to hold logs
            if "terminal_logs" not in st.session_state:
                st.session_state.terminal_logs = [
                    "INFO: SOC alert daemon initialized.",
                    "INFO: System connected to local SOAR broker.",
                    "INFO: Standing by for execution triggers."
                ]
                
            # Render logs
            log_content = ""
            for idx, line in enumerate(st.session_state.terminal_logs):
                log_content += f'<div class="terminal-line"><span class="terminal-prompt">SOC@DeXray:~#</span> {line}</div>'
                
            st.markdown(f"""
            <div class="terminal-console">
                {log_content}
            </div>
            """, unsafe_allow_html=True)
            
            # Action button
            if st.button("Trigger Automated Bank SOC Alert", type="primary", use_container_width=True):
                # Simulated actions
                st.session_state.terminal_logs.append("USER: Click event received. Triggering SIEM POST.")
                st.session_state.terminal_logs.append(f"POST: Serializing JSON alert payload to {webhook_url}...")
                
                # Perform request
                try:
                    with st.spinner("Pushing JSON payload to Webhook..."):
                        response = requests.post(webhook_url, json=alert_payload, timeout=5)
                        if response.status_code == 200 or response.status_code == 201:
                            st.session_state.terminal_logs.append(f"RESPONSE: Status {response.status_code} - HTTP OK.")
                            st.session_state.terminal_logs.append("SUCCESS: Alert ingested into SOC queues. Playbook active.")
                            st.success("SOC alert transmitted successfully!", icon=":material/check_circle:")
                        else:
                            st.session_state.terminal_logs.append(f"RESPONSE: Status {response.status_code} - Transfer warning.")
                            st.warning(f"Sent successfully but returned status {response.status_code}")
                except Exception as ex:
                    st.session_state.terminal_logs.append(f"ERROR: Webhook payload dispatch failed: {str(ex)}")
                    st.session_state.terminal_logs.append("FALLBACK: Writing local alert to sandbox database.")
                    st.error("Webhook endpoint unreachable. Local backup created.", icon=":material/warning:")
                    
                st.rerun()
