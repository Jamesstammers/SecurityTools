import streamlit as st
import re
from streamlit.components.v1 import html

# 1. PAGE CONFIGURATION
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")

# Custom CSS for Professional UI
st.markdown("""
    <style>
    .stTextArea textarea { font-family: 'Courier New', monospace; font-size: 13px; background-color: #f1f3f6 !important; color: #1a1c23 !important; }
    .stButton>button { width: 100%; border-radius: 4px; height: 3em; font-weight: bold; }
    footer {visibility: hidden;}
    .stExpander { border: 1px solid #dee2e6; border-radius: 8px; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE INITIALISATION ---
if 'timeline_events' not in st.session_state:
    st.session_state.timeline_events = []
if 'raw_input' not in st.session_state:
    st.session_state.raw_input = ""

def clear_all():
    st.session_state.timeline_events = []
    st.session_state.raw_input = ""
    st.rerun()

# --- UI HEADER ---
header_col1, header_col2 = st.columns([1, 6])
with header_col1: st.markdown("# 🛡️")
with header_col2:
    st.title("Incident Case Builder")
    st.caption("v4.0 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
st.subheader("Step 1: Alert Data")
raw_text = st.text_area("Paste Kibana JSON here", value=st.session_state.raw_input, height=150, key="raw_input")

if raw_text.strip():
    # Extraction Logic
    def extract_fields(raw_input):
        fields = [
            "kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name",
            "signal.rule.threat.technique.name", "kibana.alert.rule.threat.technique.id",
            "kibana.alert.rule.threat.technique.reference", "process.command_line",
            "process.parent.executable", "user.name.text", "host.name",
            "winlog.event_id", "kibana.alert.original_time", "kibana.alert.reason",
            "kibana.alert.rule.false_positives", "signal.rule.false_positives",
            "url.original", "source.ip", "destination.ip", "source.port", "destination.port",
            "destination.bytes", "user_agent.original", "event.action", "http.proxy.status_code",
            "hashicorp_vault.audit.request.headers.user-agent", "source.enrichment.site_name_and_system"
        ]
        res = {}
        for f in fields:
            pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
            match = re.search(pattern, raw_input, re.DOTALL)
            res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"') if match else ""
        return res

    results = extract_fields(raw_text)
    
    st.divider()
    
    # --- STEP 2: ACTIVITY & IMPACT ---
    st.subheader("Step 2: Activity & Impact")
    col1, col2 = st.columns(2)
    
    with col1:
        act_type = st.selectbox("Type of Activity Detected", 
                                ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])
        
    with col2:
        st.write("**Impact Guidance:**")
        st.caption("Operations: Service downtime, system lockdown")
        st.caption("Data: Exfiltration, unauthorized modification")
        st.caption("Reputation: Customer trust, compliance")

    imp_ops = st.text_input("Operations Impact", placeholder="e.g. Service degraded...")
    imp_data = st.text_input("Data Impact", placeholder="e.g. No exfiltration observed...")
    imp_rep = st.text_input("Reputation Impact", placeholder="e.g. Regulatory notification required...")

    st.divider()

    # --- STEP 3: TIMELINE (Iterative) ---
    st.subheader("Step 3: Timeline of Events")
    with st.expander("➕ Add Event to Timeline", expanded=True):
        t_col1, t_col2 = st.columns([1, 3])
        with t_col1:
            t_time = st.text_input("Timestamp", placeholder="HH:MM:SS")
        with t_col2:
            t_desc = st.text_input("Event Description", placeholder="User logged in from new IP...")
        
        if st.button("Add Event"):
            if t_time and t_desc:
                st.session_state.timeline_events.append({"time": t_time, "desc": t_desc})
                st.session_state.timeline_events.sort(key=lambda x: x['time'])
                st.rerun()

    if st.session_state.timeline_events:
        st.table(st.session_state.timeline_events)
        if st.button("🗑️ Clear Timeline"):
            st.session_state.timeline_events = []
            st.rerun()

    st.divider()

    # --- STEP 4: TRIAGE & VERDICT ---
    st.subheader("Step 4: Triage & Verdict")
    st.info("""**Triage Prompts:**
1. **Consult Guide:** Refer to official Investigation Guide.
2. **Verify Context:** Check admin patterns/typical user behaviour.
3. **Check False Positives:** Verify against baseline activity.""")
    
    verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
    
    summary_text = st.text_area("Summary", placeholder="Reasoning for verdict and incident overview...")
    
    next_steps = st.multiselect("Next Steps", 
                                ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

    # --- FINAL GENERATION ---
    st.divider()
    if st.button("🚀 Generate Final Case Template", type="primary"):
        
        # Assemble Markdown
        rule_name = results.get('kibana.alert.rule.name', 'Investigation')
        md = [f"# 🛡️ {rule_name}"]
        if results.get('kibana.alert.reason'): md.append(f"`{results['kibana.alert.reason']}`")
        
        # Table
        md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
        for label, key in [("Host Name", "host.name"), ("User Name", "user.name.text"), ("Action", "event.action")]:
            if results.get(key): md.append(f"| **{label}** | `{results[key]}` |")
        
        # MITRE
        if results.get('signal.rule.threat.technique.name'):
            md.append(f"| **MITRE Technique** | {results['signal.rule.threat.technique.name']} ({results.get('kibana.alert.rule.threat.technique.id')}) |")

        # Execution
        if results.get('process.parent.executable'):
            md += ["", "**Parent Process:**", "```powershell", results['process.parent.executable'], "```"]
        if results.get('process.command_line'):
            md += ["", "**Command Line:**", "```powershell", results['process.command_line'], "```"]

        # Activity Type
        md += ["", "## ⚠️ Activity Type Detected"]
        for t in ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"]:
            md.append(f"- [{'x' if t == act_type else ' '}] {t}")

        # Timeline (Sorted)
        md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
        alert_time = results.get('kibana.alert.original_time', 'T0')
        
        # Insert alert into session timeline for sorting
        full_timeline = st.session_state.timeline_events + [{"time": alert_time, "desc": "**ALERT TRIGGERED**"}]
        full_timeline.sort(key=lambda x: x['time'])
        
        for entry in full_timeline:
            md.append(f"| `{entry['time']}` | {entry['desc']} |")

        # Impact
        md += ["", "## 🎯 Potential Impact", 
               f"- **Operations:** {imp_ops if imp_ops else 'N/A'}", 
               f"- **Data:** {imp_data if imp_data else 'N/A'}", 
               f"- **Reputation:** {imp_rep if imp_rep else 'N/A'}"]

        # Triage
        md += ["", "## 🔍 Triage and Analysis Steps", 
               "1. Refer to official Investigation Guide.", 
               "2. Matches known patterns/typical user behaviour check performed.",
               f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'Checked.')}"]

        # Final
        md += ["", "## 🏁 Summary, Conclusion, and Next Steps", 
               f"**Final Determination:** {verdict}", 
               "", f"**Summary:** {summary_text}", "", "**Next Steps:**"]
        for step in next_steps:
            md.append(f"- [x] {step}")

        final_md = "\n".join(md)

        # Output with Copy Button
        st.success("✅ Case Built Successfully!")
        tab1, tab2 = st.tabs(["👁️ Preview", "📋 Copy Template"])
        with tab1: st.markdown(final_md)
        with tab2:
            copy_html = f"""
            <div style="background-color: white; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
                <button id="cpBtn" onclick="copy()" style="background-color: #007bff; color: white; width: 100%; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">📋 Copy Final Case to Clipboard</button>
                <textarea id="out" style="width: 100%; height: 400px; margin-top: 10px; font-family: monospace;">{final_md}</textarea>
            </div>
            <script>
            function copy() {{
                var t = document.getElementById("out"); var b = document.getElementById("cpBtn");
                t.select(); document.execCommand("copy");
                b.innerHTML = "✅ Copied!"; b.style.backgroundColor = "#28a745";
                setTimeout(function() {{ b.innerHTML = "📋 Copy Final Case to Clipboard"; b.style.backgroundColor = "#007bff"; }}, 2000);
            }}
            </script>
            """
            html(copy_html, height=550)

    st.button("🧹 Reset App", on_click=clear_all)
