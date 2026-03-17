import streamlit as st
import re
from streamlit.components.v1 import html

# 1. SETUP & STYLE
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
    .stTextArea textarea, .stTextInput input { 
        font-family: 'Courier New', monospace !important; 
        font-size: 13px !important; 
        background-color: #f1f3f6 !important; 
        color: #1a1c23 !important; 
    }
    .stTextArea textarea::placeholder { color: #6c757d !important; }
    .stButton>button { width: 100%; border-radius: 4px; height: 3em; font-weight: bold; }
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# Initialize Session States
if 'timeline_data' not in st.session_state: st.session_state.timeline_data = []
if 'external_links' not in st.session_state: st.session_state.external_links = []

def clear_all():
    st.session_state.timeline_data = []
    st.session_state.external_links = []
    st.session_state.raw_input = ""
    st.rerun()

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v5.0 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
raw_json = st.text_area("1. Paste Raw Kibana JSON", height=150, key="raw_input")

st.divider()

# --- STEP 2: ACTIVITY TYPE ---
st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])

st.divider()

# --- STEP 3: TIMELINE ---
st.subheader("📅 3. Timeline of Events")
t_col1, t_col2 = st.columns(2)
with t_col1: t_stamp = st.text_input("Timestamp", placeholder="HH:MM:SS")
with t_col2: t_desc = st.text_input("Event Description", placeholder="e.g. User logged in...")

if st.button("Add Event to Timeline"):
    if t_stamp and t_desc:
        st.session_state.timeline_data.append({"Timestamp": t_stamp, "Event Description": t_desc})
        st.rerun()

if st.session_state.timeline_data:
    st.table(st.session_state.timeline_data)
    if st.button("Clear Timeline Table"):
        st.session_state.timeline_data = []
        st.rerun()

st.divider()

# --- STEP 4: POTENTIAL IMPACT ---
st.subheader("🎯 4. Potential Impact")
impact_text = st.text_area("Assess Operations, Data, and Reputation risk:", height=120, 
    placeholder="Operations: (e.g., Service downtime)\nData: (e.g., Potential for exfiltration)\nReputation: (e.g., Regulatory compliance)")

st.divider()

# --- STEP 5: TRIAGE & EXTERNAL LINKS ---
st.subheader("🔍 5. Triage & Analysis")

with st.expander("🔗 Add External Investigation Links", expanded=True):
    l_col1, l_col2 = st.columns(2)
    with l_col1: l_title = st.text_input("Link Title", placeholder="e.g. VirusTotal")
    with l_col2: l_url = st.text_input("URL", placeholder="https://...")
    
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()

    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")
        if st.button("Clear All Links"):
            st.session_state.external_links = []
            st.rerun()

analysis_val = st.text_area("Investigation Analysis Details:", height=150)

st.divider()

# --- STEP 6: SUMMARY & VERDICT ---
st.subheader("🏁 6. Summary & Conclusion")
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
summary_val = st.text_area("Final Summary", placeholder="Provide a solid reason for your verdict...")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# --- GENERATE FINAL OUTPUT ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_json.strip():
        st.error("❌ Please paste JSON first!")
    else:
        # FULL EXTRACTION LIST RESTORED
        fields = [
            "kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name",
            "signal.rule.threat.technique.name", "kibana.alert.rule.threat.technique.id",
            "kibana.alert.rule.threat.technique.reference", "process.command_line",
            "process.parent.executable", "user.name.text", "host.name",
            "winlog.event_id", "kibana.alert.original_time", "kibana.alert.reason",
            "kibana.alert.rule.false_positives", "signal.rule.false_positives",
            "url.original", "source.enrichment.site_name_and_system",
            "destination.ip", "source.ip", "source.port", "destination.port",
            "destination.bytes", "user_agent.original", "event.action",
            "http.proxy.status_code", "hashicorp_vault.audit.request.headers.user-agent"
        ]
        
        results = {f: "" for f in fields}
        for f in fields:
            pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
            match = re.search(pattern, raw_json, re.DOTALL)
            if match:
                results[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

        def is_valid(val):
            return val and str(val).strip() not in ["", "Not Found", "N/A", "None"]

        # Build Markdown
        rule_name = results.get('kibana.alert.rule.name', 'Security Alert')
        md = [f"# 🛡️ {rule_name}"]
        if is_valid(results.get('kibana.alert.reason')):
            md.append(f"`{results['kibana.alert.reason']}`")
        
        md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
        
        # Metadata Table Population
        if is_valid(results.get('host.name')): md.append(f"| **Host Name** | `{results['host.name']}` |")
        if is_valid(results.get('user.name.text')): md.append(f"| **User Name** | `{results['user.name.text']}` |")
        if is_valid(results.get('event.action')): md.append(f"| **Action** | `{results['event.action']}` |")
        
        if is_valid(results.get('source.ip')):
            src = f"`{results['source.ip']}`"
            if is_valid(results.get('source.port')): src += f":`{results['source.port']}`"
            md.append(f"| **Source** | {src} |")
        if is_valid(results.get('destination.ip')):
            dst = f"`{results['destination.ip']}`"
            if is_valid(results.get('destination.port')): dst += f":`{results['destination.port']}`"
            md.append(f"| **Destination** | {dst} |")
        
        if is_valid(results.get('destination.bytes')): md.append(f"| **Bytes Sent** | `{results['destination.bytes']}` |")
        if is_valid(results.get('url.original')): md.append(f"| **URL** | `{results['url.original']}` |")
        if is_valid(results.get('http.proxy.status_code')): md_lines.append(f"| **Proxy Status** | `{results['http.proxy.status_code']}` |")
        if is_valid(results.get('user_agent.original')): md.append(f"| **User Agent** | `{results['user_agent.original']}` |")
        if is_valid(results.get('hashicorp_vault.audit.request.headers.user-agent')): md.append(f"| **Vault UA** | `{results['hashicorp_vault.audit.request.headers.user-agent']}` |")
        if is_valid(results.get('source.enrichment.site_name_and_system')): md.append(f"| **Site/System** | `{results['source.enrichment.site_name_and_system']}` |")

        # MITRE
        if is_valid(results.get('signal.rule.threat.technique.name')):
            tech_id = results.get('kibana.alert.rule.threat.technique.id', '')
            md.append(f"| **MITRE Technique** | {results['signal.rule.threat.technique.name']} ({tech_id}) |")
        if is_valid(results.get('kibana.alert.rule.threat.tactic.name')): md.append(f"| **MITRE Tactic** | {results['kibana.alert.rule.threat.tactic.name']} |")
        if is_valid(results.get('kibana.alert.rule.threat.technique.reference')): md.append(f"| **MITRE Link** | [View on MITRE ATT&CK]({results['kibana.alert.rule.threat.technique.reference']}) |")
        
        if is_valid(results.get('winlog.event_id')): md.append(f"| **Event ID** | `{results['winlog.event_id']}` |")
        if is_valid(results.get('kibana.alert.original_time')): md.append(f"| **Alert Time** | `{results['kibana.alert.original_time']}` |")

        # Execution
        if is_valid(results.get('process.parent.executable')):
            md += ["", "**Parent Process:**", "```powershell", results['process.parent.executable'], "```"]
        if is_valid(results.get('process.command_line')):
            md += ["", "**Command Line:**", "```powershell", results['process.command_line'], "```"]

        # Activity Type Checkboxes
        md += ["", "## ⚠️ Activity Type Detected"]
        for t in ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"]:
            md.append(f"- [{'x' if t == activity_type else ' '}] {t}")

        # Timeline
        md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
        alert_time = results.get('kibana.alert.original_time', 'T0')
        full_timeline = st.session_state.timeline_data + [{"Timestamp": alert_time, "Event Description": "**ALERT TRIGGERED**"}]
        full_timeline.sort(key=lambda x: x['Timestamp'])
        for e in full_timeline:
            md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")

        md += ["", "## 🎯 Potential Impact", impact_text if impact_text else "N/A"]

        md += ["", "## 🔍 Triage and Analysis Steps", 
               "1. Refer to official Investigation Guide.", 
               "2. Verified against typical user behaviour.", 
               f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'N/A') or results.get('signal.rule.false_positives', 'N/A')}", 
               "", "**Analysis Details:**", analysis_val if analysis_val else "Pending."]

        if st.session_state.external_links:
            md += ["", "## 🔗 External Investigation Links"]
            for link in st.session_state.external_links:
                md.append(f"- [{link['title']}]({link['url']})")

        # DEDICATED SUMMARY SECTION
        md += ["", "## 🗒️ Summary", summary_val if summary_val else "No summary provided."]

        # FINAL CONCLUSION
        md += ["", "## 🏁 Conclusion and Next Steps", f"**Final Determination:** {verdict}", "", "**Next Steps:**"]
        for s in next_steps:
            md.append(f"- [x] {s}")

        final_md = "\n".join(md)

        # Output
        tab1, tab2 = st.tabs(["👁️ Visual Preview", "📋 Copy Template"])
        with tab1: st.markdown(final_md)
        with tab2:
            copy_html = f"""
            <div style="background-color: white; border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                <button id="btn" onclick="copy()" style="background-color: #007bff; color: white; width: 100%; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">📋 Copy Final Case to Clipboard</button>
                <textarea id="out" style="width: 100%; height: 400px; margin-top: 10px; font-family: monospace; color: #111;">{final_md}</textarea>
            </div>
            <script>
            function copy() {{
                var t = document.getElementById("out"); var b = document.getElementById("btn");
                t.select(); document.execCommand("copy");
                b.innerHTML = "✅ Copied!"; b.style.backgroundColor = "#28a745";
                setTimeout(function() {{ b.innerHTML = "📋 Copy Final Case to Clipboard"; b.style.backgroundColor = "#007bff"; }}, 2000);
            }}
            </script>
            """
            html(copy_html, height=550)

st.divider()
st.button("Reset All Fields", on_click=clear_all)
