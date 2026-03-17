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
    .stButton>button { width: 100%; border-radius: 4px; height: 3em; font-weight: bold; }
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# Initialize Session States
if 'timeline_data' not in st.session_state: st.session_state.timeline_data = []
if 'external_links' not in st.session_state: st.session_state.external_links = []
if 'show_template' not in st.session_state: st.session_state.show_template = False

def clear_all():
    # This clears the internal lists
    st.session_state.timeline_data = []
    st.session_state.external_links = []
    st.session_state.show_template = False
    
    # This clears every widget that has a 'key' assigned
    keys_to_clear = [
        'raw_input', 'impact', 't_stamp', 't_desc', 
        'act_type', 'l_title', 'l_url', 'analysis', 
        'verdict', 'summary', 'steps'
    ]
    for key in keys_to_clear:
        if key in st.session_state:
            # Setting to None or empty string forces the widget to reset
            st.session_state[key] = "" if key != 'steps' else []
    
    # Special case for the Radio/Selectbox to reset to first index
    st.session_state['act_type'] = "Normal Activity"
    st.session_state['verdict'] = "Benign"

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v5.9 | SOC Investigation & Reporting Tool")

# --- SECTION 1: ALERT DATA ---
st.subheader("📋 1. Alert Data")
raw_json = st.text_area("Paste Raw Kibana JSON", height=150, key="raw_input")
st.divider()

# --- SECTION 2: POTENTIAL IMPACT ---
st.subheader("🎯 2. Potential Impact")
impact_text = st.text_area("Assess Operations, Data, and Reputation risk:", height=120, key="impact",
    placeholder="Operations: ...\nData: ...\nReputation: ...")
st.divider()

# --- SECTION 3: TIMELINE ---
st.subheader("📅 3. Timeline of Events")
t_col1, t_col2 = st.columns(2)
with t_col1: t_stamp = st.text_input("Timestamp", placeholder="HH:MM:SS", key="t_stamp")
with t_col2: t_desc = st.text_input("Event Description", placeholder="e.g. User logged in...", key="t_desc")

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

# --- SECTION 4: TRIAGE & ANALYSIS ---
st.subheader("🔍 4. Triage & Analysis")
activity_type = st.selectbox("⚠️ Activity Type Detected:", ["Normal Activity", "Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

with st.expander("🔗 External Investigation Links", expanded=True):
    l_col1, l_col2 = st.columns(2)
    l_title = l_col1.text_input("Link Title", placeholder="VirusTotal", key="l_title")
    l_url = l_col2.text_input("URL", placeholder="https://...", key="l_url")
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()
    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")

analysis_val = st.text_area("Investigation Analysis Details:", height=150, key="analysis")
st.divider()

# --- SECTION 5: SUMMARY & CONCLUSION ---
st.subheader("🏁 5. Summary & Conclusion")
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True, key="verdict")
summary_val = st.text_area("Final Summary", key="summary")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"], key="steps")

st.divider()

# --- GENERATE LOGIC ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_json.strip():
        st.error("❌ Please paste JSON first!")
    else:
        st.session_state.show_template = True

if st.session_state.show_template:
    fields = ["kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name", "signal.rule.threat.technique.name", "kibana.alert.rule.threat.technique.id", "kibana.alert.rule.threat.technique.reference", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "winlog.event_id", "kibana.alert.original_time", "kibana.alert.reason", "kibana.alert.rule.false_positives", "signal.rule.false_positives", "url.original", "source.enrichment.site_name_and_system", "destination.ip", "source.ip", "source.port", "destination.port", "destination.bytes", "user_agent.original", "event.action", "http.proxy.status_code", "hashicorp_vault.audit.request.headers.user-agent"]
    
    res = {f: "" for f in fields}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_json, re.DOTALL)
        if match: res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

    def is_valid(val): return val and str(val).strip() not in ["", "Not Found", "N/A", "None"]

    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}"]
    if is_valid(res.get('kibana.alert.reason')): md.append(f"`{res['kibana.alert.reason']}`")
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    
    display_mapping = {"host.name": "Host Name", "user.name.text": "User Name", "winlog.event_id": "Event ID", "source.ip": "Source IP", "destination.ip": "Dest IP"}
    for key, label in display_mapping.items():
        if is_valid(res.get(key)): md.append(f"| **{label}** | `{res[key]}` |")

    if is_valid(res.get('process.command_line')): md += ["", "**Command Line:**", f"```powershell\n{res['process.command_line']}\n```"]
    md += ["", "## 🎯 Potential Impact", impact_text or "N/A", "## 📅 Timeline", "| Timestamp | Event Description |", "| :--- | :--- |"]
    
    full_t = st.session_state.timeline_data + [{"Timestamp": res.get('kibana.alert.original_time', 'T0'), "Event Description": "**ALERT TRIGGERED**"}]
    for e in sorted(full_t, key=lambda x: x['Timestamp']):
        md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")

    md += ["", "## 🔍 Triage & Analysis", f"**Activity Type:** {activity_type}", "", "**Analysis Details:**", analysis_val or "Pending."]
    
    if st.session_state.external_links:
        md += ["", "**External Links:**"]
        for l in st.session_state.external_links: md.append(f"- [{l['title']}]({l['url']})")

    md += ["", f"## 🏁 Conclusion\n**Verdict:** {verdict}\n\n**Summary:** {summary_val}\n\n**Next Steps:**"]
    for s in next_steps: md.append(f"- [x] {s}")

    final_md = "\n".join(md)
    st.success("✅ Template Generated!")
    t1, t2 = st.tabs(["👁️ Preview", "📋 Copy Template"])
    with t1: st.markdown(final_md)
    with t2:
        html_code = f"""
        <button id="cp_btn" onclick="copy()" style="background-color: #007bff; color: white; border: none; padding: 12px; width: 100%; border-radius: 5px; cursor: pointer; font-weight: bold;">📋 Copy to Clipboard</button>
        <textarea id="copy_area" style="width: 100%; height: 300px; margin-top: 10px; border: 1px solid #ccc; border-radius: 5px; padding: 10px; font-family: monospace;">{final_md}</textarea>
        <script>
        function copy() {{
            var c = document.getElementById("copy_area"); c.select(); document.execCommand("copy");
            var b = document.getElementById("cp_btn"); b.innerHTML = "✅ Copied!"; b.style.backgroundColor = "#28a745";
            setTimeout(function(){{ b.innerHTML = "📋 Copy to Clipboard"; b.style.backgroundColor = "#007bff"; }}, 2000);
        }}
        </script>
        """
        html(html_code, height=400)

st.divider()
st.button("🔄 Reset All Fields", on_click=clear_all)
