import streamlit as st
import re
from datetime import datetime
from streamlit.components.v1 import html

# 1. SETUP & STYLE
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
    /* Theme-aware text boxes for Dark/Light mode visibility */
    .stTextArea textarea, .stTextInput input { 
        font-family: 'Courier New', monospace !important; 
        font-size: 13px !important; 
        background-color: var(--background-color) !important; 
        color: var(--text-color) !important; 
        border: 1px solid rgba(128, 128, 128, 0.3) !important;
        caret-color: var(--text-color) !important;
    }
    /* Ensure placeholders are visible in dark mode */
    ::placeholder { color: var(--text-color) !important; opacity: 0.5; }
    
    .stButton>button { width: 100%; border-radius: 4px; height: 3em; font-weight: bold; }
    footer {visibility: hidden;}
    .stAlert { padding: 10px; font-size: 14px; }
    </style>
    """, unsafe_allow_html=True)

# Initialize Session States
if 'timeline_data' not in st.session_state: st.session_state.timeline_data = []
if 'external_links' not in st.session_state: st.session_state.external_links = []
if 'show_template' not in st.session_state: st.session_state.show_template = False

def clear_all():
    st.session_state.timeline_data = []
    st.session_state.external_links = []
    st.session_state.show_template = False
    widget_keys = ['raw_input', 'impact', 't_str_input', 't_desc_input', 'act_type', 'l_title', 'l_url', 'analysis', 'verdict', 'summary', 'steps']
    for key in widget_keys:
        if key in st.session_state:
            if key == 'steps': st.session_state[key] = []
            elif key == 'act_type': st.session_state[key] = "Normal Activity"
            elif key == 'verdict': st.session_state[key] = "Benign"
            else: st.session_state[key] = ""

# --- AUTO-INJECTION LOGIC ---
def auto_inject_alert_time():
    raw_json = st.session_state.get('raw_input', '')
    if raw_json.strip():
        field = "kibana.alert.original_time"
        pattern = rf'"{re.escape(field)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_json, re.DOTALL)
        if match:
            ts = match.group(1).replace('\\\\', '\\').replace('\\"', '"')
            ts_formatted = ts.split(".") + ".000Z" if "." in ts else ts
            exists = any(item['Event Description'] == "**ALERT TRIGGERED**" for item in st.session_state.timeline_data)
            if not exists:
                st.session_state.timeline_data.append({"Timestamp": ts_formatted, "Event Description": "**ALERT TRIGGERED**"})
                st.session_state.timeline_data.sort(key=lambda x: x['Timestamp'])

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v6.3 | SOC Investigation & Reporting Tool")

# --- ALERT DATA ---
st.subheader("📋 Alert Data")
st.text_area("Paste Raw Kibana JSON", height=150, key="raw_input", on_change=auto_inject_alert_time)
st.divider()

# --- POTENTIAL IMPACT ---
st.subheader("🎯 Potential Impact")
st.text_area("Impact Assessment:", height=120, key="impact")
st.divider()

# --- TIMELINE OF EVENTS ---
st.subheader("📅 Timeline of Events")
t_col1, t_col2, t_col3 = st.columns(3)
with t_col1: d_input = st.date_input("Date")
with t_col2: 
    now_t = datetime.now().strftime("%H:%M:%S")
    t_input_str = st.text_input("Time (HH:MM:SS)", value=now_t, key="t_str_input")
with t_col3: t_desc = st.text_input("Event Description", key="t_desc_input", placeholder="e.g. User logged in...")

if st.button("Add Event to Timeline"):
    if t_desc and t_input_str:
        if re.match(r"^\d{2}:\d{2}:\d{2}$", t_input_str):
            formatted_ts = f"{d_input}T{t_input_str}.000Z"
            st.session_state.timeline_data.append({"Timestamp": formatted_ts, "Event Description": t_desc})
            st.session_state.timeline_data.sort(key=lambda x: x['Timestamp'])
            st.rerun()
        else: st.error("Format time as HH:MM:SS")

if st.session_state.timeline_data:
    for i, entry in enumerate(st.session_state.timeline_data):
        row = st.columns([1.5, 3, 0.5])
        row[0].markdown(f"`{entry['Timestamp']}`")
        row[1].write(entry['Event Description'])
        if row[2].button("🗑️", key=f"del_{i}"):
            st.session_state.timeline_data.pop(i)
            st.rerun()
st.divider()

# --- TRIAGE & ANALYSIS ---
st.subheader("🔍 Triage & Analysis")
activity_type = st.selectbox("⚠️ Activity Type:", ["Normal Activity", "Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

with st.expander("🔗 External Links", expanded=True):
    l_c1, l_c2 = st.columns(2)
    l_t = l_c1.text_input("Title", key="l_title")
    l_u = l_c2.text_input("URL", key="l_url")
    if st.button("Add Link"):
        if l_t and l_u:
            st.session_state.external_links.append({"title": l_t, "url": l_u})
            st.rerun()
    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")

st.text_area("Investigation Details:", height=150, key="analysis")
st.divider()

# --- SUMMARY & CONCLUSION ---
st.subheader("🏁 Summary & Conclusion")
st.radio("Verdict", ["Benign", "True Positive", "False Positive"], horizontal=True, key="verdict")
st.text_area("Final Summary", key="summary")
st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"], key="steps")

# --- GENERATE LOGIC ---
if st.button("🚀 Generate Final Case Report", type="primary"):
    if not st.session_state.raw_input.strip(): st.error("❌ Please paste JSON first!")
    else: st.session_state.show_template = True

if st.session_state.show_template:
    # Full extraction list
    fields = [
        "kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name", "kibana.alert.rule.threat.technique.id", "user.name.text", 
        "host.name", "source.enrichment.site_name_and_system", "winlog.event_id", "kibana.alert.original_time", 
        "destination.ip", "destination.port", "source.ip", "source.port", "process.command_line", "process.parent.executable", "url.original", "destination.bytes", "event.action"
    ]
    
    res = {f: "" for f in fields}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, st.session_state.raw_input, re.DOTALL)
        if match: res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

    def is_valid(v): return v and str(v).strip() not in ["", "Not Found", "N/A", "None", "[]"]

    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}"]
    
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    for field in fields:
        if is_valid(res.get(field)):
            label = field.replace('.', ' ').title()
            md.append(f"| **{label}** | `{res[field]}` |")

    md += ["", "## 🎯 Potential Impact", st.session_state.get('impact', 'N/A') or "N/A"]
    
    md += ["", "## 📅 Timeline", "| Timestamp | Event Description |", "| :--- | :--- |"]
    for e in sorted(st.session_state.timeline_data, key=lambda x: x['Timestamp']):
        md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")

    md += ["", f"## 🔍 Triage & Analysis\n**Activity Type:** {st.session_state.act_type}\n\n**Details:**\n{st.session_state.get('analysis', 'N/A')}"]
    
    if st.session_state.external_links:
        md += ["", "**External Links:**"]
        for l in st.session_state.external_links: md.append(f"- [{l['title']}]({l['url']})")

    md += ["", f"## 🏁 Conclusion\n**Verdict:** {st.session_state.verdict}\n\n**Summary:** {st.session_state.summary}"]
    if st.session_state.steps:
        md += ["", "**Next Steps:**"]
        for s in st.session_state.steps: md.append(f"- [x] {s}")

    final_md = "\n".join(md)
    st.success("✅ Template Generated!")
    t1, t2 = st.tabs(["👁️ Preview", "📋 Copy"])
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
