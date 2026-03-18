import streamlit as st
import re
from datetime import datetime
from streamlit.components.v1 import html

# 1. SETUP & STYLE
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
    /* Use Streamlit's native theme variables so it works in Dark & Light mode */
    .stTextArea textarea, .stTextInput input { 
        font-family: 'Courier New', monospace !important; 
        font-size: 13px !important; 
        /* This picks up the theme's background and text colors automatically */
        background-color: var(--background-color) !important; 
        color: var(--text-color) !important; 
        border: 1px solid rgba(128, 128, 128, 0.3) !important;
    }
    
    /* Ensures the cursor (caret) is always visible by matching text color */
    .stTextArea textarea { caret-color: var(--text-color) !important; }
    .stTextInput input { caret-color: var(--text-color) !important; }

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
    widget_keys = ['raw_input', 'impact', 't_desc_input', 'act_type', 'l_title', 'l_url', 'analysis', 'verdict', 'summary', 'steps']
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
            ts_formatted = ts.split(".")[0] + ".000Z" if "." in ts else ts
            
            exists = any(item['Event Description'] == "**ALERT TRIGGERED**" for item in st.session_state.timeline_data)
            if not exists:
                st.session_state.timeline_data.append({
                    "Timestamp": ts_formatted, 
                    "Event Description": "**ALERT TRIGGERED**"
                })
                st.session_state.timeline_data.sort(key=lambda x: x['Timestamp'])

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v6.3 | SOC Investigation & Reporting Tool")

# --- ALERT DATA ---
st.subheader("📋 Alert Data")
st.info("💡 Paste the raw Kibana JSON. The alert trigger time will be automatically added to your timeline below.")
st.text_area("Paste Raw Kibana JSON", height=150, key="raw_input", on_change=auto_inject_alert_time)
st.divider()

# --- POTENTIAL IMPACT ---
st.subheader("🎯 Potential Impact")
st.text_area("Impact Assessment:", height=120, key="impact")
st.divider()

# --- TIMELINE OF EVENTS ---
st.subheader("📅 Timeline of Events")
st.info("💡 Use the Date picker and enter Time as HH:MM:SS.")

t_col1, t_col2, t_col3 = st.columns([1, 1, 2])
with t_col1: 
    d_input = st.date_input("Date")
with t_col2: 
    # Using text_input allows for SS (seconds). 
    # Defaulting value to current time for convenience.
    now_time = datetime.now().strftime("%H:%M:%S")
    t_input_str = st.text_input("Time (HH:MM:SS)", value=now_time, key="t_str_input")
with t_col3: 
    t_desc = st.text_input("Event Description", placeholder="e.g. Process executed...", key="t_desc_input")

if st.button("Add Event to Timeline"):
    if t_desc and t_input_str:
        try:
            # Combine the date picker and the manual time string
            formatted_ts = f"{d_input}T{t_input_str}.000Z"
            
            # Simple regex check to ensure user entered HH:MM:SS correctly
            if re.match(r"^\d{2}:\d{2}:\d{2}$", t_input_str):
                st.session_state.timeline_data.append({"Timestamp": formatted_ts, "Event Description": t_desc})
                st.session_state.timeline_data.sort(key=lambda x: x['Timestamp'])
                st.rerun()
            else:
                st.error("⚠️ Please enter time in HH:MM:SS format.")
        except Exception as e:
            st.error(f"Error formatting timestamp: {e}")

if st.session_state.timeline_data:
    st.write("### Current Timeline")
    for i, entry in enumerate(st.session_state.timeline_data):
        row_cols = st.columns([1.5, 3, 0.5])
        # Fix for previous column indexing error
        row_cols[0].markdown(f"`{entry['Timestamp']}`")
        row_cols[1].write(entry['Event Description'])
        if row_cols[2].button("🗑️", key=f"del_{i}"):
            st.session_state.timeline_data.pop(i)
            st.rerun()
    
    if st.button("Clear Timeline Table"):
        st.session_state.timeline_data = []
        st.rerun()
st.divider()



# --- TRIAGE & ANALYSIS ---
st.subheader("🔍 Triage & Analysis")
activity_type = st.selectbox("⚠️ Activity Type Detected:", ["Normal Activity", "Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

with st.expander("🔗 External Investigation Links", expanded=True):
    l_col1, l_col2 = st.columns(2)
    l_title = l_col1.text_input("Link Title", key="l_title")
    l_url = l_col2.text_input("URL", key="l_url")
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()
    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")

analysis_val = st.text_area("Investigation Analysis Details:", height=150, key="analysis")
st.divider()

# --- SUMMARY & CONCLUSION ---
st.subheader("🏁 Summary & Conclusion")
verdict = st.radio("Final Categorisation", ["Benign", "True Positive", "False Positive"], horizontal=True, key="verdict")
summary_val = st.text_area("Final Summary", key="summary")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"], key="steps")

# --- GENERATE LOGIC ---
if st.button("🚀 Generate Final Case Report", type="primary"):
    if not st.session_state.raw_input.strip():
        st.error("❌ Please paste JSON first!")
    else:
        st.session_state.show_template = True

if st.session_state.show_template:
    fields = [
        "kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name", 
        "signal.rule.threat.technique.name", "kibana.alert.rule.threat.technique.id", 
        "kibana.alert.rule.threat.technique.reference", "process.command_line", 
        "process.parent.executable", "user.name.text", "host.name", "winlog.event_id", 
        "kibana.alert.original_time", "kibana.alert.reason", 
        "kibana.alert.rule.false_positives","url.original", "source.enrichment.site_name_and_system", 
        "destination.ip", "source.ip", "source.port", "destination.port", 
        "destination.bytes", "user_agent.original", "event.action", 
        "http.proxy.status_code", "hashicorp_vault.audit.request.headers.user-agent"
    ]
    
    res = {f: "" for f in fields}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, st.session_state.raw_input, re.DOTALL)
        if match: 
            res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

    def is_valid(v): return v and str(v).strip() not in ["", "Not Found", "N/A", "None", "[]"]

    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}"]
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    
    for field in fields:
        if is_valid(res.get(field)):
            clean_label = field.replace('.', ' ').replace('_', ' ').title()
            md.append(f"| **{clean_label}** | `{res[field]}` |")

    md += ["", "## 🎯 Potential Impact", impact or "N/A"]
    md += ["", "## 📅 Timeline", "| Timestamp | Event Description |", "| :--- | :--- |"]
    
    for e in sorted(st.session_state.timeline_data, key=lambda x: x['Timestamp']):
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
