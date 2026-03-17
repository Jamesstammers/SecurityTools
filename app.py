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
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    # Removed st.rerun() to fix the "no-op" error

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v5.6 | SOC Investigation & Reporting Tool")

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

# --- SECTION 4: TRIAGE & ANALYSIS ---
st.subheader("🔍 4. Triage & Analysis")
activity_type = st.selectbox("⚠️ Activity Type Detected:", ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

with st.expander("🔗 External Investigation Links"):
    l_col1, l_col2 = st.columns(2)
    l_title = l_col1.text_input("Link Title", placeholder="VirusTotal")
    l_url = l_col2.text_input("URL", placeholder="https://...")
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()

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
    fields = ["kibana.alert.rule.name", "process.command_line", "user.name.text", "host.name", "kibana.alert.original_time"]
    res = {f: "" for f in fields}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_json, re.DOTALL)
        if match: res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

    # Build Markdown Report
    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}"]
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    if res.get('host.name'): md.append(f"| **Host** | `{res['host.name']}` |")
    if res.get('user.name.text'): md.append(f"| **User** | `{res['user.name.text']}` |")
    
    md += ["", "## 🎯 Potential Impact", impact_text or "N/A"]

    md += ["", "## 📅 Timeline", "| Timestamp | Event Description |", "| :--- | :--- |"]
    for e in st.session_state.timeline_data:
        md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")
    md.append(f"| `{res.get('kibana.alert.original_time', 'T0')}` | **ALERT TRIGGERED** |")

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
