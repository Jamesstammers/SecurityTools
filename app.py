import streamlit as st
import json
from datetime import datetime

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
    for key in st.session_state.keys():
        del st.session_state[key]
    st.rerun()

def extract_nested_json(data, field_list):
    """Recursively extracts fields from nested JSON."""
    results = {f: "" for f in field_list}
    def search(d, current_key=""):
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{current_key}.{k}" if current_key else k
                if new_key in field_list: results[new_key] = v
                search(v, new_key)
        elif isinstance(d, list):
            for item in d: search(item, current_key)
    search(data)
    return results

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v5.5 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
st.subheader("📋 1. Alert Data")
raw_input = st.text_area("Paste Raw Kibana JSON", height=150, key="raw_input")

# --- STEP 2: ACTIVITY TYPE ---
st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

# --- STEP 3: TIMELINE ---
st.subheader("📅 3. Timeline of Events")
t_col1, t_col2 = st.columns([1, 2])
with t_col1: 
    # Default to current time for efficiency
    t_stamp = st.text_input("Timestamp", value=datetime.now().strftime("%H:%M:%S"), key="t_stamp")
with t_col2: 
    t_desc = st.text_input("Event Description", placeholder="e.g. Malicious file executed", key="t_desc")

if st.button("Add Event to Timeline"):
    if t_stamp and t_desc:
        st.session_state.timeline_data.append({"Timestamp": t_stamp, "Event Description": t_desc})
        st.rerun()

if st.session_state.timeline_data:
    st.table(st.session_state.timeline_data)
    if st.button("Clear Timeline Table"):
        st.session_state.timeline_data = []
        st.rerun()

# --- STEP 4-6: IMPACT, ANALYSIS & VERDICT ---
st.divider()
impact_text = st.text_area("🎯 4. Potential Impact", height=100, key="impact", placeholder="Operations: ...\nData: ...")

st.subheader("🔍 5. Triage & Analysis")
with st.expander("🔗 Add External Investigation Links"):
    l_col1, l_col2 = st.columns(2)
    l_title = l_col1.text_input("Link Title", placeholder="VirusTotal")
    l_url = l_col2.text_input("URL", placeholder="https://...")
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()

analysis_val = st.text_area("Investigation Details:", height=150, key="analysis")

st.subheader("🏁 6. Summary & Conclusion")
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True, key="verdict")
summary_val = st.text_area("Final Summary", key="summary")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"], key="steps")

# --- GENERATE LOGIC ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_input.strip():
        st.error("❌ Please paste JSON first!")
    else:
        st.session_state.show_template = True

if st.session_state.show_template:
    fields = ["kibana.alert.rule.name", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "kibana.alert.original_time"]
    try:
        json_data = json.loads(raw_input)
        res = extract_nested_json(json_data, fields)
    except Exception:
        st.error("⚠️ Invalid JSON format. Please check your input.")
        res = {f: "N/A" for f in fields}

    # Build Markdown Report
    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    for label, key in [("Host", "host.name"), ("User", "user.name.text")]:
        md.append(f"| **{label}** | `{res.get(key, 'N/A')}` |")
    
    if res.get("process.command_line"):
        md += ["", "**Command Line:**", f"```powershell\n{res['process.command_line']}\n```"]

    md += ["", "## 📅 Timeline", "| Timestamp | Event Description |", "| :--- | :--- |"]
    for e in st.session_state.timeline_data:
        md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")

    md += ["", "## 🎯 Impact", impact_text or "N/A", "## 🔍 Analysis", analysis_val or "Pending."]
    
    if st.session_state.external_links:
        md += ["", "## 🔗 Links"]
        for l in st.session_state.external_links: md.append(f"- [{l['title']}]({l['url']})")

    md += ["", f"## 🏁 Conclusion\n**Verdict:** {verdict}\n\n**Next Steps:**"]
    for s in next_steps: md.append(f"- [x] {s}")

    final_md = "\n".join(md)
    
    t1, t2 = st.tabs(["👁️ Preview", "📋 Copy Template"])
    with t1: st.markdown(final_md)
    with t2:
        st.info("Use the button in the top-right of the box below to copy.")
        st.code(final_md, language="markdown") # Reliable copy feature

st.divider()
st.button("🔄 Reset All Fields", on_click=clear_all)
