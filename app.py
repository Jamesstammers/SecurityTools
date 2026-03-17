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
st.caption("v4.7 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
raw_json = st.text_area("1. Paste Raw Kibana JSON", height=150, key="raw_input")

st.divider()

# --- STEP 2: ACTIVITY TYPE ---
st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])

st.divider()

# --- STEP 3: TIMELINE ---
st.subheader("📅 3. Timeline of Events")
t_col1, t_col2, t_col3 = st.columns([1, 2, 1])
with t_col1: t_stamp = st.text_input("Timestamp", placeholder="HH:MM:SS")
with t_col2: t_desc = st.text_input("Event Description", placeholder="e.g. User logged in...")
with t_col3:
    st.write(" ")
    if st.button("Add Event"):
        if t_stamp and t_desc:
            st.session_state.timeline_data.append({"Timestamp": t_stamp, "Event Description": t_desc})
            # Sorting happens at generation to ensure Alert is included correctly
st.caption("The Alert Trigger will be added automatically to the final report.")

if st.session_state.timeline_data:
    st.table(st.session_state.timeline_data)

st.divider()

# --- STEP 4: POTENTIAL IMPACT ---
st.subheader("🎯 4. Potential Impact")
impact_text = st.text_area("Assess Operations, Data, and Reputation risk:", height=100, 
    placeholder="Operations: ...\nData: ...\nReputation: ...")

st.divider()

# --- STEP 5: TRIAGE & EXTERNAL LINKS ---
st.subheader("🔍 5. Triage & Analysis")

with st.expander("🔗 Add External Investigation Links", expanded=True):
    l_col1, l_col2, l_col3 = st.columns([1.5, 2, 1])
    with l_col1: l_title = st.text_input("Link Title", placeholder="e.g. VirusTotal")
    with l_col2: l_url = st.text_input("URL", placeholder="https://...")
    with l_col3:
        st.write(" ")
        if st.button("Add Link"):
            if l_title and l_url:
                st.session_state.external_links.append({"title": l_title, "url": l_url})

    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")

analysis_val = st.text_area("Investigation Analysis Details:", height=150)
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
summary_val = st.text_area("Summary Statement", height=100)
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# --- GENERATE FINAL OUTPUT ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_json.strip():
        st.error("❌ Please paste JSON first!")
    else:
        # Extraction
        fields = ["kibana.alert.rule.name", "kibana.alert.original_time", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "kibana.alert.rule.false_positives", "kibana.alert.reason"]
        results = {f: "" for f in fields}
        for f in fields:
            pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
            match = re.search(pattern, raw_json, re.DOTALL)
            if match: results[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

        # Build Markdown
        md = [f"# 🛡️ {results.get('kibana.alert.rule.name', 'Security Alert')}"]
        if results.get('kibana.alert.reason'): md.append(f"`{results['kibana.alert.reason']}`")
        
        md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
        if results.get('host.name'): md.append(f"| **Host Name** | `{results['host.name']}` |")
        if results.get('user.name.text'): md.append(f"| **User Name** | `{results['user.name.text']}` |")
        
        if results.get('process.parent.executable'):
            md += ["", "**Parent Process:**", "```powershell", results['process.parent.executable'], "```"]
        if results.get('process.command_line'):
            md += ["", "**Command Line:**", "```powershell", results['process.command_line'], "```"]

        md += ["", "## ⚠️ Activity Type Detected"]
        for t in ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"]:
            md.append(f"- [{'x' if t == activity_type else ' '}] {t}")

        # Timeline Construction
        md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
        
        # Merge Alert Trigger and Manual Events
        alert_time = results.get('kibana.alert.original_time', 'T0')
        full_timeline = st.session_state.timeline_data + [{"Timestamp": alert_time, "Event Description": "**ALERT TRIGGERED**"}]
        # Sort chronologically by timestamp string
        full_timeline.sort(key=lambda x: x['Timestamp'])
        
        for e in full_timeline:
            md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")

        md += ["", "## 🎯 Potential Impact", impact_text if impact_text else "N/A"]

        md += ["", "## 🔍 Triage and Analysis Steps", "1. Refer to official Investigation Guide.", "2. Verified against typical user behaviour.", f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'N/A')}", "", "**Analysis Details:**", analysis_val if analysis_val else "Pending."]

        if st.session_state.external_links:
            md += ["", "## 🔗 External Investigation Links"]
            for link in st.session_state.external_links:
                md.append(f"- [{link['title']}]({link['url']})")

        # SUMMARY SECTION (Now its own section)
        md += ["", "## 🗒️ Summary", summary_val if summary_val else "No summary provided."]

        md += ["", "## 🏁 Conclusion and Next Steps", f"**Final Determination:** {verdict}", "", "**Next Steps:**"]
        for s in next_steps: md.append(f"- [x] {s}")

        final_md = "\n".join(md)

        # Output
        tab1, tab2 = st.tabs(["👁️ Preview", "📋 Copy Template"])
        with tab1: st.markdown(final_md)
        with tab2:
            copy_html = f"""
            <div style="background-color: white; border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                <button id="btn" onclick="copy()" style="background-color: #007bff; color: white; width: 100%; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">📋 Copy Final Case to Clipboard</button>
                <textarea id="out" style="width: 100%; height: 350px; margin-top: 10px; font-family: monospace; color: #111;">{final_md}</textarea>
            </div>
            <script>
            function copy() {{
                var t = document.getElementById("out"); var b = document.getElementById("btn");
                t.select(); document.execCommand("copy");
                b.innerHTML = "✅ Copied!"; b.style.backgroundColor = "#28a745";
                setTimeout(function() {{ b.innerHTML = "📋 Copy to Clipboard"; b.style.backgroundColor = "#007bff"; }}, 2000);
            }}
            </script>
            """
            html(copy_html, height=450)

st.button("Reset All Fields", on_click=clear_all)
