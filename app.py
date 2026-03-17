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
    st.rerun()

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v5.2 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
st.subheader("📋 1. Alert Data")
raw_json = st.text_area("Paste Raw Kibana JSON", height=150, key="raw_input")

st.divider()

# --- STEP 2: ACTIVITY TYPE ---
activity_type = st.selectbox("⚠️ 2. Activity Type", ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

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

# --- STEP 4: POTENTIAL IMPACT ---
impact_text = st.text_area("🎯 4. Potential Impact", height=120, key="impact",
    placeholder="Operations: ...\nData: ...\nReputation: ...")

# --- STEP 5: TRIAGE & EXTERNAL LINKS ---
st.subheader("🔍 5. Triage & Analysis")
with st.expander("🔗 Add External Investigation Links", expanded=True):
    l_col1, l_col2 = st.columns(2)
    l_title = l_col1.text_input("Link Title", placeholder="VirusTotal")
    l_url = l_col2.text_input("URL", placeholder="https://...")
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()
    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")

analysis_val = st.text_area("Investigation Analysis Details:", height=150, key="analysis")

# --- STEP 6: SUMMARY & VERDICT ---
st.subheader("🏁 6. Summary & Conclusion")
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
    # RE-IMPLEMENTED REGEX EXTRACTION
    fields = ["kibana.alert.rule.name", "kibana.alert.reason", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "source.ip", "destination.ip", "kibana.alert.original_time"]
    res = {f: "" for f in fields}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_json, re.DOTALL)
        if match: res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

    # Build MD
    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}"]
    if res.get('kibana.alert.reason'): md.append(f"`{res['kibana.alert.reason']}`")
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    
    for label, key in [("Host", "host.name"), ("User", "user.name.text"), ("Source IP", "source.ip"), ("Dest IP", "destination.ip")]:
        if res.get(key): md.append(f"| **{label}** | `{res[key]}` |")
    
    if res.get('process.command_line'):
        md += ["", "**Command Line:**", f"```powershell\n{res['process.command_line']}\n```"]

    md += ["", "## 📅 Timeline", "| Timestamp | Event Description |", "| :--- | :--- |"]
    for e in st.session_state.timeline_data:
        md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")
    md.append(f"| `{res.get('kibana.alert.original_time', 'T0')}` | **ALERT TRIGGERED** |")

    md += ["", "## 🎯 Impact", impact_text or "N/A", "## 🔍 Analysis", analysis_val or "Pending."]
    
    if st.session_state.external_links:
        md += ["", "## 🔗 Links"]
        for l in st.session_state.external_links: md.append(f"- [{l['title']}]({l['url']})")

    md += ["", f"## 🏁 Conclusion\n**Verdict:** {verdict}\n\n**Next Steps:**"]
    for s in next_steps: md.append(f"- [x] {s}")

    final_md = "\n".join(md)
    
    st.success("✅ Template Generated!")
    t1, t2 = st.tabs(["👁️ Preview", "📋 Copy Template"])
    with t1: st.markdown(final_md)
    with t2:
        # Improved HTML Copy Component
        html_code = f"""
        <div style="font-family: sans-serif;">
            <button id="cp_btn" onclick="copyToClipboard()" style="background-color: #007bff; color: white; border: none; padding: 12px; width: 100%; border-radius: 5px; cursor: pointer; font-weight: bold;">📋 Copy to Clipboard</button>
            <textarea id="copy_area" style="width: 100%; height: 300px; margin-top: 10px; border: 1px solid #ccc; border-radius: 5px; padding: 10px; font-family: monospace;">{final_md}</textarea>
        </div>
        <script>
        function copyToClipboard() {{
            var copyText = document.getElementById("copy_area");
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            document.execCommand("copy");
            var btn = document.getElementById("cp_btn");
            btn.innerHTML = "✅ Copied!";
            btn.style.backgroundColor = "#28a745";
            setTimeout(function(){{ btn.innerHTML = "📋 Copy to Clipboard"; btn.style.backgroundColor = "#007bff"; }}, 2000);
        }}
        </script>
        """
        html(html_code, height=450)

st.divider()
st.button("🔄 Reset All Fields", on_click=clear_all)
