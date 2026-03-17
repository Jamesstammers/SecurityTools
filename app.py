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
    .stExpander { border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 10px;}
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE ---
if 'timeline_events' not in st.session_state: st.session_state.timeline_events = []

def clear_all():
    st.session_state.timeline_events = []
    st.rerun()

# --- UI HEADER ---
header_col1, header_col2 = st.columns([1, 4])
with header_col1: st.markdown("# 🛡️")
with header_col2:
    st.title("Incident Case Builder")
    st.caption("v4.1 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
st.subheader("📋 1. Alert Data")
raw_text = st.text_area("Paste Kibana JSON here", height=150, placeholder='Paste the raw JSON from the Kibana alert log...')

st.divider()

# --- STEP 2: ACTIVITY TYPE ---
st.subheader("⚠️ 2. Type of Activity Detected")
act_type = st.selectbox("Select the detected activity category:", 
                        ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])

st.divider()

# --- STEP 3: TIMELINE ---
st.subheader("📅 3. Timeline of Events")
st.info("Add events in any order; the app will sort them chronologically in the final report.")
with st.expander("➕ Add New Event", expanded=True):
    t_col1, t_col2 = st.columns([1, 3])
    with t_col1:
        t_time = st.text_input("Timestamp", placeholder="HH:MM:SS")
    with t_col2:
        t_desc = st.text_input("Event Description", placeholder="Briefly describe what happened...")
    
    if st.button("Add to Timeline"):
        if t_time and t_desc:
            st.session_state.timeline_events.append({"time": t_time, "desc": t_desc})
            st.rerun()

if st.session_state.timeline_events:
    st.table(st.session_state.timeline_events)
    if st.button("🗑️ Reset Timeline"):
        st.session_state.timeline_events = []
        st.rerun()

st.divider()

# --- STEP 4: IMPACT ---
st.subheader("🎯 4. Potential Impact")
st.write("Assess the potential damage or risk to the following:")
imp_ops = st.text_area("Operations", placeholder="e.g., Service downtime, system lockdown...")
imp_data = st.text_area("Data", placeholder="e.g., Potential for exfiltration, unauthorized modification...")
imp_rep = st.text_area("Reputation", placeholder="e.g., Impact on customer trust, regulatory compliance...")

st.divider()

# --- STEP 5: VERDICT & SUMMARY ---
st.subheader("🔍 5. Triage, Analysis & Verdict")
st.warning("""**Guidance:**
- **Consult Guide:** Refer to the official Investigation Guide.
- **Verify Context:** Check known admin patterns or typical user behaviour.
- **Check False Positives:** Verify against baseline activity.""")

verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)

summary_text = st.text_area("Summary", placeholder="Reasoning for verdict and incident overview...")

next_steps = st.multiselect("Next Steps", 
                            ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# --- FINAL GENERATION ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    
    # 1. Extraction (Hidden from User)
    def extract_fields(raw_input):
        fields = ["kibana.alert.rule.name", "kibana.alert.original_time", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "kibana.alert.reason", "kibana.alert.rule.false_positives"]
        res = {}
        for f in fields:
            pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
            match = re.search(pattern, raw_input, re.DOTALL)
            res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"') if match else ""
        return res

    results = extract_fields(raw_text)
    
    # 2. Assemble Markdown
    rule_name = results.get('kibana.alert.rule.name', 'Security Investigation')
    md = [f"# 🛡️ {rule_name}"]
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
        md.append(f"- [{'x' if t == act_type else ' '}] {t}")

    md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
    alert_time = results.get('kibana.alert.original_time', 'T0')
    full_timeline = st.session_state.timeline_events + [{"time": alert_time, "desc": "**ALERT TRIGGERED**"}]
    full_timeline.sort(key=lambda x: x['time'])
    for entry in full_timeline:
        md.append(f"| `{entry['time']}` | {entry['desc']} |")

    md += ["", "## 🎯 Potential Impact", f"- **Operations:** {imp_ops if imp_ops else 'N/A'}", f"- **Data:** {imp_data if imp_data else 'N/A'}", f"- **Reputation:** {imp_rep if imp_rep else 'N/A'}"]

    md += ["", "## 🔍 Triage and Analysis Steps", "1. Refer to official Investigation Guide.", "2. Matches known patterns/typical user behaviour check performed.", f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'Verified baseline.')}"]

    md += ["", "## 🏁 Summary, Conclusion, and Next Steps", f"**Final Determination:** {verdict}", "", f"**Summary:** {summary_text}", "", "**Next Steps:**"]
    for step in next_steps:
        md.append(f"- [x] {step}")

    final_md = "\n".join(md)

    # 3. Output
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
