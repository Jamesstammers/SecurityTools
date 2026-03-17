import streamlit as st
import re
from streamlit.components.v1 import html

# 1. SETUP & STYLE
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")

# Custom CSS for Professional UI
st.markdown("""
    <style>
    .stTextArea textarea { font-family: 'Courier New', monospace; font-size: 13px; background-color: #f1f3f6 !important; color: #1a1c23 !important; }
    .stButton>button { width: 100%; border-radius: 4px; height: 3em; font-weight: bold; }
    [data-testid="stHorizontalBlock"] { align-items: center; }
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# Session State for Timeline
if 'timeline_data' not in st.session_state:
    st.session_state.timeline_data = []

def clear_all():
    st.session_state.timeline_data = []
    st.session_state.raw_input = ""
    st.rerun()

# --- UI HEADER ---
header_col1, header_col2 = st.columns([1, 4])
with header_col1: st.markdown("# 🛡️")
with header_col2:
    st.title("Incident Case Builder")
    st.caption("v4.2 | SOC Investigation & Reporting Tool")

st.info("💡 **Instructions:** Copy your raw JSON from the Kibana alert log into the box below, fill in your analysis, and click **Generate Final Template**.")

# --- STEP 1: JSON INPUT ---
raw_json = st.text_area("1. Paste Raw Kibana JSON", height=150, key="raw_input")

st.divider()

# --- STEP 2: ACTIVITY TYPE ---
st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", 
                             ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])

st.divider()

# --- STEP 3: TIMELINE ---
st.subheader("📅 3. Timeline of Events")
t_col1, t_col2, t_col3 = st.columns([1, 2, 1])
with t_col1:
    t_stamp = st.text_input("Timestamp", placeholder="HH:MM:SS")
with t_col2:
    t_desc = st.text_input("Event Description", placeholder="User action/log entry...")
with t_col3:
    st.write(" ") # Spacer
    if st.button("Add Event"):
        if t_stamp and t_desc:
            st.session_state.timeline_data.append({"time": t_stamp, "desc": t_desc})
            st.session_state.timeline_data.sort(key=lambda x: x['time'])

if st.session_state.timeline_data:
    st.table(st.session_state.timeline_data)
    if st.button("Clear Timeline"):
        st.session_state.timeline_data = []
        st.rerun()

st.divider()

# --- STEP 4: POTENTIAL IMPACT (Simplified) ---
st.subheader("🎯 4. Potential Impact")
impact_text = st.text_area(
    "Assess the potential damage or risk to operations, data, and reputation:",
    height=150,
    placeholder="Operations: (e.g., Service downtime, system lockdown)\nData: (e.g., Potential for exfiltration, unauthorized modification)\nReputation: (e.g., Impact on customer trust, regulatory compliance)"
)

st.divider()

# --- STEP 5: TRIAGE & VERDICT ---
st.subheader("🔍 5. Triage, Analysis & Verdict")
st.warning("""**Triage Prompts:**
- **Consult Guide:** Refer to the official Investigation Guide.
- **Verify Context:** Determine if the activity matches known administrative patterns or typical user behaviour.
- **Check False Positives:** Verify if activity matches baseline activity.""")

verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
summary_val = st.text_area("Summary", placeholder="Reasoning for verdict and incident overview...")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# --- GENERATE FINAL OUTPUT ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_json.strip():
        st.error("❌ Please paste JSON first!")
    else:
        # Extraction
        fields = ["kibana.alert.rule.name", "kibana.alert.original_time", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "kibana.alert.rule.false_positives", "kibana.alert.reason"]
        results = {}
        for f in fields:
            pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
            match = re.search(pattern, raw_json, re.DOTALL)
            results[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"') if match else ""

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

        md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
        alert_time = results.get('kibana.alert.original_time', 'T0')
        full_timeline = st.session_state.timeline_data + [{"time": alert_time, "desc": "**ALERT TRIGGERED**"}]
        full_timeline.sort(key=lambda x: x['time'])
        for e in full_timeline:
            md.append(f"| `{e['time']}` | {e['desc']} |")

        md += ["", "## 🎯 Potential Impact", impact_text if impact_text else "Pending assessment."]

        md += ["", "## 🔍 Triage and Analysis Steps", "1. Refer to official Investigation Guide.", "2. Verified against typical user behaviour.", f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'N/A')}"]
        
        md += ["", "## 🏁 Summary, Conclusion, and Next Steps", f"**Final Determination:** {verdict}", "", f"**Summary:** {summary_val}", "", "**Next Steps:**"]
        for s in next_steps: md.append(f"- [x] {s}")

        final_md = "\n".join(md)

        # Output Tabs
        st.success("✅ Case Template Generated!")
        tab1, tab2 = st.tabs(["👁️ Visual Preview", "📋 Copy Template"])
        with tab1: st.markdown(final_md)
        with tab2:
            copy_html = f"""
            <div style="background-color: white; border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                <button id="btn" onclick="copy()" style="background-color: #007bff; color: white; width: 100%; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">📋 Copy to Clipboard</button>
                <textarea id="out" style="width: 100%; height: 350px; margin-top: 10px;">{final_md}</textarea>
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

if st.button("Reset Everything", on_click=clear_all):
    pass
