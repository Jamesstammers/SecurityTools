import streamlit as st
import re
from streamlit.components.v1 import html

# 1. SETUP & STYLE
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")
st.markdown("""
    <style>
    .stTextArea textarea { font-family: monospace; font-size: 13px; background-color: #f1f3f6 !important; color: #111 !important; }
    .stButton>button { width: 100%; border-radius: 4px; font-weight: bold; height: 3em; }
    </style>
    """, unsafe_allow_html=True)

# Initialize Timeline in Session State
if 'timeline' not in st.session_state:
    st.session_state.timeline = []

def clear_data():
    st.session_state.timeline = []
    st.rerun()

# 2. INSTRUCTIONS & JSON INPUT
st.title("🛡️ Incident Case Builder")
st.info("💡 **Instructions:** Copy your raw JSON from the Kibana alert log into the box below, fill in your analysis, and click **Generate Final Template**.")

raw_json = st.text_area("1. Paste Raw Kibana JSON", height=150)

st.divider()

# 3. ANALYST INPUTS (Always visible)
st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", 
                             ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])

st.divider()

st.subheader("📅 3. Timeline of Events")
# Timeline Input Row
t_col1, t_col2, t_col3 = st.columns([1, 2, 1])
with t_col1:
    t_stamp = st.text_input("Timestamp", placeholder="HH:MM:SS")
with t_col2:
    t_desc = st.text_input("Event Description", placeholder="e.g. User logged in...")
with t_col3:
    st.write(" ") # Padding
    if st.button("Add Event"):
        if t_stamp and t_desc:
            st.session_state.timeline.append({"time": t_stamp, "desc": t_desc})
            st.session_state.timeline.sort(key=lambda x: x['time'])

# Display Current Timeline
if st.session_state.timeline:
    st.table(st.session_state.timeline)
    if st.button("Reset Timeline"):
        st.session_state.timeline = []
        st.rerun()

st.divider()

st.subheader("🎯 4. Potential Impact")
st.caption("Operations: Service downtime, system lockdown | Data: Exfiltration, modification | Reputation: Trust, compliance")
impact_ops = st.text_input("Operations Impact")
impact_data = st.text_input("Data Impact")
impact_rep = st.text_input("Reputation Impact")

st.divider()

st.subheader("🔍 5. Triage & Verdict")
st.markdown("""
- **Consult Guide:** Refer to the official Investigation Guide.
- **Verify Context:** Determine if activity matches known admin patterns or typical user behaviour.
- **Check False Positives:** Verify if activity matches baseline activity.
""")
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
summary = st.text_area("Summary", placeholder="Reasoning for verdict...")

next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# 4. GENERATION LOGIC
if st.button("🚀 Generate Final Template", type="primary"):
    # Extraction
    fields = ["kibana.alert.rule.name", "kibana.alert.original_time", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "kibana.alert.rule.false_positives"]
    results = {}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_json, re.DOTALL)
        results[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"') if match else ""

    # Build Markdown
    md = [f"# 🛡️ {results.get('kibana.alert.rule.name', 'Security Alert')}"]
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    if results.get('host.name'): md.append(f"| **Host Name** | `{results['host.name']}` |")
    if results.get('user.name.text'): md.append(f"| **User Name** | `{results['user.name.text']}` |")
    
    md += ["", "## ⚠️ Activity Type Detected"]
    for t in ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"]:
        md.append(f"- [{'x' if t == activity_type else ' '}] {t}")

    md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
    alert_time = results.get('kibana.alert.original_time', 'T0')
    full_timeline = st.session_state.timeline + [{"time": alert_time, "desc": "**ALERT TRIGGERED**"}]
    full_timeline.sort(key=lambda x: x['time'])
    for e in full_timeline:
        md.append(f"| `{e['time']}` | {e['desc']} |")

    md += ["", "## 🎯 Potential Impact", f"- **Operations:** {impact_ops}", f"- **Data:** {impact_data}", f"- **Reputation:** {impact_rep}"]
    md += ["", "## 🔍 Triage and Analysis Steps", "1. Refer to official Investigation Guide.", "2. Verified against typical user behaviour.", f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'N/A')}"]
    md += ["", "## 🏁 Summary, Conclusion, and Next Steps", f"**Final Determination:** {verdict}", "", f"**Summary:** {summary}", "", "**Next Steps:**"]
    for s in next_steps: md.append(f"- [x] {s}")

    final_md = "\n".join(md)

    # Output
    st.subheader("✅ Final Output")
    st.markdown(final_md)
    
    copy_html = f"""
    <div style="background-color: white; border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
        <button id="btn" onclick="copy()" style="background-color: #007bff; color: white; width: 100%; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">📋 Copy to Clipboard</button>
        <textarea id="out" style="width: 100%; height: 300px; margin-top: 10px;">{final_md}</textarea>
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

if st.button("Reset Everything"):
    clear_data()
