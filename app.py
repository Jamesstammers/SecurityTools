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
if 'show_template' not in st.session_state: st.session_state.show_template = False

def clear_all():
    # Clear all session state keys
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    # No st.rerun() needed here! 
    # Streamlit triggers a rerun automatically after this callback ends.


# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v5.2 | SOC Investigation & Reporting Tool")

# --- STEP 1: JSON INPUT ---
st.subheader("📋 1. Alert Data")
raw_json = st.text_area("Paste Raw Kibana JSON", height=150, key="raw_input")

st.divider()

# --- STEP 2: ACTIVITY TYPE ---
st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"], key="act_type")

st.divider()

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

st.divider()

# --- STEP 4: POTENTIAL IMPACT ---
st.subheader("🎯 4. Potential Impact")
impact_text = st.text_area("Assess Operations, Data, and Reputation risk:", height=120, key="impact",
    placeholder="Operations: (e.g., Service downtime)\nData: (e.g., Potential for exfiltration)\nReputation: (e.g., Regulatory compliance)")

st.divider()

# --- STEP 5: TRIAGE & EXTERNAL LINKS ---
st.subheader("🔍 5. Triage & Analysis")

with st.expander("🔗 Add External Investigation Links", expanded=True):
    l_col1, l_col2 = st.columns(2)
    with l_col1: l_title = st.text_input("Link Title", placeholder="e.g. VirusTotal")
    with l_col2: l_url = st.text_input("URL", placeholder="https://...")
    if st.button("Add Link"):
        if l_title and l_url:
            st.session_state.external_links.append({"title": l_title, "url": l_url})
            st.rerun()
    if st.session_state.external_links:
        for link in st.session_state.external_links:
            st.caption(f"✅ Added: **{link['title']}**")

analysis_val = st.text_area("Investigation Analysis Details:", height=150, key="analysis")

st.divider()

# --- STEP 6: SUMMARY & VERDICT ---
st.subheader("🏁 6. Summary & Conclusion")
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True, key="verdict")
summary_val = st.text_area("Final Summary", placeholder="Provide a solid reason for your verdict...", key="summary")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"], key="steps")

st.divider()

# --- GENERATE LOGIC ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_json.strip():
        st.error("❌ Please paste JSON first!")
    else:
        st.session_state.show_template = True

if st.session_state.show_template:
    # EXTRACTION
    fields = ["kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name", "signal.rule.threat.technique.name", "kibana.alert.rule.threat.technique.id", "kibana.alert.rule.threat.technique.reference", "process.command_line", "process.parent.executable", "user.name.text", "host.name", "winlog.event_id", "kibana.alert.original_time", "kibana.alert.reason", "kibana.alert.rule.false_positives", "signal.rule.false_positives", "url.original", "source.enrichment.site_name_and_system", "destination.ip", "source.ip", "source.port", "destination.port", "destination.bytes", "user_agent.original", "event.action", "http.proxy.status_code", "hashicorp_vault.audit.request.headers.user-agent"]
    res = {f: "" for f in fields}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_json, re.DOTALL)
        if match: res[f] = match.group(1).replace('\\\\', '\\').replace('\\"', '"')

    def is_valid(val): return val and str(val).strip() not in ["", "Not Found", "N/A", "None"]

    # Build MD
    md = [f"# 🛡️ {res.get('kibana.alert.rule.name', 'Security Alert')}"]
    if is_valid(res.get('kibana.alert.reason')): md.append(f"`{res['kibana.alert.reason']}`")
    md += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
    
    if is_valid(res.get('host.name')): md.append(f"| **Host Name** | `{res['host.name']}` |")
    if is_valid(res.get('user.name.text')): md.append(f"| **User Name** | `{res['user.name.text']}` |")
    if is_valid(res.get('source.ip')):
        s = f"`{res['source.ip']}`"
        if is_valid(res.get('source.port')): s += f":`{res['source.port']}`"
        md.append(f"| **Source** | {s} |")
    if is_valid(res.get('destination.ip')):
        d = f"`{res['destination.ip']}`"
        if is_valid(res.get('destination.port')): d += f":`{res['destination.port']}`"
        md.append(f"| **Destination** | {d} |")
    if is_valid(res.get('url.original')): md.append(f"| **URL** | `{res['url.original']}` |")
    if is_valid(res.get('http.proxy.status_code')): md.append(f"| **Proxy Status** | `{res['http.proxy.status_code']}` |")
    
    if is_valid(res.get('process.parent.executable')): md += ["", "**Parent Process:**", "```powershell", res['process.parent.executable'], "```"]
    if is_valid(res.get('process.command_line')): md += ["", "**Command Line:**", "```powershell", res['process.command_line'], "```"]

    md += ["", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |"]
    alert_time = res.get('kibana.alert.original_time', 'T0')
    full_t = st.session_state.timeline_data + [{"Timestamp": alert_time, "Event Description": "**ALERT TRIGGERED**"}]
    full_t.sort(key=lambda x: x['Timestamp'])
    for e in full_t: md.append(f"| `{e['Timestamp']}` | {e['Event Description']} |")

    md += ["", "## 🎯 Potential Impact", impact_text if impact_text else "N/A"]
    md += ["", "## 🔍 Triage and Analysis Steps", "1. Refer to Guide.", "2. Behaviour check.", f"3. Baseline: {res.get('kibana.alert.rule.false_positives', 'N/A')}", "", "**Analysis Details:**", analysis_val if analysis_val else "Pending."]
    
    if st.session_state.external_links:
        md += ["", "## 🔗 External Links"]
        for l in st.session_state.external_links: md.append(f"- [{l['title']}]({l['url']})")

    md += ["", "## 🗒️ Summary", summary_val if summary_val else "N/A"]
    md += ["", "## 🏁 Conclusion", f"**Final Determination:** {verdict}", "", "**Next Steps:**"]
    for s in next_steps: md.append(f"- [x] {s}")

    final_md = "\n".join(md)
    st.success("✅ Template Generated!")
    t1, t2 = st.tabs(["👁️ Preview", "📋 Copy Template"])
    with t1: st.markdown(final_md)
    with t2:
        html(f"""
        <div style="background-color: white; border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
            <button id="btn" onclick="copy()" style="background-color: #007bff; color: white; width: 100%; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">📋 Copy Final Case</button>
            <textarea id="out" style="width: 100%; height: 350px; margin-top: 10px;">{final_md}</textarea>
        </div>
        <script>
        function copy() {{
            var t = document.getElementById("out"); var b = document.getElementById("btn");
            t.select(); document.execCommand("copy");
            b.innerHTML = "✅ Copied!"; b.style.backgroundColor = "#28a745";
            setTimeout(function() {{ b.innerHTML = "📋 Copy Final Case"; b.style.backgroundColor = "#007bff"; }}, 2000);
        }}
        </script>
        """, height=500)

st.divider()
st.button("🔄 Reset All Fields", on_click=clear_all)
