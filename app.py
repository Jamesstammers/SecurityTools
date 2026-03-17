import streamlit as st
import re
from streamlit.components.v1 import html

# 1. PAGE SETUP
st.set_page_config(page_title="SOC Case Builder", page_icon="🛡️", layout="centered")

# Initialize Timeline in Session State so it survives refreshes
if 'timeline_data' not in st.session_state:
    st.session_state.timeline_data = []

# 2. INSTRUCTIONS
st.title("🛡️ Incident Case Builder")
st.info("💡 **Instructions:** Paste JSON, fill in your analysis, then click **Generate Final Template** at the bottom.")

# 3. PERMANENT INPUT FIELDS (Outside any 'if' blocks)
raw_json = st.text_area("1. Paste Raw Kibana JSON", height=150, placeholder="Paste JSON here...")

st.divider()

st.subheader("⚠️ 2. Activity Type")
activity_type = st.selectbox("Type of activity detected:", 
                             ["Malware", "Hacking", "Social", "Misuse", "Physical", "Error"])

st.divider()

st.subheader("📅 3. Timeline of Events")
t_col1, t_col2, t_col3 = st.columns([1, 2, 1])
with t_col1:
    t_stamp = st.text_input("Timestamp", placeholder="HH:MM:SS")
with t_col2:
    t_desc = st.text_input("Event Description", placeholder="e.g. User logged in...")
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

st.subheader("🎯 4. Potential Impact")
st.caption("Guidance: Operations (Downtime) | Data (Exfil) | Reputation (Trust)")
imp_ops = st.text_input("Operations Impact")
imp_data = st.text_input("Data Impact")
imp_rep = st.text_input("Reputation Impact")

st.divider()

st.subheader("🔍 5. Triage & Verdict")
verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
summary_val = st.text_area("Summary", placeholder="Reasoning for verdict...")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# 4. GENERATION BUTTON (The only thing inside an 'if')
if st.button("🚀 Generate Final Template", type="primary"):
    if not raw_json.strip():
        st.error("Please paste JSON first!")
    else:
        # (Insert the extraction and markdown assembly logic here)
        st.success("✅ Template Ready Below")
        # [Insert the HTML Copy Box here]
