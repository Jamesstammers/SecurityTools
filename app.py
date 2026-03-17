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

if 'timeline_data' not in st.session_state: st.session_state.timeline_data = []

def clear_all():
    st.session_state.timeline_data = []
    st.session_state.raw_input = ""
    st.rerun()

# --- UI HEADER ---
st.title("🛡️ Incident Case Builder")
st.caption("v4.4 | SOC Investigation & Reporting Tool")

# --- STEP 1-4 (Truncated for brevity, keep your existing code here) ---
raw_json = st.text_area("1. Paste Raw Kibana JSON", height=150, key="raw_input")
# ... [Include Activity, Timeline, and Impact sections from previous version] ...

st.divider()

# --- STEP 5: TRIAGE & ANALYSIS ---
st.subheader("🔍 5. Triage & Analysis")

# Hyperlink Helper Tool
with st.expander("🔗 Hyperlink Helper (Optional)"):
    st.caption("Generate markdown links to paste into your analysis below.")
    link_col1, link_col2 = st.columns(2)
    with link_col1:
        link_title = st.text_input("Link Title", placeholder="e.g., VirusTotal Report")
    with link_col2:
        link_url = st.text_input("URL", placeholder="https://...")
    
    if link_title and link_url:
        st.code(f"[{link_title}]({link_url})", language="markdown")
        st.caption("👆 Copy this into the Analysis box below.")

analysis_val = st.text_area(
    "Investigation Analysis Details:",
    height=200,
    placeholder="Describe your findings here. You can use markdown or paste links from the helper above."
)

verdict = st.radio("Final Determination", ["Benign", "True Positive", "False Positive"], horizontal=True)
summary_val = st.text_area("Summary Statement", placeholder="Executive summary of the verdict...")
next_steps = st.multiselect("Next Steps", ["Incident escalation required", "Suppress alert / Tune rule", "Close case"])

st.divider()

# --- GENERATE FINAL OUTPUT ---
if st.button("🚀 Generate Final Case Template", type="primary"):
    if not raw_json.strip():
        st.error("❌ Please paste JSON first!")
    else:
        # ... [Keep your existing extraction logic here] ...
        
        # Build Markdown (Section 5 Update)
        # (Add your previous MD building logic here, then update Section 5:)
        
        md_analysis = [
            "", "## 🔍 Triage and Analysis Steps", 
            "1. Refer to official Investigation Guide.", 
            "2. Verified against typical user behaviour.", 
            f"3. Baseline check: {results.get('kibana.alert.rule.false_positives', 'N/A')}",
            "", "**Investigation Details:**",
            analysis_val if analysis_val else "No detailed analysis provided."
        ]
        
        # ... [Combine everything into final_md and show the Copy Box] ...
        # (Use your previous final_md assembly and HTML copy box logic)
