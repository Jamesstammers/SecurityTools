import streamlit as st
import re
from streamlit.components.v1 import html

# 1. PAGE CONFIGURATION
st.set_page_config(page_title="SOC Case Generator", page_icon="🛡️", layout="centered")

# Custom CSS for fixing text colors, alignment, and button text wrapping
st.markdown("""
    <style>
    /* Fix text area colors */
    .stTextArea textarea { 
        font-family: 'Courier New', monospace; 
        font-size: 13px; 
        background-color: #f1f3f6 !important; 
        color: #1a1c23 !important; 
    }
    
    /* Force buttons to be side-by-side and prevent text wrap */
    [data-testid="stHorizontalBlock"] {
        align-items: center;
        display: flex;
        justify-content: center;
    }

    .stButton>button { 
        width: 100%; 
        white-space: nowrap; /* Prevents text from going to second line */
        border-radius: 4px; 
        height: 3em; 
        font-weight: bold; 
    }
    
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE FOR CLEAR BUTTON ---
if 'raw_input' not in st.session_state:
    st.session_state.raw_input = ""

def clear_text():
    st.session_state.raw_input = ""

# --- UI HEADER ---
header_col1, header_col2 = st.columns([1, 4])
with header_col1:
    st.markdown("# 🛡️")
with header_col2:
    st.title("Incident Case Generator")
    st.caption("v2.8 | Security Operations Centre | Internal Tool")

# --- INPUT SECTION ---
raw_text = st.text_area("Kibana JSON Data Source", 
                        value=st.session_state.raw_input, 
                        height=200, 
                        key="raw_input",
                        placeholder='Paste the full alert JSON here...')

# Improved Button Layout with side-by-side forcing
btn_col1, btn_col2 = st.columns(2)
with btn_col1:
    generate_ready = st.button("🚀 Generate Template", type="primary")
with btn_col2:
    st.button("🧹 Clear Input", on_click=clear_text)

# --- LOGIC HELPERS ---
def is_valid(val):
    return val and str(val).strip() not in ["", "Not Found", "N/A", "None"]

def extract_fields(raw_input):
    fields = [
        "kibana.alert.rule.name", "kibana.alert.rule.threat.tactic.name",
        "signal.rule.threat.technique.name", "kibana.alert.rule.threat.technique.id",
        "kibana.alert.rule.threat.technique.reference", "process.command_line",
        "process.parent.executable", "user.name.text", "host.name",
        "winlog.event_id", "kibana.alert.original_time", "kibana.alert.reason",
        "kibana.alert.rule.false_positives", "signal.rule.false_positives",
        "url.original", "source.enrichment.site_name_and_system",
        "destination.ip", "source.ip", "source.port", "destination.port",
        "destination.bytes", "user_agent.original", "event.action",
        "http.proxy.status_code", "hashicorp_vault.audit.request.headers.user-agent"
    ]
    res = {}
    for f in fields:
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_input, re.DOTALL)
        if match:
            val = match.group(1).replace('\\\\', '\\').replace('\\"', '"')
            res[f] = val
        else:
            res[f] = ""
    return res

# --- MAIN EXECUTION ---
if generate_ready:
    if not raw_text.strip():
        st.warning("⚠️ No data detected. Please paste your JSON content first.")
    else:
        with st.spinner('Processing...'):
            results = extract_fields(raw_text)
            
            # Start Building Markdown
            rule_title = results.get('kibana.alert.rule.name', 'Security Alert Investigation')
            md_lines = [f"# 🛡️ {rule_title}"]
            if is_valid(results.get('kibana.alert.reason')):
                md_lines.append(f"`{results['kibana.alert.reason']}`")
            
            md_lines += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
            
            # Metadata rows
            if is_valid(results.get('host.name')): md_lines.append(f"| **Host Name** | `{results['host.name']}` |")
            if is_valid(results.get('user.name.text')): md_lines.append(f"| **User Name** | `{results['user.name.text']}` |")
            if is_valid(results.get('event.action')): md_lines.append(f"| **Action** | `{results['event.action']}` |")
            
            if is_valid(results.get('source.ip')):
                src = f"`{results['source.ip']}`"
                if is_valid(results.get('source.port')): src += f":`{results['source.port']}`"
                md_lines.append(f"| **Source** | {src} |")
            if is_valid(results.get('destination.ip')):
                dst = f"`{results['destination.ip']}`"
                if is_valid(results.get('destination.port')): dst += f":`{results['destination.port']}`"
                md_lines.append(f"| **Destination** | {dst} |")
            
            if is_valid(results.get('url.original')): md_lines.append(f"| **URL** | `{results['url.original']}` |")
            
            # MITRE
            if is_valid(results.get('signal.rule.threat.technique.name')):
                tech_id = results.get('kibana.alert.rule.threat.technique.id', '')
                md_lines.append(f"| **MITRE Technique** | {results['signal.rule.threat.technique.name']} ({tech_id}) |")
            if is_valid(results.get('kibana.alert.rule.threat.tactic.name')): md_lines.append(f"| **MITRE Tactic** | {results['kibana.alert.rule.threat.tactic.name']} |")
            if is_valid(results.get('kibana.alert.rule.threat.technique.reference')): md_lines.append(f"| **MITRE Link** | [View on MITRE ATT&CK]({results['kibana.alert.rule.threat.technique.reference']}) |")
            
            if is_valid(results.get('winlog.event_id')): md_lines.append(f"| **Event ID** | `{results['winlog.event_id']}` |")
            if is_valid(results.get('kibana.alert.original_time')): md_lines.append(f"| **Alert Time** | `{results['kibana.alert.original_time']}` |")

            if is_valid(results.get('process.parent.executable')):
                md_lines += ["", "**Parent Process:**", "```powershell", results['process.parent.executable'], "```"]
            if is_valid(results.get('process.command_line')):
                md_lines += ["", "**Command Line:**", "```powershell", results['process.command_line'], "```"]

            md_lines += [
                "", "## ⚠️ Activity Type Detected", "- [ ] Malware", "- [ ] Hacking", "- [ ] Social", "- [ ] Misuse", "- [ ] Physical", "- [ ] Error",
                "", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |", "| `[HH:MM:SS]` | *Prior Activity...* |",
                f"| `{results.get('kibana.alert.original_time', 'T0')}` | **ALERT TRIGGERED** |", "| `[HH:MM:SS]` | *Follow-on Activity...* |",
                "", "## 🎯 Potential Impact", "- **Operations:** (e.g., Service downtime)", "- **Data:** (e.g., Potential for exfiltration)", "- **Reputation:** (e.g., Regulatory compliance)",
                "", "## 🔍 Triage and Analysis Steps", "1. **Consult Guide:** Refer to the official Investigation Guide.", "2. **Verify Context:** Determine if the activity matches typical user behaviour."
            ]

            triage_fp = "3. **Check against False Positives:** Verify if activity matches baseline activity."
            fps = results.get('kibana.alert.rule.false_positives') or results.get('signal.rule.false_positives')
            if is_valid(fps): triage_fp += f" Known false positives for this rule include: {fps}"
            md_lines.append(triage_fp)

            md_lines += [
                "", "## 🏁 Summary, Conclusion, and Next Steps", "**Final Determination:** (Benign / True Positive / False Positive)", 
                "", "**Summary:**", "", "", "", 
                "**Next Steps:**", "", "- [ ] Incident escalation required", "- [ ] Suppress alert / Tune rule", "- [ ] Close case"
            ]

            final_markdown = "\n".join(md_lines)

            # --- TABS FOR PREVIEW VS COPY ---
            st.divider()
            tab1, tab2 = st.tabs(["👁️ Visual Preview", "📋 Raw Template (Copy)"])

            with tab1:
                st.info("Visual representation of the final Kibana Case.")
                st.markdown(final_markdown)

            with tab2:
                copy_html = f"""
                <div style="background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <button id="copyBtn" onclick="copyToClipboard()" style="background-color: #007bff; color: white; border: none; padding: 12px 24px; border-radius: 5px; cursor: pointer; font-weight: bold; width: 100%; font-size: 16px;">📋 Click to Copy Case Template</button>
                    <textarea id="output" style="width: 100%; height: 350px; margin-top: 15px; border: 1px solid #ced4da; border-radius: 4px; padding: 12px; font-family: monospace; font-size: 13px; color: #333;">{final_markdown}</textarea>
                </div>
                <script>
                function copyToClipboard() {{
                    var copyText = document.getElementById("output");
                    var btn = document.getElementById("copyBtn");
                    copyText.select();
                    document.execCommand("copy");
                    btn.innerHTML = "✅ Copied to Clipboard!";
                    btn.style.backgroundColor = "#28a745";
                    setTimeout(function() {{ 
                        btn.innerHTML = "📋 Click to Copy Case Template"; 
                        btn.style.backgroundColor = "#007bff";
                    }}, 2000);
                }}
                </script>
                """
                html(copy_html, height=500)
