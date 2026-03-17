import streamlit as st
import re
from streamlit.components.v1 import html

# 1. PAGE CONFIGURATION
st.set_page_config(page_title="Kibana Alert Parser", page_icon="🛡️", layout="wide")

# --- UI HEADER ---
st.title("🛡️ Kibana Alert Parser")
st.markdown("Paste the raw JSON from Kibana below to generate your investigation template.")

# --- INPUT SECTION ---
# Using a text area for large JSON blobs
raw_text = st.text_area("Paste Data Here", height=250, placeholder='{"kibana.alert.rule.name": ...}')

# --- EXTRACTION & LOGIC HELPERS ---
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
        # Regex handles standard strings and array-wrapped fields
        pattern = rf'"{re.escape(f)}":\s*(?:\[\s*)?"(.*?)"(?=\s*\]|\s*,)'
        match = re.search(pattern, raw_input, re.DOTALL)
        if match:
            # Clean up escape characters (e.g., \" or \\)
            val = match.group(1).replace('\\\\', '\\').replace('\\"', '"')
            res[f] = val
        else:
            res[f] = ""
    return res

# --- MAIN EXECUTION ---
if st.button("Generate Template", type="primary"):
    if not raw_text.strip():
        st.error("❌ Please paste your Kibana data into the box above.")
    else:
        results = extract_fields(raw_text)
        
        # Build Title and Reason
        rule_title = results.get('kibana.alert.rule.name', 'Security Alert Investigation')
        md_lines = [f"# 🛡️ {rule_title}"]
        if is_valid(results.get('kibana.alert.reason')):
            md_lines.append(f"`{results['kibana.alert.reason']}`")
        
        md_lines += ["", "## 📋 Key Information", "| Field | Value |", "| :--- | :--- |"]
        
        # Populate Metadata Table
        if is_valid(results.get('host.name')): 
            md_lines.append(f"| **Host Name** | `{results['host.name']}` |")
        if is_valid(results.get('user.name.text')): 
            md_lines.append(f"| **User Name** | `{results['user.name.text']}` |")
        if is_valid(results.get('event.action')): 
            md_lines.append(f"| **Action** | `{results['event.action']}` |")

        # Network Logic
        if is_valid(results.get('source.ip')):
            src = f"`{results['source.ip']}`"
            if is_valid(results.get('source.port')): src += f":`{results['source.port']}`"
            md_lines.append(f"| **Source** | {src} |")
        if is_valid(results.get('destination.ip')):
            dst = f"`{results['destination.ip']}`"
            if is_valid(results.get('destination.port')): dst += f":`{results['destination.port']}`"
            md_lines.append(f"| **Destination** | {dst} |")
        if is_valid(results.get('destination.bytes')): 
            md_lines.append(f"| **Bytes Sent** | `{results['destination.bytes']}` |")

        # Web/Proxy/Enrichment
        if is_valid(results.get('url.original')): 
            md_lines.append(f"| **URL** | `{results['url.original']}` |")
        if is_valid(results.get('http.proxy.status_code')): 
            md_lines.append(f"| **Proxy Status** | `{results['http.proxy.status_code']}` |")
        if is_valid(results.get('user_agent.original')): 
            md_lines.append(f"| **User Agent** | `{results['user_agent.original']}` |")
        if is_valid(results.get('hashicorp_vault.audit.request.headers.user-agent')): 
            md_lines.append(f"| **Vault UA** | `{results['hashicorp_vault.audit.request.headers.user-agent']}` |")
        if is_valid(results.get('source.enrichment.site_name_and_system')): 
            md_lines.append(f"| **Site/System** | `{results['source.enrichment.site_name_and_system']}` |")

        # MITRE ATT&CK
        if is_valid(results.get('signal.rule.threat.technique.name')):
            tech_id = results.get('kibana.alert.rule.threat.technique.id', '')
            md_lines.append(f"| **MITRE Technique** | {results['signal.rule.threat.technique.name']} ({tech_id}) |")
        if is_valid(results.get('kibana.alert.rule.threat.tactic.name')): 
            md_lines.append(f"| **MITRE Tactic** | {results['kibana.alert.rule.threat.tactic.name']} |")
        if is_valid(results.get('kibana.alert.rule.threat.technique.reference')): 
            md_lines.append(f"| **MITRE Link** | [View on MITRE ATT&CK]({results['kibana.alert.rule.threat.technique.reference']}) |")

        if is_valid(results.get('winlog.event_id')): 
            md_lines.append(f"| **Event ID** | `{results['winlog.event_id']}` |")
        if is_valid(results.get('kibana.alert.original_time')): 
            md_lines.append(f"| **Alert Time** | `{results['kibana.alert.original_time']}` |")

        # Execution Details as Code Blocks
        if is_valid(results.get('process.parent.executable')):
            md_lines += ["", "**Parent Process:**", "```powershell", f"{results['process.parent.executable']}", "```"]
        if is_valid(results.get('process.command_line')):
            md_lines += ["", "**Command Line:**", "```powershell", f"{results['process.command_line']}", "```"]

        # Timeline and Impact Sections
        md_lines += [
            "", "## ⚠️ Activity Type Detected", "- [ ] Malware", "- [ ] Hacking", "- [ ] Social", "- [ ] Misuse", "- [ ] Physical", "- [ ] Error",
            "", "## 📅 Timeline of Events", "| Timestamp | Event Description |", "| :--- | :--- |", "| `[HH:MM:SS]` | *Prior Activity...* |",
            f"| `{results.get('kibana.alert.original_time', 'T0')}` | **ALERT TRIGGERED** |", "| `[HH:MM:SS]` | *Follow-on Activity...* |",
            "", "## 🎯 Potential Impact", "Evaluate the potential damage or risk to operations, data, and reputation:", 
            "- **Operations:** (e.g., Service downtime, system lockdown)", "- **Data:** (e.g., Potential for exfiltration, unauthorized modification)", "- **Reputation:** (e.g., Impact on customer trust, regulatory compliance)",
            "", "## 🔍 Triage and Analysis Steps", "1. **Consult Guide:** Refer to the official Investigation Guide.", "2. **Verify Context:** Determine if the activity matches known administrative patterns or typical user behaviour."
        ]

        # Triage Step 3 for False Positives
        triage_fp = "3. **Check against False Positives:** Verify if activity matches baseline activity."
        fps = results.get('kibana.alert.rule.false_positives') or results.get('signal.rule.false_positives')
        if is_valid(fps): triage_fp += f" Known false positives for this rule include: {fps}"
        md_lines.append(triage_fp)

        # Summary Section
        md_lines += [
            "", "## 🏁 Summary, Conclusion, and Next Steps", "**Final Determination:** (Benign / True Positive / False Positive)", "", "**Summary:**", "", "", "", 
            "**Next Steps:**", "", "- [ ] Incident escalation required", "- [ ] Suppress alert / Tune rule", "- [ ] Close case"
        ]

        final_markdown = "\n".join(md_lines)

        # --- OUTPUT AREA ---
        st.divider()
        st.subheader("📋 Generated Case Template")
        
        # Displaying the "Copy to Clipboard" HTML Widget
        copy_html = f"""
        <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px;">
            <button id="copyBtn" onclick="copyToClipboard()" style="background-color: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; width: 100%;">📋 Copy Template</button>
            <textarea id="output" style="width: 100%; height: 400px; margin-top: 10px; border: 1px solid #ccc; padding: 10px; font-family: monospace;">{final_markdown}</textarea>
        </div>
        <script>
        function copyToClipboard() {{
            var copyText = document.getElementById("output");
            var btn = document.getElementById("copyBtn");
            copyText.select();
            document.execCommand("copy");
            btn.innerHTML = "✅ Copied!";
            btn.style.backgroundColor = "#28a745";
            setTimeout(function() {{ 
                btn.innerHTML = "📋 Copy Template"; 
                btn.style.backgroundColor = "#007bff";
            }}, 2000);
        }}
        </script>
        """
        html(copy_html, height=500)
