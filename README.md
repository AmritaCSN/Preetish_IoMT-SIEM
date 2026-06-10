# Insider Log Poisoning Attack and AI-Enhanced Defenses in IoMT-SIEM Pipelines

This repository contains the implementation, scripts, and documentation for the major project **"Insider Log Poisoning Attack on IoMT–SIEM Pipeline via Compromised Aggregation Database"**. It demonstrates a realistic insider threat scenario in an **Internet of Medical Things (IoMT)** environment using the **Xiomt2024** dataset.

## Overview of the Project

The project simulates a complete IoMT-SIEM pipeline where an insider with access to the aggregation database (MinIO) performs **log poisoning** using **7 evasion techniques**. 

Malicious logs (e.g., DDoS, spoofing, etc.) are transformed to appear benign while preserving their malicious nature. These poisoned logs bypass Wazuh (SIEM) detection and reach the AI server. A validation script identifies the bypassed attacks, followed by a **RAG + LLM** pipeline that reclassifies the threats, generates human-readable explanations, and provides risk assessment & remediation steps for the SOC team.

**Key Highlights:**
- Clean detection of malicious IoMT activity logs
- Poisoning using 7 sophisticated evasion techniques
- Bypass of Wazuh SIEM rules
- Post-attack validation and detection recovery using RAG + LLM
- Human-readable remediation for security operations

## Attack Techniques Used

| Technique                  | Description |
|---------------------------|-----------|
| **Label Flipping**        | Change attack labels (e.g., "DDoS" → "Benign") |
| **Timestamp Jitter**      | Add random ±15s delays to timestamps |
| **IP Substitution**       | Replace external attack IPs with internal benign IPs |
| **Domain Masquerading**   | Swap malicious domains with trusted ones |
| **Size & Duration Shaping**| Normalize packet sizes (80-2800 bytes) and durations |
| **Benign Injection**      | Inject fake protocols and user agents |
| **Field Removal**         | Remove obvious attack-specific fields |

## Architecture

![Project Architecture](archi.jpg)

*(Replace with your actual architecture diagram)*

## 📁 Project Structure

| File/Folder              | Description |
|--------------------------|-----------|
| `cic_to_logs.py` / `xiomt_to_logs.py` | Converts Xiomt2024 dataset into structured JSON logs |
| `poisoned_script.py`     | Applies 7 evasion techniques and generates `benign.json` (poisoned + original benign logs) |
| `validation_script.py`   | Extracts logs from MinIO & Wazuh, validates bypassed malicious logs |
| `minio-to-wazuh.conf`    | Logstash / Filebeat configuration for ingestion |
| `rag_pipeline.py`        | RAG orchestration for retrieval and validation data |
| `llm_remediation.py`     | LLM-based reclassification, explanation & remediation generation |
| `archi.jpg`              | System architecture diagram |
| `Block_diagram.png`      | Block diagram of the pipeline |
| `README.md`              | This file |

## 🔧 Tools & Technologies Used

| Category           | Tool/Technology              | Description |
|--------------------|------------------------------|-----------|
| **Dataset**        | Xiomt2024                    | IoMT activity logs with benign and malicious instances |
| **Storage**        | MinIO                        | Aggregation database (compromised by insider) |
| **SIEM**           | Wazuh                        | Security monitoring and log analysis |
| **Orchestration**  | Logstash / Filebeat          | Log shipping and processing |
| **AI Layer**       | RAG + LLM                    | Threat reclassification and remediation |
| **Scripting**      | Python 3                     | Log poisoning, validation, and LLM pipeline |
| **Environment**    | WSL / Linux                  | Development and testing environment |
| **Visualization**  | Kibana / Wazuh Dashboard     | Detection metrics and poisoning impact |

## Workflow

1. **Data Ingestion** — Xiomt2024 logs → MinIO (Aggregation DB)
2. **Insider Poisoning** — Malicious logs transformed using 7 techniques
3. **SIEM Processing** — Poisoned logs sent to Wazuh (most bypass detection)
4. **Validation** — Python script compares MinIO vs Wazuh logs to detect bypasses
5. **RAG + LLM Recovery**
   - RAG retrieves validation differences
   - LLM reclassifies threats, explains poisoning, and suggests mitigations

## Key Outcomes

- Demonstrates effectiveness of log poisoning against SIEM systems
- Shows how RAG + LLM can recover and explain hidden threats
- Provides actionable remediation for SOC teams
- Highlights insider threat risks in IoMT healthcare environments

## Setup & Usage

2. First Convert your batch files into proper JSON Lines format (.jsonl).
(a) Create a directory for the flattened logs
```bash
mkdir -p ../flattened_jsonl
```
(b) Convert ALL batch files to JSON Lines format (one log per line)
```bash
for file in batch_*.json; do   
 echo "Converting $file ..."    
jq -c '.[]' "$file" > "../flattened_jsonl/${file%.json}.jsonl"
Done
echo "Conversion completed!"
ls -lh ../flattened_jsonl/
```

4. Configure Wazuh to Read Them, go to cd /var/ossec/etc/rules/
   ```bash
   cat > local_rules.xml << 'EOF'
   <!-- X-IoMT Dataset - IoT Medical Device Attack Detection -->
   <group name="local,iot,iomt">
   <!-- Base malicious detection -->
   <rule id="100001" level="10">
    <decoded_as>json</decoded_as>
    <field name="tags" type="pcre2">malicious</field>
    <description>IoMT: Malicious activity detected - $(event.action) on $(device.type)</description>
    <group>iot_attack,malicious,</group>
   </rule>
   <!-- High severity attacks (Mirai, DDoS, Bot commands, etc.) -->
   <rule id="100002" level="15">
    <if_sid>100001</if_sid>
    <field name="tags" type="pcre2">mirai|bot_command|ddos|dos</field>
    <description>IoMT CRITICAL: $(message) | Device: $(device.type) | SrcIP: $(network.src_ip)</description>
    <group>iot_attack,mirai,ddos,critical,</group>
   </rule>
   <!-- Medium severity attacks -->
   <rule id="100003" level="12">
    <if_sid>100001</if_sid>
    <field name="tags" type="pcre2">bruteforce|spoofing|recon|web-based</field>
    <description>IoMT Suspicious: $(event.action) on $(device.type) - $(message)</description>
    </rule>
   </group>
   EOF
   ```







To remove all logs from wazuh
- Open your Wazuh Dashboard.
- From the left menu, go to Indexer management → Dev Tools (or search for "Dev Tools").
- In the left panel (console), paste the following command and click the green play/run button: DELETE /wazuh-alerts-*
