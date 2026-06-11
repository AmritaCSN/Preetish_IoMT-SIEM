import json
import csv
from datetime import datetime

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
OUTPUT_CSV = "wazuh_iomt_detection_report.csv"

KEYWORDS = ["poison", "Poisoned", "script", "suspicious", "Mirai", "BRUTE_FORCE",
            "CRITICAL", "MQTT flood", "bot command"]
RULE_IDS = ["100002", "100003"]
MIN_LEVEL = 7
AGENT_NAME = None

def extract_detection_report():
    alerts = []
   
    print(f"Reading alerts from: {ALERTS_FILE}\n")
   
    with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
               
                rule_id = str(alert.get('rule', {}).get('id', ''))
                description = alert.get('rule', {}).get('description', '').lower()
                level = alert.get('rule', {}).get('level', 0)
                agent = alert.get('agent', {}).get('name', '')
               
                if level < MIN_LEVEL:
                    continue
                if RULE_IDS and rule_id not in RULE_IDS:
                    continue
                if AGENT_NAME and AGENT_NAME.lower() not in agent.lower():
                    continue
                if KEYWORDS and not any(kw.lower() in description for kw in KEYWORDS):
                    continue
                   
                alerts.append(alert)
               
            except:
                continue
   
    print(f"Found {len(alerts)} matching alerts.\n")
   
    if alerts:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "rule_id", "rule_description", "rule_level",
                "agent_name", "agent_ip", "full_log", "data"
            ])
           
            for alert in sorted(alerts, key=lambda x: x.get('@timestamp', ''), reverse=True):
                src = alert
                rule = src.get('rule', {})
                agent = src.get('agent', {})
                data = src.get('data', {})
               
                writer.writerow([
                    src.get('@timestamp'),
                    rule.get('id'),
                    rule.get('description'),
                    rule.get('level'),
                    agent.get('name'),
                    agent.get('ip'),
                    src.get('full_log', '')[:600],
                    str(data)[:400]
                ])
       
        print(f"Report successfully saved as: {OUTPUT_CSV}")
        print(f"Location: {OUTPUT_CSV}")
    else:
        print("No alerts matched. Try loosening the filters.")

if __name__ == "__main__":
    extract_detection_report()
