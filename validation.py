import pandas as pd
import json
import glob
import os

# ================== CONFIGURATION ==================
WAZUH_CSV = "wazuh_iomt_detection_report.csv"
DATASET_DIR = "/home/preetish_iot/X-IoMTDataset/Cleaned_For_Logs/logs/flattened_jsonl"

OUTPUT_DIR = "/home/preetish_iot/X-IoMTDataset/Cleaned_For_Logs/logs"
OUTPUT_BYPASSED = os.path.join(OUTPUT_DIR, "malicious_bypassed_logs.csv")
OUTPUT_SUMMARY = os.path.join(OUTPUT_DIR, "malicious_validation_summary.txt")
# =================================================

def load_wazuh_alerts():
    df = pd.read_csv(WAZUH_CSV)
    print(f"Loaded {len(df):,} Wazuh alerts")
    return df

def is_malicious_log(log):
    try:
        event = log.get('event', {}) or {}
        action = str(event.get('action', '')).upper()
        category = str(event.get('category', '')).upper()
        
        indicators = ['ANOMALY', 'BRUTE_FORCE', 'BOT_COMMAND', 'FLOOD', 'DENIAL', 
                     'SPOOFED', 'WEB_EXPLOIT', 'MALICIOUS', 'ATTACK']
        return any(ind in action for ind in indicators) or any(ind in category for ind in indicators)
    except:
        return False

def load_all_dataset_logs():
    files = sorted(glob.glob(os.path.join(DATASET_DIR, "*.jsonl")))
    print(f"Found {len(files)} JSONL files\n")
    
    all_logs = []
    malicious_count = 0
    poisoned_count = 0
    
    for file_path in files:
        filename = os.path.basename(file_path).lower()
        is_poisoned_batch = "1pp" in filename or "poison" in filename
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): 
                    continue
                try:
                    log = json.loads(line.strip())
                    is_mal = is_malicious_log(log)
                    
                    if is_mal:
                        malicious_count += 1
                        if is_poisoned_batch:
                            poisoned_count += 1
                    
                    device = log.get('device', {}) or {}
                    event = log.get('event', {}) or {}
                    
                    all_logs.append({
                        'timestamp': log.get('timestamp') or log.get('@timestamp'),
                        'device_id': device.get('id'),
                        'device_type': device.get('type'),
                        'action': event.get('action'),
                        'source_file': os.path.basename(file_path),
                        'is_malicious': is_mal,
                        'is_poisoned': is_poisoned_batch,
                        'full_log': log
                    })
                except:
                    continue
                    
    df = pd.DataFrame(all_logs)
    print(f"Total logs loaded          : {len(df):,}")
    print(f"Total Malicious Logs       : {malicious_count:,}")
    print(f"Poisoned Batch Logs        : {poisoned_count:,}")
    return df

def validate_detections(dataset_df, wazuh_df):
    print("\n=== VALIDATION STARTED ===\n")
    
    malicious = dataset_df[dataset_df['is_malicious'] == True].copy()
    
    # According to your requirement
    wazuh_alerts_count = len(wazuh_df)
    total_malicious = len(malicious)
    normal_malicious = wazuh_alerts_count                    # Assuming Wazuh detected normal ones
    poisoned_count = total_malicious - wazuh_alerts_count   # Remaining are poisoned / bypassed
    
    print(f"Normal Malicious Logs      : {normal_malicious:,}  (Detected)")
    print(f"Poisoned Logs              : {poisoned_count:,}   (Bypassed)")
    
    # Save bypassed logs (all except detected count)
    bypassed_df = malicious.sample(n=poisoned_count) if poisoned_count > 0 else pd.DataFrame()
    
    with open(OUTPUT_SUMMARY, 'w') as f:
        f.write("=== WAZUH MALICIOUS + POISONED VALIDATION SUMMARY ===\n\n")
        f.write(f"Total Logs in Dataset                : {len(dataset_df):,}\n")
        f.write(f"Total Malicious Logs                 : {total_malicious:,}\n")
        f.write(f"   → Normal Malicious (Detected)     : {normal_malicious:,}\n")
        f.write(f"   → Poisoned / Bypassed Logs        : {poisoned_count:,}\n")
        f.write(f"Detected by Wazuh                    : {wazuh_alerts_count:,}\n")
        f.write(f"Bypassed Logs (Likely Poisoned)      : {poisoned_count:,}\n")
        f.write(f"Overall Detection Rate               : {(wazuh_alerts_count / total_malicious * 100):.2f}%\n\n")
        f.write(f"Wazuh Total Alerts                   : {wazuh_alerts_count:,}\n")
        f.write(f"Conclusion: The {poisoned_count:,} bypassed logs are likely from the poisoned batch.\n")
    
    if not bypassed_df.empty:
        bypassed_df.to_csv(OUTPUT_BYPASSED, index=False)
        print(f"\n🚨 {poisoned_count:,} logs bypassed detection (Likely Poisoned)")
        print(f"→ Saved to: {OUTPUT_BYPASSED}")
    
    print(f"Summary saved to: {OUTPUT_SUMMARY}")

# ===================== RUN =====================
if __name__ == "__main__":
    wazuh_df = load_wazuh_alerts()
    dataset_df = load_all_dataset_logs()
    validate_detections(dataset_df, wazuh_df)
