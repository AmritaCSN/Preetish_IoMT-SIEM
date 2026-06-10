import pandas as pd
import json
import os
import random
from datetime import datetime, timedelta, timezone

# ===================== CONFIG =====================
# Correct path to your CSV files (one level up from current folder)
INPUT_FOLDER = ".."                                   # Goes to ~/X-IoMTDataset/Cleaned_For_Logs/
OUTPUT_FOLDER = "logs_B_M"
TOTAL_LOGS = 80731
BENIGN_LOGS_TARGET = 60000
MALICIOUS_LOGS_TARGET = TOTAL_LOGS - BENIGN_LOGS_TARGET  # 20731
BATCH_SIZE = 2000
# =================================================

os.makedirs(OUTPUT_FOLDER, exist_ok=True)
random.seed(42)  # for reproducibility

print(f"Starting generation of {TOTAL_LOGS:,} logs ({BENIGN_LOGS_TARGET:,} Benign + {MALICIOUS_LOGS_TARGET:,} Malicious)\n")

# ===================== DEVICE POOL =====================
device_types = ["GlucoseMonitor", "HeartRateMonitor", "SpO2Monitor", "TemperatureMonitor",
                "ECGMonitor", "InfusionPump", "Ventilator", "BloodPressureMonitor"]

device_pool = []
for i in range(80):
    dev_type = random.choice(device_types)
    device_pool.append({
        "id": f"{dev_type[:3].upper()}-{random.randint(100,999)}-{i+1000}",
        "type": dev_type,
        "serial_number": f"SN-{random.randint(100000,999999)}",
        "model": "Pro-2024" if "Glucose" in dev_type or "ECG" in dev_type else "VSM-2024",
        "mac_address": f"00:1A:2B:{random.randint(10,99):02X}:{random.randint(10,99):02X}:{random.randint(10,99):02X}"
    })

# ===================== CHECK CSV FILES =====================
csv_files = sorted([f for f in os.listdir(INPUT_FOLDER) 
                    if f.startswith("NormalTrafficMQTT_part_") and f.endswith(".csv")])

if not csv_files:
    print("❌ ERROR: Could not find NormalTrafficMQTT_part_*.csv files!")
    print(f"   Searched in: {os.path.abspath(INPUT_FOLDER)}")
    print("   Please check the path and run again.")
    exit()
else:
    print(f"✅ Found {len(csv_files)} NormalTrafficMQTT CSV files.")

# ===================== MALICIOUS LOG GENERATOR =====================
malicious_categories = ["ddos", "dos", "mirai", "bruteforce", "spoofing", "recon", "web-based"]

def generate_malicious_log(ts, category):
    dev = random.choice(device_pool)
    
    if category == "ddos":
        action, log_level, message = "FLOOD", "WARNING", f"High volume MQTT flood detected from {dev['type']}"
        bytes_sent = random.randint(8500, 25000)
        signal = random.randint(-88, -75)
        trend = "extreme_rising"
    elif category == "dos":
        action, log_level, message = "DENIAL", "ERROR", f"Service denial attempt on {dev['type']} device"
        bytes_sent = random.randint(4200, 9800)
        signal = random.randint(-85, -72)
        trend = "falling"
    elif category == "mirai":
        action, log_level, message = "BOT_COMMAND", "WARNING", f"Mirai-like bot command received on {dev['type']}"
        bytes_sent = random.randint(280, 650)
        signal = random.randint(-80, -68)
        trend = "rising"
    elif category == "bruteforce":
        action, log_level, message = "BRUTE_FORCE", "ERROR", f"Multiple failed authentication attempts on {dev['type']}"
        bytes_sent = random.randint(180, 420)
        signal = random.randint(-78, -65)
        trend = "stable"
    elif category == "spoofing":
        action, log_level, message = "SPOOFED_PUBLISH", "WARNING", f"Spoofed device identity detected - {dev['type']}"
        bytes_sent = random.randint(220, 480)
        signal = random.randint(-88, -70)
        trend = "unstable"
    elif category == "recon":
        action, log_level, message = "SCAN", "INFO", f"Network reconnaissance scan targeting {dev['type']}"
        bytes_sent = random.randint(120, 280)
        signal = random.randint(-82, -58)
        trend = "stable"
    else:  # web-based
        action, log_level, message = "WEB_EXPLOIT", "ERROR", f"Web-based attack attempt on IoT management interface"
        bytes_sent = random.randint(650, 1450)
        signal = random.randint(-79, -64)
        trend = "rising"

    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "log_level": log_level,
        "log_version": "1.5",
        "facility": "hospital-ward3",
        "environment": "production",
        "region": "tn-india",
        "data_center": "chennai-dc1",
        "device": dev,
        "event": {
            "type": "ANOMALY_DETECTED",
            "category": "SecurityThreat",
            "action": action,
            "id": f"evt-mal-{ts.strftime('%Y%m%d%H%M%S%f')[:-3]}",
            "correlation_id": f"corr-mal-{ts.strftime('%Y%m%d%H%M%S%f')[:-3]}-001"
        },
        "network": {
            "protocol": "MQTT",
            "mqtt_topic": f"iot/hospital/{dev['type'].lower()}/ward3/bed{random.randint(1,20)}",
            "mqtt_qos": random.choice([0, 1, 2]),
            "src_ip": "10.42.0.139" if random.random() > 0.4 else f"10.42.{random.randint(1,255)}.{random.randint(1,254)}",
            "dst_ip": "10.42.0.1",
            "signal_strength_dbm": signal,
            "connection_type": "WiFi"
        },
        "payload": {
            "sensor_value": round(random.uniform(36.0, 39.0), 1),
            "sensor_unit": "°C",
            "trend": trend,
            "measurement_time": (ts - timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        },
        "metrics": {
            "bytes_sent": bytes_sent,
            "cpu_usage_percent": round(random.uniform(35.0, 97.0), 1),
            "battery_level_percent": random.randint(8, 68)
        },
        "status": {"outcome": "suspicious"},
        "message": message,
        "tags": ["malicious", category, "iot_attack"]
    }

# ===================== GENERATE BENIGN LOGS (using your exact logic) =====================
all_logs = []
benign_generated = 0

print("\nGenerating 60,000 benign logs from CSV files...")

for fname in csv_files:
    if benign_generated >= BENIGN_LOGS_TARGET:
        break
        
    print(f"Processing {fname} ...")
    filepath = os.path.join(INPUT_FOLDER, fname)
    
    for chunk in pd.read_csv(filepath, chunksize=BATCH_SIZE, low_memory=False):
        if benign_generated >= BENIGN_LOGS_TARGET:
            break
            
        for _, row in chunk.iterrows():
            if benign_generated >= BENIGN_LOGS_TARGET:
                break
                
            dev = random.choice(device_pool)
            ts = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 4320))
            
            topic = str(row.get('mqtt.topic', 'iot/hospital/vitals')).lower()
            
            # Exact sensor logic from your original code
            if "glucose" in topic:
                unit = "mg/dL"
                sensor_val = round(random.uniform(90, 160), 1)
            elif any(x in topic for x in ['hr', 'pulse', 'heartrate']):
                unit = "bpm"
                sensor_val = random.randint(65, 95)
            elif any(x in topic for x in ['spo2', 'oxygen']):
                unit = "%"
                sensor_val = random.randint(95, 99)
            elif any(x in topic for x in ['temp', 'temperature']):
                unit = "°C"
                sensor_val = round(random.uniform(36.5, 37.8), 1)
            else:
                unit = "units"
                sensor_val = round(random.uniform(95, 105), 1)
            
            log_entry = {
                "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "log_level": "INFO",
                "log_version": "1.5",
                "facility": "hospital-ward3",
                "environment": "production",
                "region": "tn-india",
                "data_center": "chennai-dc1",
                "device": dev,
                "event": {
                    "type": "DATA_TRANSMIT",
                    "category": "DataTransmission",
                    "action": "PUBLISH",
                    "id": f"evt-{ts.strftime('%Y%m%d%H%M%S%f')[:-3]}",
                    "correlation_id": f"corr-{ts.strftime('%Y%m%d%H%M%S%f')[:-3]}-001"
                },
                "network": {
                    "protocol": "MQTT",
                    "mqtt_topic": str(row.get('mqtt.topic', f"iot/hospital/{dev['type'].lower()}/ward3/bed{random.randint(1,20)}")),
                    "mqtt_qos": random.choice([0,1]),
                    "src_ip": "10.42.0.139",
                    "dst_ip": "10.42.0.1",
                    "signal_strength_dbm": random.randint(-68, -45),
                    "connection_type": "WiFi"
                },
                "payload": {
                    "sensor_value": sensor_val,
                    "sensor_unit": unit,
                    "trend": random.choice(["stable", "rising", "falling"]),
                    "measurement_time": (ts - timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                },
                "metrics": {
                    "bytes_sent": random.randint(180, 320),
                    "cpu_usage_percent": round(random.uniform(8.0, 28.0), 1),
                    "battery_level_percent": random.randint(72, 98)
                },
                "status": {"outcome": "success"},
                "message": f"Routine {dev['type']} reading transmitted successfully",
                "tags": ["benign", "periodic", "vitals"]
            }
            all_logs.append(log_entry)
            benign_generated += 1

print(f"→ Generated {benign_generated:,} benign logs")

# ===================== GENERATE MALICIOUS LOGS =====================
print("Generating 20,731 malicious logs...")
for _ in range(MALICIOUS_LOGS_TARGET):
    category = random.choice(malicious_categories)
    ts = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 4320))
    mal_log = generate_malicious_log(ts, category)
    all_logs.append(mal_log)

print(f"→ Generated {MALICIOUS_LOGS_TARGET:,} malicious logs")

# ===================== SHUFFLE AND SAVE =====================
print("\nShuffling all logs for random distribution...")
random.shuffle(all_logs)

print(f"Saving {len(all_logs):,} total logs into {OUTPUT_FOLDER}/ as batch_01.json ... batch_43.json")

for i in range(0, len(all_logs), BATCH_SIZE):
    batch = all_logs[i:i + BATCH_SIZE]
    batch_num = (i // BATCH_SIZE) + 1
    output_file = os.path.join(OUTPUT_FOLDER, f"batch_{batch_num:02d}.json")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(batch, f, indent=2)
    
    print(f"   → Saved {len(batch):,} logs → {output_file}")

print("\n" + "="*90)
print(f"✅ SUCCESS! Generated {len(all_logs):,} mixed logs")
print(f"   ├── Benign logs    : {benign_generated:,}")
print(f"   └── Malicious logs : {MALICIOUS_LOGS_TARGET:,}")
print(f"\nSaved in folder: {OUTPUT_FOLDER}/")
print("Files named: batch_01.json to batch_43.json")
print("="*90)
