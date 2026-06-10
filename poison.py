import json
import random
import datetime
from pathlib import Path
from typing import List, Dict, Any
import io
import sys

# ========================= CONFIG =========================
LOCAL_INPUT_DIR = Path("/home/preetish_iot/X-IoMTDataset/Cleaned_For_Logs/logs/flattened_jsonl")
OUTPUT_OBJECT_NAME = "sanitized/sanitized_malicious_20k.jsonl"
MINIO_BUCKET = "raw-immutable"   # for upload only

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# ========================= BENIGN POOLS =========================
BENIGN_IPS = [f"10.42.0.{i}" for i in range(50, 200)] + \
             [f"192.168.10.{i}" for i in range(10, 100)] + \
             [f"172.16.{i}.{j}" for i in range(1, 15) for j in range(1, 200)]

BENIGN_DOMAINS = ["iot-hospital.local", "med-dev.internal", "telemetry.hospital.net",
                  "device-hub.local", "vitals-monitor.internal", "hospital-hub.local"]

BENIGN_PROTOCOLS = ["MQTT", "CoAP", "HTTP", "AMQP"]
BENIGN_USER_AGENTS = ["IoMT-Agent/2.1", "SensorHub-v1.4", "MQTTClient-Python/3.10",
                     "IoT-Device/1.0", "EdgeGateway/3.2"]

BAD_KEYWORDS = ["malicious", "AttackType", "attack_type", "ddos", "DDoS", "mirai",
                "bot_command", "bruteforce", "spoofing", "recon", "web-based",
                "threat", "malware", "exploit", "shell", "cmd", "c2", "payload", "dos"]

# Try to import minio for upload
try:
    from minio import Minio
    MINIO_AVAILABLE = True
except ImportError:
    MINIO_AVAILABLE = False
    print("⚠️  minio not installed. Will save locally only.")

if MINIO_AVAILABLE:
    client = Minio("iotserver1r760:9000", "minioadmin", "minioadmin", secure=False)

def load_all_logs_local() -> List[Dict]:
    """Load logs from local directory"""
    all_logs: List[Dict] = []
    jsonl_files = sorted(LOCAL_INPUT_DIR.glob("batch_*.jsonl"))
    
    print(f"Found {len(jsonl_files)} batch files locally.")
    
    for file_path in jsonl_files:
        print(f"  Loading: {file_path.name}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        log = json.loads(line_str)
                        all_logs.append(log)
                    except:
                        continue
        if len(all_logs) % 20000 == 0 and len(all_logs) > 0:
            print(f"   Loaded {len(all_logs):,} logs so far...")
    
    print(f"✅ Total logs loaded: {len(all_logs):,}")
    return all_logs


def is_malicious(log: Dict) -> bool:
    tags = log.get("tags")
    if not tags:
        return False
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, list):
        return False
    tag_str = " ".join(str(t).lower() for t in tags)
    return any(bad in tag_str for bad in BAD_KEYWORDS)


def clean_tags(tags):
    if not isinstance(tags, list):
        return ["benign", "normal", "iot", "periodic", "vitals"]
    cleaned = [t for t in tags if not any(bad in str(t).lower() for bad in BAD_KEYWORDS)]
    if len(cleaned) < 2:
        cleaned = ["benign", "normal", "iot", "periodic", "vitals"]
    return cleaned


def sanitize_recursive(obj: Any) -> Any:
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if any(bad.lower() in k.lower() for bad in BAD_KEYWORDS):
                del obj[k]
                continue
            obj[k] = sanitize_recursive(obj[k])
        return obj
    elif isinstance(obj, list):
        return [sanitize_recursive(item) for item in obj]
    elif isinstance(obj, str):
        for bad in BAD_KEYWORDS:
            if bad.lower() in obj.lower():
                obj = obj.replace(bad, "normal").replace(bad.upper(), "normal")
        return obj
    return obj


def apply_7_evasion_techniques(log: Dict) -> Dict:
    poisoned = json.loads(json.dumps(log))

    # 1. Label Flipping
    if "tags" in poisoned:
        poisoned["tags"] = clean_tags(poisoned["tags"])
    else:
        poisoned["tags"] = ["benign", "normal", "iot", "periodic", "vitals"]

    # 2. Timestamp Jitter
    now = datetime.datetime.utcnow()
    if "timestamp" in poisoned:
        try:
            ts_str = str(poisoned["timestamp"]).replace("Z", "+00:00")
            ts = datetime.datetime.fromisoformat(ts_str)
            jitter = random.randint(-15, 15)
            poisoned["timestamp"] = (ts + datetime.timedelta(seconds=jitter)).isoformat() + "Z"
        except:
            poisoned["timestamp"] = now.isoformat() + "Z"

    # 3. IP Substitution
    def replace_ips(obj):
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, str) and ('.' in v or ':' in v) and any(c.isdigit() for c in v[:40]):
                    if random.random() < 0.88:
                        obj[k] = random.choice(BENIGN_IPS)
                elif isinstance(v, (dict, list)):
                    replace_ips(v)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                replace_ips(obj[i])
    replace_ips(poisoned)

    # 4-7. Other techniques (same as before)
    domain_fields = ["domain", "host", "hostname", "mqtt_topic", "url", "endpoint"]
    for field in domain_fields:
        if field in poisoned and random.random() < 0.85:
            poisoned[field] = random.choice(BENIGN_DOMAINS)
        if isinstance(poisoned.get("network"), dict) and field in poisoned["network"]:
            if random.random() < 0.85:
                poisoned["network"][field] = random.choice(BENIGN_DOMAINS)

    for key in ["bytes", "bytes_sent", "packet_size", "size", "length", "payload_size"]:
        if key in poisoned:
            poisoned[key] = random.randint(80, 2800)
        if isinstance(poisoned.get("metrics"), dict) and key in poisoned["metrics"]:
            poisoned["metrics"][key] = random.randint(80, 2800)

    if "duration" in poisoned:
        poisoned["duration"] = round(random.uniform(0.3, 4.8), 2)

    poisoned.setdefault("protocol", random.choice(BENIGN_PROTOCOLS))
    poisoned.setdefault("user_agent", random.choice(BENIGN_USER_AGENTS))

    if isinstance(poisoned.get("network"), dict):
        poisoned["network"]["protocol"] = random.choice(BENIGN_PROTOCOLS)

    if isinstance(poisoned.get("status"), dict):
        poisoned["status"]["outcome"] = "success"
        poisoned["status"]["result"] = "ok"
    else:
        poisoned["status"] = {"outcome": "success", "result": "ok"}

    poisoned = sanitize_recursive(poisoned)

    if "severity" in poisoned:
        poisoned["severity"] = "low"

    return poisoned


def main():
    print("🚀 Starting Sanitization of Malicious Logs...\n")
    
    all_logs = load_all_logs_local()
    
    malicious_logs = [log for log in all_logs if is_malicious(log)]
    print(f"Found {len(malicious_logs):,} malicious logs to sanitize.")
    
    if len(malicious_logs) == 0:
        print("❌ No malicious logs found! Check your BAD_KEYWORDS.")
        return

    sanitized_logs = []
    for i, log in enumerate(malicious_logs):
        sanitized = apply_7_evasion_techniques(log)
        sanitized_logs.append(sanitized)
        
        if (i + 1) % 4000 == 0:
            print(f"→ Sanitized {i+1:,}/{len(malicious_logs):,} malicious logs")

    # Save output
    buffer = io.StringIO()
    for log in sanitized_logs:
        buffer.write(json.dumps(log, ensure_ascii=False) + '\n')

    output_path = Path("batch_1p.jsonl")
    output_path.write_text(buffer.getvalue(), encoding='utf-8')
    print(f"\n✅ SUCCESS! Saved {len(sanitized_logs):,} sanitized logs to:")
    print(f"   {output_path.absolute()}")

    print("\n" + "="*80)
    print("NEXT STEP: Ingest this file into Wazuh along with your 60k benign logs.")
    print("="*80)


if __name__ == "__main__":
    main()
