import os
import time
import threading
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

# --- CONFIGURATION ---
LOG_FILE = "/var/log/suricata/fast.log"  # Change if needed
SIMULATED_BLOCK_LIST = set()
THREAT_LOG_FILE = "detected_threats.log"
VISUALIZATION_INTERVAL = 60  # seconds

# --- FUNCTION: Monitor Alerts ---
def monitor_suricata_alerts():
    print("🔍 Starting real-time alert monitoring...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # Move to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            process_alert(line.strip())

# --- FUNCTION: Process and Respond ---
def process_alert(line):
    print(f"⚠️ Alert: {line}")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Log to file
    with open(THREAT_LOG_FILE, "a") as log:
        log.write(f"{timestamp} | {line}\n")

    # Extract basic IP (mocked example for demo purposes)
    if "->" in line:
        try:
            parts = line.split("->")
            src = parts[0].split()[-1]
            dst = parts[1].split()[0]
            print(f"👁️ Source: {src} | Destination: {dst}")

            # Simulated Response
            if src not in SIMULATED_BLOCK_LIST:
                SIMULATED_BLOCK_LIST.add(src)
                print(f"⛔ Simulated: Blocking {src} (added to blacklist)")
        except Exception as e:
            print(f"Error parsing IPs: {e}")

# --- FUNCTION: Visualization of Alerts ---
def visualize_threats():
    while True:
        time.sleep(VISUALIZATION_INTERVAL)
        try:
            times = []
            with open(THREAT_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        ts = line.split("|")[0].strip()
                        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                        times.append(dt)
                    except:
                        continue

            if not times:
                print("📭 No data to visualize.")
                continue

            # Count per minute
            counter = defaultdict(int)
            for t in times:
                minute = t.strftime("%Y-%m-%d %H:%M")
                counter[minute] += 1

            sorted_keys = sorted(counter.keys())
            values = [counter[k] for k in sorted_keys]

            plt.figure(figsize=(10, 5))
            plt.plot(sorted_keys, values, marker='o')
            plt.xticks(rotation=45, ha='right')
            plt.title("📊 Alerts Over Time")
            plt.xlabel("Time")
            plt.ylabel("Number of Alerts")
            plt.tight_layout()
            plt.grid()
            plt.show()
        except Exception as e:
            print(f"Visualization error: {e}")

# --- MAIN ---
if __name__ == "__main__":
    print("🚨 Python Network Intrusion Detection System (NIDS) - Running")

    t1 = threading.Thread(target=monitor_suricata_alerts, daemon=True)
    t2 = threading.Thread(target=visualize_threats, daemon=True)

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopped NIDS. Exiting.")
