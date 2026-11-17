from scapy.all import sniff,IP,TCP,UDP,ICMP
from datetime import datetime
import os

LOG_FILE="logs/capture_log.txt"
PACKET_COUNT=20
stats={"TCP":0,"UDP":0,"ICMP":0,"Other":0,"total_bytes":0}

def get_filter(protocol):
    return {"TCP":"tcp","UDP":"udp","ICMP":"icmp"}.get(protocol)

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    ip=packet[IP]
    size=len(packet)

    if packet.haslayer(TCP):
        protocol="TCP"
        source=f"{ip.src}:{packet[TCP].sport}"
        destination=f"{ip.dst}:{packet[TCP].dport}"
        flags=packet[TCP].flags
    elif packet.haslayer(UDP):
        protocol="UDP"
        source=f"{ip.src}:{packet[UDP].sport}"
        destination=f"{ip.dst}:{packet[UDP].dport}"
        flags="-"
    elif packet.haslayer(ICMP):
        protocol="ICMP"
        source=ip.src
        destination=ip.dst
        flags="-"
    else:
        protocol="Other"
        source=ip.src
        destination=ip.dst
        flags="-"

    stats[protocol]+=1
    stats["total_bytes"]+=size

    entry=f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {protocol} | {source} --> {destination} | Size: {size} bytes | Flags: {flags}"
    print(entry)

    with open(LOG_FILE,"a",encoding="utf-8") as file:
        file.write(entry+"\n")

def show_summary():
    total=sum(stats[p] for p in ["TCP","UDP","ICMP","Other"])
    summary=f"""
CAPTURE SUMMARY
Session End: {datetime.now():%Y-%m-%d %H:%M:%S}
Filter: {selected_protocol}
TCP: {stats["TCP"]}
UDP: {stats["UDP"]}
ICMP: {stats["ICMP"]}
Other: {stats["Other"]}
Total Packets: {total}
Total Data: {stats["total_bytes"]} bytes
"""

    print(summary)

    with open(LOG_FILE,"a",encoding="utf-8") as file:
        file.write(summary)

os.makedirs("logs",exist_ok=True)

print("1. ALL\n2. TCP\n3. UDP\n4. ICMP")
choice=input("Enter choice (1-4): ").strip()
selected_protocol={"1":"ALL","2":"TCP","3":"UDP","4":"ICMP"}.get(choice,"ALL")
capture_filter=get_filter(selected_protocol)

with open(LOG_FILE,"a",encoding="utf-8") as file:
    file.write(f"\nNEW CAPTURE SESSION\nFilter: {selected_protocol}\n")

try:
    sniff(filter=capture_filter,prn=analyze_packet,count=PACKET_COUNT,store=False)
except KeyboardInterrupt:
    print("Capture stopped.")
except Exception as error:
    print(f"Capture error: {error}")
finally:
    show_summary()
    print(f"Log file: {LOG_FILE}")