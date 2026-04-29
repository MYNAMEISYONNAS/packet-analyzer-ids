#!/usr/bin/env python 

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
ALERT_FILE = OUTPUT_DIR / "alerts.json"

syn_tracker = defaultdict(set)
alerts = []


def save_alert(alert):
    OUTPUT_DIR.mkdir(exist_ok=True)
    alerts.append(alert)

    with open(ALERT_FILE, "w") as file:
        json.dump(alerts, file, indent=4)

    print(f"[SAVED] Alert written to: {ALERT_FILE}")


def create_alert(title, severity, details):
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "title": title,
        "severity": severity,
        "details": details
    }


def analyze_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

        if tcp_flags == "S":
            syn_tracker[src_ip].add(dst_port)

            if len(syn_tracker[src_ip]) >= 10:
                alert = create_alert(
                    "Possible SYN Scan Detected",
                    "HIGH",
                    {
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "ports_targeted": sorted(syn_tracker[src_ip])
                    }
                )

                print("\n[ALERT] Possible SYN Scan Detected!")
                print(alert)
                save_alert(alert)

    if UDP in packet and DNS in packet and DNSQR in packet:
        domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")

        print("\n[DNS QUERY]")
        print(f"Source IP: {src_ip}")
        print(f"Destination DNS Server: {dst_ip}")
        print(f"Domain Queried: {domain}")

        if domain.endswith(".ru") or domain.endswith(".xyz"):
            alert = create_alert(
                "Suspicious DNS TLD Detected",
                "MEDIUM",
                {
                    "source_ip": src_ip,
                    "destination_dns_server": dst_ip,
                    "domain": domain
                }
            )

            print("[ALERT] Suspicious DNS TLD detected")
            print(alert)
            save_alert(alert)


def main():
    print("Starting packet analyzer with JSON alert logging...")
    print(f"Alerts will be saved to: {ALERT_FILE}")
    print("Press CTRL + C to stop.\n")

    sniff(prn=analyze_packet, store=False)


if __name__ == "__main__":
    main()
