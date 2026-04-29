#!/usr/bin/env python3

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

from rule_loader import load_rules


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
ALERT_FILE = OUTPUT_DIR / "alerts.json"
RULES_DIR = BASE_DIR / "rules"

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


def get_rules_by_type(rules, rule_type):
    return [rule for rule in rules if rule.get("type") == rule_type]


def check_dns_rules(domain, src_ip, dst_ip, rules):
    dns_rules = get_rules_by_type(rules, "dns")

    for rule in dns_rules:
        contains_values = rule.get("conditions", {}).get("contains", [])

        for value in contains_values:
            if value in domain:
                alert = create_alert(
                    rule.get("title", "DNS Rule Matched"),
                    rule.get("severity", "MEDIUM"),
                    {
                        "source_ip": src_ip,
                        "destination_dns_server": dst_ip,
                        "domain": domain,
                        "matched_value": value,
                        "rule_file": rule.get("file"),
                        "description": rule.get("description")
                    }
                )

                print(f"[ALERT] {rule.get('title')}")
                print(alert)
                save_alert(alert)
                return


def check_syn_scan_rules(src_ip, dst_ip, dst_port, rules):
    syn_tracker[src_ip].add(dst_port)

    syn_rules = get_rules_by_type(rules, "tcp_syn_scan")

    for rule in syn_rules:
        threshold = rule.get("threshold", {}).get("unique_ports", 10)

        if len(syn_tracker[src_ip]) >= threshold:
            alert = create_alert(
                rule.get("title", "Possible SYN Scan Detected"),
                rule.get("severity", "HIGH"),
                {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "ports_targeted": sorted(syn_tracker[src_ip]),
                    "unique_ports": len(syn_tracker[src_ip]),
                    "threshold": threshold,
                    "rule_file": rule.get("file"),
                    "description": rule.get("description")
                }
            )

            print(f"\n[ALERT] {rule.get('title')}")
            print(alert)
            save_alert(alert)
            return


def analyze_packet(packet, rules):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

        if tcp_flags == "S":
            check_syn_scan_rules(src_ip, dst_ip, dst_port, rules)

    if UDP in packet and DNS in packet and DNSQR in packet:
        domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")

        print("\n[DNS QUERY]")
        print(f"Source IP: {src_ip}")
        print(f"Destination DNS Server: {dst_ip}")
        print(f"Domain Queried: {domain}")

        check_dns_rules(domain, src_ip, dst_ip, rules)


def main():
    rules = load_rules(RULES_DIR)

    print("Starting packet analyzer with YAML-based detection rules...")
    print(f"Loaded {len(rules)} rule(s) from: {RULES_DIR}")
    print(f"Alerts will be saved to: {ALERT_FILE}")
    print("Press CTRL + C to stop.\n")

    sniff(
        prn=lambda packet: analyze_packet(packet, rules),
        store=False
    )


if __name__ == "__main__":
    main()
