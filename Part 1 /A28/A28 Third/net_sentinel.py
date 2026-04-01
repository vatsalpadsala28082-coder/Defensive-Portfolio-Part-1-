#!/usr/bin/env python3
"""
net_sentinel.py — Network & System Security Analyzer
Tools: Host Scanner | Pass Validator | Auth Monitor | Shield Rules
"""

import argparse
import socket
import re
from datetime import datetime

# ══════════════════════════════════════════════
#  HOST SCANNER
# ══════════════════════════════════════════════
def host_scan(ip, low, high):
    print(f"\n{'='*52}")
    print(f"  HOST SCANNER  |  {ip}  |  Ports {low} to {high}")
    print(f"{'='*52}")
    active = []
    for port in range(low, high + 1):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(0.4)
            status = conn.connect_ex((ip, port))
            if status == 0:
                try:
                    label = socket.getservbyport(port)
                except:
                    label = "n/a"
                print(f"  >> Port {port:<6} STATUS: ACTIVE   Service: {label}")
                active.append(port)
            conn.close()
        except KeyboardInterrupt:
            print("\n  Scan aborted.")
            break
    print(f"{'='*52}")
    print(f"  Total Active Ports Found: {len(active)}\n")


# ══════════════════════════════════════════════
#  PASS VALIDATOR
# ══════════════════════════════════════════════
def validate_pass(secret):
    print(f"\n{'='*52}")
    print(f"  PASS VALIDATOR")
    print(f"{'='*52}")

    checks = [
        ("Length at least 12 chars",    len(secret) >= 12),
        ("Has uppercase letter",        bool(re.search(r'[A-Z]', secret))),
        ("Has lowercase letter",        bool(re.search(r'[a-z]', secret))),
        ("Has numeric digit",           bool(re.search(r'[0-9]', secret))),
        ("Has special symbol",          bool(re.search(r'[^a-zA-Z0-9]', secret))),
        ("No dictionary words",         not bool(re.search(
            r'(pass|admin|user|root|test|login|letme)', secret, re.IGNORECASE))),
    ]

    total = 0
    for desc, result in checks:
        tag = " OK " if result else "FAIL"
        print(f"  [{tag}]  {desc}")
        if result:
            total += 1

    verdict = {6: "VAULT-GRADE", 5: "SECURE", 4: "ACCEPTABLE"}.get(total, "INSECURE")
    print(f"\n  Points : {total} / 6")
    print(f"  Status : {verdict}")
    print(f"{'='*52}\n")


# ══════════════════════════════════════════════
#  AUTH MONITOR (Log Analysis)
# ══════════════════════════════════════════════
def monitor_auth(log_file):
    print(f"\n{'='*52}")
    print(f"  AUTH MONITOR  |  {log_file}")
    print(f"{'='*52}")

    pat_fail = re.compile(r'Failed password for (\S+) from ([\d.]+)')
    pat_ok   = re.compile(r'Accepted password for (\S+) from ([\d.]+)')

    ok_list, fail_list, ip_hits = [], [], {}

    try:
        with open(log_file, "r") as fh:
            for line in fh:
                f = pat_fail.search(line)
                o = pat_ok.search(line)
                if f:
                    fail_list.append((f.group(1), f.group(2)))
                    ip_hits[f.group(2)] = ip_hits.get(f.group(2), 0) + 1
                if o:
                    ok_list.append((o.group(1), o.group(2)))
    except FileNotFoundError:
        print(f"  [!] Cannot locate file: {log_file}")
        print(f"  Tip: Provide a valid local log file path\n")
        return

    print(f"\n  [+] Verified Logins : {len(ok_list)}")
    for usr, addr in ok_list[:5]:
        print(f"      {usr:<15} {addr}")

    print(f"\n  [-] Login Failures  : {len(fail_list)}")
    print(f"  [-] Suspicious IPs  : {len(ip_hits)}")
    print()
    for addr, hits in sorted(ip_hits.items(), key=lambda x: -x[1])[:10]:
        alert = "  [!!! BRUTE FORCE ALERT]" if hits >= 5 else ""
        print(f"      {addr:<20} {hits} hit(s){alert}")
    print(f"{'='*52}\n")


# ══════════════════════════════════════════════
#  SHIELD RULES (Firewall Generator)
# ══════════════════════════════════════════════
def shield_rules(blacklist_ip, whitelist_ports, export=None):
    ts = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    lines = [
        "#!/bin/bash",
        f"# Net Sentinel — Shield Rules | {ts}",
        "#",
        "# Step 1: Clear existing rules",
        "iptables -F",
        "iptables -Z",
        "",
        f"# Step 2: Blacklist IP -> {blacklist_ip}",
        f"iptables -A INPUT   -s {blacklist_ip} -j REJECT",
        f"iptables -A FORWARD -s {blacklist_ip} -j REJECT",
        "",
        "# Step 3: Whitelist ports",
    ]
    for wp in whitelist_ports:
        lines.append(f"iptables -A INPUT -p tcp --dport {wp} -m state --state NEW,ESTABLISHED -j ACCEPT")

    lines += [
        "",
        "# Step 4: Set default policies",
        "iptables -P INPUT   DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT  ACCEPT",
        "",
        "echo 'Net Sentinel: Shield rules loaded at " + ts + "'"
    ]

    output = "\n".join(lines)
    if export:
        with open(export, "w") as fh:
            fh.write(output)
        print(f"\n  [SHIELD] Rules exported to: {export}\n")
    else:
        print("\n" + output + "\n")


# ══════════════════════════════════════════════
#  FULL DEMO
# ══════════════════════════════════════════════
def full_demo():
    print("\n" + "*" * 52)
    print("     NET SENTINEL — FULL SYSTEM DEMO")
    print("*" * 52)

    print("\n--- [A] HOST SCANNER ---")
    host_scan("127.0.0.1", 20, 100)

    print("\n--- [B] PASS VALIDATOR ---")
    validate_pass("N3tS3nt!nel#2024")

    print("\n--- [C] SHIELD RULES ---")
    shield_rules("172.16.0.55", [21, 22, 80, 443, 8080])


# ══════════════════════════════════════════════
#  MAIN CLI
# ══════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        prog="net_sentinel.py",
        description="Net Sentinel — Host Scanner | Pass Validator | Auth Monitor | Shield Rules"
    )
    sp = parser.add_subparsers(dest="tool")

    # hostscan
    hs = sp.add_parser("hostscan", help="Scan active ports on a host")
    hs.add_argument("ip")
    hs.add_argument("--low",  type=int, default=1)
    hs.add_argument("--high", type=int, default=1024)

    # validate
    vl = sp.add_parser("validate", help="Validate password strength")
    vl.add_argument("secret")

    # monitor
    mn = sp.add_parser("monitor", help="Monitor auth log for threats")
    mn.add_argument("logfile")

    # shield
    sh = sp.add_parser("shield", help="Generate firewall shield rules")
    sh.add_argument("--block",  required=True)
    sh.add_argument("--open",   nargs="+", type=int, default=[])
    sh.add_argument("--export", default=None)

    # demo
    sp.add_parser("demo", help="Run full feature demonstration")

    args = parser.parse_args()

    if   args.tool == "hostscan": host_scan(args.ip, args.low, args.high)
    elif args.tool == "validate": validate_pass(args.secret)
    elif args.tool == "monitor":  monitor_auth(args.logfile)
    elif args.tool == "shield":   shield_rules(args.block, args.open, args.export)
    elif args.tool == "demo":     full_demo()
    else: parser.print_help()

if __name__ == "__main__":
    main()
