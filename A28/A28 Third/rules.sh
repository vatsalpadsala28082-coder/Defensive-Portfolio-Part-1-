#!/bin/bash
# Net Sentinel — Shield Rules | 11-03-2026 14:22:56
#
# Step 1: Clear existing rules
iptables -F
iptables -Z

# Step 2: Blacklist IP -> 172.16.0.55
iptables -A INPUT   -s 172.16.0.55 -j REJECT
iptables -A FORWARD -s 172.16.0.55 -j REJECT

# Step 3: Whitelist ports

# Step 4: Set default policies
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

echo 'Net Sentinel: Shield rules loaded at 11-03-2026 14:22:56'