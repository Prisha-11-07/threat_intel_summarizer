#!/usr/bin/env bash
# Linux iptables Threat Feed Enforcement
# Target: APT29

echo '[+] Applying iptables drop rules for APT29...'
iptables -I INPUT 1 -s 185.220.101.5 -m comment --comment "SOC Threat Intel: APT29" -j DROP
iptables -I OUTPUT 1 -d 185.220.101.5 -m comment --comment "SOC Threat Intel: APT29" -j DROP
iptables -I FORWARD 1 -d 185.220.101.5 -m comment --comment "SOC Threat Intel: APT29" -j DROP
iptables -I INPUT 1 -s 45.154.255.89 -m comment --comment "SOC Threat Intel: APT29" -j DROP
iptables -I OUTPUT 1 -d 45.154.255.89 -m comment --comment "SOC Threat Intel: APT29" -j DROP
iptables -I FORWARD 1 -d 45.154.255.89 -m comment --comment "SOC Threat Intel: APT29" -j DROP
echo '[✓] Enforced 2 IP block rules successfully.'