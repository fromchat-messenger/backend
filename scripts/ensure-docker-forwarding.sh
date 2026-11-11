#!/usr/bin/env bash
# Cloud VMs often ship iptables-legacy with FORWARD policy DROP while Docker
# programs custom bridges through iptables-nft. Inter-container traffic on those
# bridges is dropped until legacy FORWARD allows forwarding.
set -euo pipefail

if command -v iptables-legacy >/dev/null 2>&1; then
  sudo iptables-legacy -P FORWARD ACCEPT
  sudo iptables-legacy -P INPUT ACCEPT
fi
