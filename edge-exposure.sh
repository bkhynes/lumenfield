#!/usr/bin/env bash
# Prints routers whose recorded build is older than a floor you choose.
# Input CSV: name,mgmt_ip,recorded_version
set -euo pipefail
FLOOR="${1:-7.19}"
FILE="${2:-routers.csv}"
echo "Floor: $FLOOR"
awk -F, -v floor="$FLOOR" 'NR>1 && $3 < floor {print "BEHIND", $1, $2, $3}' "$FILE"
