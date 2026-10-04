"""Lumenfield catalog.

Public exposure classes drawn from vendor and CISA KEV reporting.
Scripts shipped with each item are defensive checks and hardening
patterns only. They do not demonstrate exploitation.
"""

from __future__ import annotations

CATALOG = [
    {
        "id": "LF-EDGE-001",
        "cve": "CVE-2026-76504",
        "title": "Cisco Catalyst SD-WAN Manager authentication bypass",
        "vendor": "Cisco",
        "product": "Catalyst SD-WAN Manager",
        "klass": "Authentication bypass",
        "cvss": 9.8,
        "kev_added": "2026-09-30",
        "due": "2026-10-03",
        "exposure": "Internet-facing management plane",
        "relevance": 97,
        "status": "Actively listed",
        "audience": "Network operations, MSSP clients with SD-WAN",
        "impact": "An unauthenticated remote party can reach the management API with admin privileges if the Manager is reachable. That is a control-plane compromise, not a single-host nuisance: policy, certificates, and branch connectivity sit behind it.",
        "why_ongoing": "SD-WAN managers stay relevant after the first patch wave because appliances are often forgotten on management VRFs, lab clones keep old builds, and 2026 already put multiple SD-WAN issues on the KEV list. A one-time scan in January does not see a September control-plane bug.",
        "client_line": "Your branch network's control panel may be reachable without a password. We treat that as a board-level outage risk until the build is confirmed and the panel is off the public internet.",
        "fix": [
            "Install the Cisco fixed release for every Manager node, including standby and lab copies.",
            "Remove public reachability. Allow the Manager only from a bastion or VPN.",
            "Review /var/log/nms/vmanage-server.log for unexpected j_security_check calls, especially accounts whose names start with viptela-reserved-, from IPs you do not operate.",
            "Rotate local admin credentials and API tokens after the upgrade.",
        ],
        "check_name": "edge-exposure.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Defensive inventory only. Does not send exploit traffic.
# Lists listeners that often front network-management planes.
set -euo pipefail
echo "Lumenfield edge exposure inventory — $(date -Is)"
echo "Host: $(hostname -f 2>/dev/null || hostname)"
if command -v ss >/dev/null; then
  ss -lntup | awk 'NR==1 || /:443|:8443|:9443|:22 /'
else
  netstat -lntup 2>/dev/null || true
fi
echo
echo "Public addresses on this host:"
ip -4 addr show scope global | awk '/inet / {print $2}'
echo
echo "Reminder: a management UI should not answer on those addresses."
""",
    },
    {
        "id": "LF-MAIL-002",
        "cve": "CVE-2026-104286",
        "title": "FortiMail unauthenticated file write",
        "vendor": "Fortinet",
        "product": "FortiMail",
        "klass": "Path traversal",
        "cvss": 9.1,
        "kev_added": "2026-10-01",
        "due": "2026-10-04",
        "exposure": "Mail gateway on HTTP or HTTPS",
        "relevance": 96,
        "status": "Due this week",
        "audience": "Anyone running FortiMail as the inbound mail boundary",
        "impact": "A path-traversal and null-handling flaw can let an unauthenticated caller write files on the appliance through the web service. A mail gateway that accepts attacker-controlled files is a pivot into identity and finance workflows.",
        "why_ongoing": "Mail security appliances are patched on change windows, not on disclosure day. The KEV due date is 4 October 2026. Relevance stays high until every HA member and every virtual appliance image is on the fixed build.",
        "client_line": "The system that screens your email can be written to without a login. We recommend an emergency change window, not the next monthly cycle.",
        "fix": [
            "Apply Fortinet's fixed FortiMail release on active and passive nodes.",
            "Restrict the admin and API listeners to management networks.",
            "After patching, review newly written files and unexpected admin accounts. A version upgrade does not always remove an implant dropped earlier.",
            "Confirm mail-flow policy still matches the intended gateway after reboot.",
        ],
        "check_name": "appliance-admin-bind.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Confirms whether an admin listener is bound wider than the management plane.
# Safe to run on a jump host. It only reads local socket state.
set -euo pipefail
MGMT_CIDR="${1:-10.0.0.0/8}"
echo "Expected management plane: $MGMT_CIDR"
ss -lnt | awk 'NR>1 {print $4}' | while read -r ep; do
  case "$ep" in
    0.0.0.0:*|\\[::\\]:*|[::]:*) echo "WIDE BIND $ep — review if this is an admin UI" ;;
    *) echo "scoped $ep" ;;
  esac
done
""",
    },
    {
        "id": "LF-APP-003",
        "cve": "CVE-2026-102489",
        "title": "Zammad session fixation to code execution",
        "vendor": "Zammad",
        "product": "Zammad",
        "klass": "Session fixation",
        "cvss": 8.8,
        "kev_added": "2026-10-02",
        "due": "2026-10-05",
        "exposure": "Customer support portal",
        "relevance": 93,
        "status": "Newly listed",
        "audience": "Support-desk owners, MSP ticketing stacks",
        "impact": "A session-fixation weakness in Zammad can be chained into code execution as the application user. Support desks hold customer identity data and often have SMTP and directory credentials beside the tickets.",
        "why_ongoing": "Helpdesk software is exposed on purpose. Fixation bugs stay relevant wherever session IDs are accepted from the query string or a cookie set before login. New portal themes and reverse proxies reintroduce the condition.",
        "client_line": "A customer logging into the support portal could be handed a session an outsider already knows. Patch, then confirm the portal regenerates the session at login.",
        "fix": [
            "Upgrade Zammad to the vendor fixed release before the 5 October 2026 KEV date.",
            "Terminate TLS at a proxy you control and pass only your own session cookie.",
            "Regenerate session identifiers on authentication and reject session IDs supplied in URLs.",
            "Review application logs for logins that reused a pre-auth session id.",
        ],
        "check_name": "session_hygiene.php",
        "check_lang": "php",
        "check": """<?php
/**
 * Hardening pattern for PHP session handling.
 * This is the defensive control, not an attack demonstration.
 * Run with: php session_hygiene.php
 */
declare(strict_types=1);

function lumenfield_session_start(): void {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Lax');
    session_name('LFSESS');
    session_start();
}

function lumenfield_on_login(string $user): void {
    session_regenerate_id(true);
    $_SESSION['user'] = $user;
    $_SESSION['issued_at'] = time();
}

echo "strict_mode recommendation: 1\\n";
echo "use_only_cookies recommendation: 1\\n";
echo "Reject any session id that arrives in the query string.\\n";
""",
    },
    {
        "id": "LF-SDWAN-004",
        "cve": "CVE-2026-93952",
        "title": "VeloCloud Orchestrator unauthenticated host compromise",
        "vendor": "Arista",
        "product": "VeloCloud Orchestrator On-Prem",
        "klass": "Improper input validation",
        "cvss": 10.0,
        "kev_added": "2026-09-22",
        "due": "2026-09-25",
        "exposure": "Orchestrator web interface",
        "relevance": 88,
        "status": "Past due — confirm closure",
        "audience": "WAN transformation programmes",
        "impact": "Arista rated this CVSS 10 and confirmed active exploitation. Network access to the on-prem orchestrator web interface, in a certificate-authenticated edge design, can compromise the host and the data it manages. No tenant password is required.",
        "why_ongoing": "Fixes landed on 5.2.3.16 and 6.4.2.8 first; other supported branches followed later. Estates that standardised on 6.1 or 7.0 can still be open. Past-due KEV items stay on the client report until evidence of the fixed build is attached.",
        "client_line": "The system that configures every branch may be fully exposed. We do not close this item on a ticket comment — we close it on a version screenshot.",
        "fix": [
            "Move every on-prem orchestrator to 5.2.3.16 / 6.4.2.8 or the fixed build for that branch.",
            "Do not publish the orchestrator UI to the internet.",
            "Treat pre-patch exposure as an incident: preserve logs before upgrade.",
            "Reissue edge certificates if the orchestrator was reachable during the exploitation window.",
        ],
        "check_name": "version-attest.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Records a version attestation for the client file. No probing of third parties.
set -euo pipefail
OUT="${1:-lumenfield-attestation.txt}"
{
  echo "attested_at=$(date -Is)"
  echo "host=$(hostname)"
  echo "operator=${USER:-unknown}"
  echo "note=Paste vendor version output below. Do not invent a fixed build."
} > "$OUT"
echo "Wrote $OUT — attach vendor 'show version' or UI screenshot."
""",
    },
    {
        "id": "LF-VPN-005",
        "cve": "CVE-2026-85102",
        "title": "Check Point VPN certificate validation failure",
        "vendor": "Check Point",
        "product": "Quantum Security Gateway / Spark",
        "klass": "Improper certificate validation",
        "cvss": 9.8,
        "kev_added": "2026-09-22",
        "due": "2026-09-25",
        "exposure": "Site-to-site or remote-access VPN",
        "relevance": 86,
        "status": "Past due — forensic triage",
        "audience": "Perimeter owners",
        "impact": "Gateways doing site-to-site or remote-access VPN can accept a peer they should have rejected. CISA marked the related Check Point KEV entries for forensic triage, not patch-and-forget.",
        "why_ongoing": "Certificate-validation bugs remain relevant for the life of every unused VPN community and every partner tunnel. A gateway patched in production and forgotten in a branch pair is still the finding.",
        "client_line": "A VPN that does not properly check who is on the other end is not a VPN. We pair the patch with a tunnel inventory.",
        "fix": [
            "Apply the Check Point fixed jumbo and confirm it on every cluster member.",
            "Inventory site-to-site and remote-access communities; disable unused ones.",
            "Because KEV guidance asked for forensic triage, review gateway logs for unfamiliar peers before and after the patch.",
            "Revisit the companion management-plane issue CVE-2026-93616 on the same estate.",
        ],
        "check_name": "tunnel-inventory.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Local note-taker for VPN communities. Fill from the management console export.
set -euo pipefail
cat <<'EOF'
community,peer,purpose,owner,last_seen,keep
# example-partner,203.0.113.10,EDI invoices,finance,2026-09-01,yes
EOF
echo "Export communities from the console. Delete rows you cannot name."
""",
    },
    {
        "id": "LF-COLLAB-006",
        "cve": "CVE-2026-65660",
        "title": "Microsoft SharePoint code injection",
        "vendor": "Microsoft",
        "product": "SharePoint Server",
        "klass": "Code injection",
        "cvss": 8.8,
        "kev_added": "2026-09-25",
        "due": "2026-09-28",
        "exposure": "Authenticated SharePoint",
        "relevance": 79,
        "status": "Confirm patch + content audit",
        "audience": "Intranets and partner extranets",
        "impact": "An authenticated user can inject code that the server executes. In real intrusions this is a second step after a stolen mailbox or a weak partner account, then a path toward file shares and identity systems.",
        "why_ongoing": "SharePoint farms lag cumulative updates, and a patched server can still host a web shell left behind. Evolving tests re-check both build number and unexpected files in layout directories.",
        "client_line": "A normal user account on the intranet may be enough to run code on the SharePoint server. Patch the farm, then look for files that should not be there.",
        "fix": [
            "Install the current SharePoint security update on every WFE and app server.",
            "Reduce who can edit pages and add web parts.",
            "Compare layout and template directories with a known-good file list.",
            "Pair with identity review: phishing-resistant MFA on every account that can edit.",
        ],
        "check_name": "layout-diff.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Compares a SharePoint layout directory to a baseline manifest.
# Usage: layout-diff.sh /path/to/layouts baseline.sha256
set -euo pipefail
DIR="${1:?layout directory}"
BASE="${2:?baseline sha256 file}"
find "$DIR" -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/lf-layout.sha256
diff -u "$BASE" /tmp/lf-layout.sha256 || echo "Drift detected — analyst review, do not delete blindly."
""",
    },
    {
        "id": "LF-NET-007",
        "cve": "CVE-2026-67279",
        "title": "MikroTik RouterOS control bypass",
        "vendor": "MikroTik",
        "product": "RouterOS",
        "klass": "Workflow enforcement",
        "cvss": 6.5,
        "kev_added": "2026-09-25",
        "due": "2026-09-28",
        "exposure": "Branch routers",
        "relevance": 74,
        "status": "Estate-wide, easy to miss",
        "audience": "Retail, regional offices, ISP edge",
        "impact": "A behavioural-workflow flaw lets a caller skip a control the router should enforce. CVSS understates it when the router is the only firewall at a site.",
        "why_ongoing": "RouterOS fleets are large, Winbox stays exposed, and a 6.5 score loses the argument against a change freeze. KEV listing is the relevance signal, not the CVSS badge.",
        "client_line": "Branch routers are how a modest bug becomes every shop's network. We schedule them as a fleet, not as a single ticket.",
        "fix": [
            "Upgrade RouterOS on a canary site, then the fleet, including spare units on the shelf.",
            "Disable Winbox, API, and webfig on the WAN.",
            "Replace shared admin passwords with per-device credentials in a vault.",
        ],
        "check_name": "fleet-watchlist.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Prints routers whose recorded build is older than a floor you choose.
# Input CSV: name,mgmt_ip,recorded_version
set -euo pipefail
FLOOR="${1:-7.19}"
FILE="${2:-routers.csv}"
echo "Floor: $FLOOR"
awk -F, -v floor="$FLOOR" 'NR>1 && $3 < floor {print "BEHIND", $1, $2, $3}' "$FILE"
""",
    },
    {
        "id": "LF-ADC-008",
        "cve": "CVE-2026-88771",
        "title": "Citrix NetScaler unauthenticated command execution",
        "vendor": "Citrix",
        "product": "NetScaler ADC / Gateway",
        "klass": "Improper input validation",
        "cvss": 9.8,
        "kev_added": "2026-09-27",
        "due": "2026-09-30",
        "exposure": "Gateway VIP",
        "relevance": 90,
        "status": "Assume edge interest",
        "audience": "Remote access programmes",
        "impact": "NetScaler ADC and Gateway can be driven into command execution by an unauthenticated caller if the virtual server is exposed. These appliances terminate VPN and often sit next to directory services.",
        "why_ongoing": "Citrix gateway bugs recur because the VIP must be public. Each new KEV entry is a reason the test library grows instead of being retired after one engagement.",
        "client_line": "The remote-work front door can run commands before anyone logs in. Patch, restrict the management IP, and check for persistence.",
        "fix": [
            "Apply the Citrix fixed build and reboot into it — config-only workarounds are not closure.",
            "Bind the management GUI to a non-routable address.",
            "Search for unexpected cron entries, new admin accounts, and modified nsscripts after the window of exposure.",
            "Force a re-auth of VPN users if logs suggest pre-patch access.",
        ],
        "check_name": "gateway-posture.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Posture questions for an ADC change record. Answer from the console, not by guessing.
set -euo pipefail
for q in \\
  "Fixed build installed on all HA nodes?" \\
  "Management GUI unreachable from the internet?" \\
  "New local accounts since 2026-09-20 reviewed?" \\
  "Config backup taken before upgrade?"
do
  echo "[ ] $q"
done
""",
    },
    {
        "id": "LF-END-009",
        "cve": "CVE-2026-86950",
        "title": "Apple CoreGraphics out-of-bounds write",
        "vendor": "Apple",
        "product": "iOS, iPadOS, macOS",
        "klass": "Memory corruption",
        "cvss": 8.6,
        "kev_added": "2026-09-29",
        "due": "2026-10-02",
        "exposure": "Endpoints opening documents or web content",
        "relevance": 81,
        "status": "Endpoint lag",
        "audience": "Device fleets",
        "impact": "An out-of-bounds write in CoreGraphics can become code execution when a person opens crafted content. Executive devices are the usual soft edge around a well-patched data centre.",
        "why_ongoing": "MDM rings, BYOD, and deferred rapid-security responses keep a fraction of the fleet behind. The test evolves by reading MDM compliance, not by attacking a handset.",
        "client_line": "A document opened on a director's laptop can be the way in. We measure the fleet, not the gold image.",
        "fix": [
            "Push the Apple security update through MDM and block access from non-compliant devices.",
            "Report devices unseen in 14 days as unknown, not as healthy.",
            "Keep mail and browser isolation policies in place while the ring completes.",
        ],
        "check_name": "mdm-lag.sh",
        "check_lang": "bash",
        "check": """#!/usr/bin/env bash
# Summarise an MDM export. CSV columns: device,os,build,last_seen
set -euo pipefail
FILE="${1:-devices.csv}"
python3 - "$FILE" <<'PY'
import csv, sys
from datetime import datetime, timezone
path = sys.argv[1]
now = datetime.now(timezone.utc)
late = 0
with open(path, newline="") as fh:
    for row in csv.DictReader(fh):
        seen = row.get("last_seen") or ""
        print(f"{row.get('device','?'):20} {row.get('os','')} {row.get('build','')} seen {seen}")
        late += 1
print(f"rows={late} — flag any build below the Apple security release.")
PY
""",
    },
    {
        "id": "LF-OPS-010",
        "cve": "CLASS-KEV-FEED",
        "title": "Self-learning test intake from public KEV",
        "vendor": "Lumenfield",
        "product": "Intake pipeline",
        "klass": "Process control",
        "cvss": 0,
        "kev_added": "2026-10-04",
        "due": "rolling",
        "exposure": "Assessment programme",
        "relevance": 100,
        "status": "Always on",
        "audience": "The engagement itself",
        "impact": "A static penetration-test PDF expires the week a new edge bug is added to KEV. Clients feel the gap when the next incident is a product you scanned three months ago and never re-tested.",
        "why_ongoing": "CISA's Known Exploited Vulnerabilities catalog is a public priority queue. Lumenfield ingests new entries, scores them against the client's asset tags, and opens an analyst task. That is how the test library grows without waiting for the next annual proposal.",
        "client_line": "We do not resell last quarter's findings. When a new exploited bug matches your stack, it appears on this board and in the next brief.",
        "fix": [
            "Tag assets with vendor and role so new KEV rows can match automatically.",
            "Run the intake weekly, and immediately when a due date falls inside ten days.",
            "Keep human review on every new test. Automation files the lead; an analyst confirms it belongs in the client report.",
            "Store evidence of closure: build, date, operator, and log review.",
        ],
        "check_name": "kev_sync.py",
        "check_lang": "python",
        "check": """#!/usr/bin/env python3
\"\"\"Pull the public CISA KEV feed and list entries newer than a watermark.

This imports advisory metadata only. It does not download exploit detail
or send traffic to client systems.
\"\"\"
import json, sys, urllib.request
FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
watermark = sys.argv[1] if len(sys.argv) > 1 else "2026-09-20"
with urllib.request.urlopen(FEED, timeout=30) as resp:
    data = json.load(resp)
rows = [v for v in data.get("vulnerabilities", []) if v.get("dateAdded", "") >= watermark]
print(f"new_since {watermark}: {len(rows)}")
for v in rows[:25]:
    print(f"{v.get('dateAdded')}  {v.get('cveID')}  {v.get('vendorProject')}  {v.get('product')}")
""",
    },
]
