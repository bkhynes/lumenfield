"""Safe-only Nmap Scripting Engine pass.

Runs after the banner scan, and only against hosts that already answered
on the authorised private range. The script expression is the safe
category with intrusive, exploit, brute, denial-of-service, fuzzer, and
malware scripts removed.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

SAFE_EXPR = "safe and not (intrusive or exploit or brute or dos or fuzzer or malware)"
MAX_HOSTS = 12


def safe_pass(observations: list[dict]) -> dict:
    if not observations:
        return {"available": bool(shutil.which("nmap")), "notes": [], "reason": "No answered host to script."}
    if not shutil.which("nmap"):
        return {"available": False, "notes": [], "reason": "Nmap is not installed. On the Mac: brew install nmap"}
    hosts = sorted({row["host"] for row in observations})[:MAX_HOSTS]
    ports = ",".join(sorted({str(row["port"]) for row in observations}))
    command = [
        "nmap", "-Pn", "-n", "-T2",
        "--host-timeout", "25s",
        "--script-timeout", "20s",
        "-p", ports,
        "--script", SAFE_EXPR,
        "-oX", "-",
        *hosts,
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "notes": [], "reason": f"Safe script pass did not finish: {exc}"}
    notes = _parse(completed.stdout)
    return {
        "available": True,
        "expression": SAFE_EXPR,
        "hosts": hosts,
        "notes": notes,
        "reason": completed.stderr.strip()[:180] if not notes else "",
    }


def _parse(xml_text: str) -> list[dict]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    notes = []
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr") if address is not None else "?"
        for script in host.iter("script"):
            output = " ".join((script.get("output") or "").split())
            if not output:
                continue
            notes.append({"host": ip, "script": script.get("id") or "script", "output": output[:280]})
    return notes[:40]
