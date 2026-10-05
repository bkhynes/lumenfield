"""Device inventory for the authorised private network.

Reads the neighbour table and the latest banner scan, then stores first
seen, last seen, and how often each address has answered. MySQL is the
system of record. Nothing here leaves the range the operator confirmed.
"""

from __future__ import annotations

import os
import socket
import subprocess
from datetime import datetime, timezone

import pymysql

OUIS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "f4:5c:89": "Apple",
    "3c:22:fb": "Apple",
    "00:1a:11": "Google",
    "18:b4:30": "Nest",
    "b0:be:76": "TP-Link",
    "50:c7:bf": "TP-Link",
    "c0:25:e9": "Netgear",
    "00:1b:2f": "Netgear",
    "00:09:0f": "Fortinet",
    "00:0c:29": "VMware",
}


def mysql_config(database: str | None = None) -> dict:
    config = {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "charset": "utf8mb4",
        "autocommit": True,
        "connect_timeout": 3,
    }
    config["database"] = database if database is not None else os.environ.get("MYSQL_DATABASE", "lumenfield")
    return config


def ensure_schema() -> None:
    bootstrap = mysql_config(database=None)
    bootstrap.pop("database", None)
    conn = pymysql.connect(**bootstrap)
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE DATABASE IF NOT EXISTS lumenfield")
            cur.execute("USE lumenfield")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                  id BIGINT PRIMARY KEY AUTO_INCREMENT,
                  ip VARCHAR(45) NOT NULL,
                  mac VARCHAR(17) NULL,
                  hostname VARCHAR(255) NULL,
                  vendor VARCHAR(80) NULL,
                  role_hint VARCHAR(80) NULL,
                  first_seen DATETIME NOT NULL,
                  last_seen DATETIME NOT NULL,
                  times_seen INT NOT NULL DEFAULT 1,
                  last_ports VARCHAR(160) NULL,
                  last_evidence VARCHAR(255) NULL,
                  UNIQUE KEY uniq_ip (ip)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sightings (
                  id BIGINT PRIMARY KEY AUTO_INCREMENT,
                  device_id BIGINT NOT NULL,
                  seen_at DATETIME NOT NULL,
                  neigh_state VARCHAR(24) NULL,
                  ports VARCHAR(160) NULL,
                  evidence VARCHAR(255) NULL,
                  KEY device_seen (device_id, seen_at)
                )
                """
            )
    finally:
        conn.close()


def neighbours() -> list[dict]:
    try:
        raw = subprocess.check_output(["ip", "neigh"], text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("fe80",):
            continue
        ip = parts[0]
        if ":" in ip:
            continue
        mac = parts[parts.index("lladdr") + 1] if "lladdr" in parts else None
        state = parts[-1]
        if state == "FAILED":
            continue
        rows.append({"ip": ip, "mac": mac, "state": state, "vendor": _vendor(mac)})
    return rows


def record(scan: dict) -> dict:
    ensure_schema()
    online = _merge(scan)
    conn = pymysql.connect(**mysql_config())
    try:
        with conn.cursor() as cur:
            for device in online:
                _upsert(cur, device, scan.get("scanned_at"))
        return summary(conn)
    finally:
        conn.close()


def summary(conn=None) -> dict:
    if conn is None:
        ensure_schema()
    own = conn is None
    if own:
        conn = pymysql.connect(**mysql_config())
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ip, mac, hostname, vendor, role_hint, first_seen, last_seen,
                       times_seen, last_ports, last_evidence
                FROM devices
                ORDER BY last_seen DESC
                LIMIT 80
                """
            )
            devices = [_row(cur, row) for row in cur.fetchall()]
            cur.execute("SELECT COUNT(*) FROM devices WHERE last_seen >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE")
            recent = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM devices")
            known = cur.fetchone()[0]
        return {"ok": True, "connected_now": recent, "known": known, "devices": devices}
    finally:
        if own:
            conn.close()


def _merge(scan: dict) -> list[dict]:
    by_ip: dict[str, dict] = {}
    for neigh in neighbours():
        by_ip[neigh["ip"]] = {**neigh, "ports": [], "evidence": ""}
    for obs in scan.get("observations") or []:
        row = by_ip.setdefault(obs["host"], {"ip": obs["host"], "mac": None, "state": "answered", "vendor": None, "ports": [], "evidence": ""})
        row["ports"].append(str(obs["port"]))
        if obs.get("evidence"):
            row["evidence"] = obs["evidence"][:180]
        row["role_hint"] = _role(obs.get("evidence") or "")
    for row in by_ip.values():
        row["hostname"] = _hostname(row["ip"])
        row.setdefault("role_hint", None)
    return list(by_ip.values())


def _upsert(cur, device: dict, seen_at: str | None) -> None:
    seen = seen_at.replace("T", " ").replace("Z", "") if seen_at else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ports = ",".join(device.get("ports") or [])
    cur.execute(
        """
        INSERT INTO devices (ip, mac, hostname, vendor, role_hint, first_seen, last_seen, times_seen, last_ports, last_evidence)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s, %s)
        ON DUPLICATE KEY UPDATE
          mac = COALESCE(VALUES(mac), mac),
          hostname = COALESCE(VALUES(hostname), hostname),
          vendor = COALESCE(VALUES(vendor), vendor),
          role_hint = COALESCE(VALUES(role_hint), role_hint),
          last_seen = VALUES(last_seen),
          times_seen = times_seen + 1,
          last_ports = VALUES(last_ports),
          last_evidence = VALUES(last_evidence)
        """,
        (device["ip"], device.get("mac"), device.get("hostname"), device.get("vendor"), device.get("role_hint"), seen, seen, ports, device.get("evidence")),
    )
    cur.execute("SELECT id, times_seen FROM devices WHERE ip = %s", (device["ip"],))
    device_id, times_seen = cur.fetchone()
    cur.execute(
        "INSERT INTO sightings (device_id, seen_at, neigh_state, ports, evidence) VALUES (%s, %s, %s, %s, %s)",
        (device_id, seen, device.get("state"), ports, device.get("evidence")),
    )
    device["times_seen"] = times_seen


def _row(cur, row: tuple) -> dict:
    ip, mac, hostname, vendor, role, first_seen, last_seen, times_seen, ports, evidence = row
    cur.execute("SELECT COUNT(*) FROM sightings WHERE device_id = (SELECT id FROM devices WHERE ip = %s)", (ip,))
    sightings = cur.fetchone()[0]
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "role": role,
        "first_seen": str(first_seen),
        "last_seen": str(last_seen),
        "times_seen": times_seen,
        "sightings": sightings,
        "ports": ports,
        "evidence": evidence,
    }


def _hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0][:255]
    except OSError:
        return None


def _vendor(mac: str | None) -> str | None:
    if not mac or len(mac) < 8:
        return None
    return OUIS.get(mac.lower()[:8])


def _role(evidence: str) -> str | None:
    text = evidence.lower()
    for needle, role in (("ssh", "remote admin"), ("forti", "mail or firewall"), ("mikrotik", "router"), ("sharepoint", "intranet")):
        if needle in text:
            return role
    return None


if __name__ == "__main__":
    ensure_schema()
    print(summary())
