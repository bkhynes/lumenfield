"""Authorised exposure scan for the connected private network.

Identifies services by open port, TLS certificate name, and HTTP or SSH
banner, then matches those names to the Lumenfield board. It does not send
exploit traffic, attempt logins, or leave the private ranges the operator
confirmed.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from catalog import CATALOG

PORTS = (22, 80, 443, 444, 8443, 9443, 8291)
MAX_HOSTS = 128
TIMEOUT = 0.45

FINGERPRINTS = [
    {"id": "LF-EDGE-001", "needles": ("vmanage", "viptela", "sd-wan manager", "sdwan")},
    {"id": "LF-MAIL-002", "needles": ("fortimail", "fortinet")},
    {"id": "LF-APP-003", "needles": ("zammad",)},
    {"id": "LF-SDWAN-004", "needles": ("velocloud", "vco")},
    {"id": "LF-VPN-005", "needles": ("check point", "checkpoint")},
    {"id": "LF-COLLAB-006", "needles": ("sharepoint", "microsoftsharepointteamservices")},
    {"id": "LF-NET-007", "needles": ("mikrotik", "routeros")},
    {"id": "LF-ADC-008", "needles": ("netscaler", "citrix", "ns_af")},
]


def local_network() -> dict:
    host = _local_ip()
    ip = ipaddress.ip_address(host)
    if ip.is_private:
        net = ipaddress.ip_network(f"{host}/24", strict=False)
    else:
        net = ipaddress.ip_network(f"{host}/32")
    return {"host": host, "cidr": str(net), "private": ip.is_private or ip.is_loopback}


def scan(cidr: str, confirmed: bool) -> dict:
    if not confirmed:
        raise PermissionError("Confirm this is a network you are authorised to assess.")
    network = ipaddress.ip_network(cidr, strict=False)
    if not _allowed(network):
        raise PermissionError("Lumenfield only scans loopback and private ranges you operate.")
    hosts = [str(ip) for ip in network.hosts()]
    truncated = len(hosts) > MAX_HOSTS
    hosts = hosts[:MAX_HOSTS]
    observations = []
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(_probe, host) for host in hosts]
        for future in as_completed(futures):
            observations.extend(future.result())
    findings = _match(observations)
    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cidr": str(network),
        "hosts_considered": len(hosts),
        "truncated": truncated,
        "observations": observations,
        "findings": findings,
        "clear": not findings,
    }


def _allowed(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return network.is_private or network.is_loopback


def _local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def _probe(host: str) -> list[dict]:
    found = []
    for port in PORTS:
        banner = _banner(host, port)
        if banner is None:
            continue
        found.append({"host": host, "port": port, "evidence": banner[:180]})
    return found


def _banner(host: str, port: int) -> str | None:
    try:
        with socket.create_connection((host, port), TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            if port in (443, 444, 8443, 9443):
                return _tls_name(sock, host) or _http(sock, host, tls=True)
            if port == 22:
                return sock.recv(120).decode("utf-8", "replace").strip() or "ssh-open"
            hint = _http(sock, host, tls=False)
            return hint or "open"
    except OSError:
        return None


def _tls_name(sock: socket.socket, host: str) -> str | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with context.wrap_socket(sock, server_hostname=host) as wrapped:
            cert = wrapped.getpeercert(binary_form=False) or {}
            subject = " ".join(v for pair in cert.get("subject", ()) for _, v in pair)
            return subject or _http(wrapped, host, tls=False)
    except (ssl.SSLError, OSError):
        return None


def _http(sock: socket.socket, host: str, tls: bool) -> str | None:
    try:
        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        raw = sock.recv(400).decode("utf-8", "replace")
    except OSError:
        return None
    interesting = [line.strip() for line in raw.splitlines() if line.lower().startswith(("server:", "location:", "set-cookie:", "http/"))]
    return " | ".join(interesting)[:180] or None


def _match(observations: list[dict]) -> list[dict]:
    by_id = {item["id"]: item for item in CATALOG}
    hits = []
    seen = set()
    for obs in observations:
        evidence = obs["evidence"].lower()
        for rule in FINGERPRINTS:
            if not any(needle in evidence for needle in rule["needles"]):
                continue
            key = (rule["id"], obs["host"], obs["port"])
            if key in seen:
                continue
            seen.add(key)
            item = by_id[rule["id"]]
            hits.append({
                "id": item["id"],
                "cve": item["cve"],
                "title": item["title"],
                "relevance": item["relevance"],
                "client_line": item["client_line"],
                "fix": item["fix"],
                "host": obs["host"],
                "port": obs["port"],
                "evidence": obs["evidence"],
                "note": "Product name matched a watched, exploited class. Confirm the build before treating this as an incident.",
            })
    return sorted(hits, key=lambda row: -row["relevance"])
