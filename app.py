#!/usr/bin/env python3
"""Lumenfield — adaptive exposure intelligence for client briefs.

Authorized assessment and education service. Ships defensive checks
and remediation guidance. Does not include exploit payloads.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_file

from catalog import CATALOG
from report_pdf import build_brief
from inventory import record, summary
from nse import safe_pass
from scanner import local_network, scan

ROOT = Path(__file__).resolve().parent
APP = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
WATCH = ROOT / "data" / "watchlist.json"
LAST = ROOT / "data" / "last_scan.json"
HISTORY = ROOT / "data" / "scan_history.json"


def load_watch() -> dict:
    if WATCH.exists():
        return json.loads(WATCH.read_text())
    return {"watermark": "2026-09-20", "adopted": []}


@APP.route("/")
def index():
    return render_template("index.html", findings=CATALOG, today=date.today().isoformat())


@APP.route("/api/findings")
def findings():
    return jsonify(CATALOG)


@APP.route("/api/findings/<fid>")
def one(fid: str):
    for item in CATALOG:
        if item["id"] == fid:
            return jsonify(item)
    abort(404)


@APP.route("/api/report", methods=["POST"])
def report():
    body = request.get_json(silent=True) or {}
    client = (body.get("client") or "Northwind Partners").strip()[:80]
    prepared = (body.get("prepared") or "Lumenfield").strip()[:80]
    selected = body.get("ids") or [item["id"] for item in CATALOG]
    chosen = [item for item in CATALOG if item["id"] in selected]
    if not chosen:
        chosen = CATALOG
    scan_note = last_scan() if body.get("include_scan") else None
    out = ROOT / "briefs" / f"{date.today().isoformat()}-lumenfield-brief.pdf"
    out.parent.mkdir(exist_ok=True)
    build_brief(out, client=client, prepared=prepared, findings=chosen, scan=scan_note)
    return send_file(out, as_attachment=True, download_name=out.name)


@APP.route("/api/network")
def network():
    return jsonify(local_network())


def load_history() -> list:
    if not HISTORY.exists():
        return []
    return json.loads(HISTORY.read_text())


def remember(result: dict) -> dict:
    previous = load_history()[:1]
    prior_keys = {f"{hit['host']}:{hit['port']}:{hit['id']}" for hit in (previous[0].get("findings") or [])} if previous else set()
    keys = {f"{hit['host']}:{hit['port']}:{hit['id']}" for hit in result.get("findings", [])}
    result["delta"] = {
        "new": sorted(keys - prior_keys),
        "cleared": sorted(prior_keys - keys),
        "compared_with": previous[0].get("scanned_at") if previous else None,
    }
    receipt = {
        "scanned_at": result.get("scanned_at"),
        "cidr": result.get("cidr"),
        "clear": result.get("clear"),
        "hosts_considered": result.get("hosts_considered"),
        "services": len(result.get("observations") or []),
        "matches": len(result.get("findings") or []),
        "findings": result.get("findings") or [],
    }
    history = [receipt, *load_history()][:8]
    HISTORY.parent.mkdir(exist_ok=True)
    HISTORY.write_text(json.dumps(history, indent=2))
    LAST.write_text(json.dumps(result, indent=2))
    return result


@APP.route("/api/history")
def history():
    return jsonify(load_history())


def last_scan() -> dict | None:
    if not LAST.exists():
        return None
    return json.loads(LAST.read_text())


@APP.route("/api/scan", methods=["GET"])
def saved_scan():
    return jsonify(last_scan() or {})


@APP.route("/api/scan", methods=["POST"])
def run_scan():
    body = request.get_json(silent=True) or {}
    cidr = (body.get("cidr") or local_network()["cidr"]).strip()
    try:
        result = scan(cidr, confirmed=bool(body.get("confirmed")))
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    LAST.parent.mkdir(exist_ok=True)
    result = remember(result)
    result["nse"] = safe_pass(result.get("observations") or [])
    try:
        result["devices"] = record(result)
    except Exception as exc:
        result["devices"] = {"ok": False, "error": "MySQL is not reachable. Start docker compose up, then scan again."}
    return jsonify(result)


@APP.route("/api/devices")
def devices():
    try:
        return jsonify(summary())
    except Exception:
        return jsonify({"ok": False, "connected_now": 0, "known": 0, "devices": [], "error": "MySQL is not reachable yet."})


@APP.route("/api/intake", methods=["POST"])
def intake():
    """Record an analyst adoption. Optional live fetch of public KEV metadata."""
    body = request.get_json(silent=True) or {}
    watch = load_watch()
    note = {
        "cve": (body.get("cve") or "UNFILED")[:32],
        "note": (body.get("note") or "Analyst adopted from public feed")[:240],
        "on": date.today().isoformat(),
    }
    watch.setdefault("adopted", []).insert(0, note)
    watch["adopted"] = watch["adopted"][:40]
    WATCH.parent.mkdir(exist_ok=True)
    WATCH.write_text(json.dumps(watch, indent=2))
    return jsonify(watch)


@APP.route("/api/watch")
def watch():
    return jsonify(load_watch())


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=8765, debug=False)
