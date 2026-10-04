# Lumenfield

Adaptive exposure intelligence for client security briefs.

Lumenfield is a service console, not an exploit kit. It keeps a living board of currently relevant exposure classes, explains why each one still matters, ships a defensive check or hardening pattern, and prints a visual PDF a client can keep.

New tests are adopted from the public [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feed. Automation files the lead. An analyst confirms it before it reaches the client.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:8765

## What you will not find here

No proof-of-concept exploits, payloads, or attack traffic. Checks are local posture, version attestation, and public advisory intake.

## Layout

- `app.py` — service
- `catalog.py` — current board
- `report_pdf.py` — client brief
- `templates/` `static/` — briefing UI
- `ingest/kev_sync.py` — public KEV watermark
