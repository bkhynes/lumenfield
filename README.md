# Lumenfield

Adaptive exposure intelligence for client security briefs.

Lumenfield reads the connected private network, matches service banners to exploited product classes, and prints a client brief. A clear scan plays the field animation. A match gets the client line and the fix.

The scan is banner and certificate-name matching on loopback and private ranges only, after the operator confirms authorisation. It does not send exploit traffic.

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
- `scanner.py` — private-range banner scan
