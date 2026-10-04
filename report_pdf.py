"""Client brief PDF for Lumenfield. Visual, print-ready, no exploit detail."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.colors import Color, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas


INK = Color(0.04, 0.09, 0.08)
FIELD = Color(0.07, 0.16, 0.13)
LIME = Color(0.78, 1.0, 0.32)
MINT = Color(0.45, 0.86, 0.74)
SAND = Color(0.96, 0.94, 0.88)
CLAY = Color(0.93, 0.38, 0.30)
AMBER = Color(0.96, 0.72, 0.28)


def _wrap(c: canvas.Canvas, text: str, x: float, y: float, width: float, size: float, leading: float, color, font="Times-Roman"):
    c.setFillColor(color)
    c.setFont(font, size)
    words = text.split()
    line = ""
    for word in words:
        trial = word if not line else f"{line} {word}"
        if c.stringWidth(trial, font, size) <= width:
            line = trial
        else:
            c.drawString(x, y, line)
            y -= leading
            line = word
    if line:
        c.drawString(x, y, line)
        y -= leading
    return y


def build_brief(path: Path, client: str, prepared: str, findings: list[dict]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(path), pagesize=A4)
    c.setTitle(f"Lumenfield brief — {client}")
    c.setAuthor(prepared)
    w, h = A4

    def header():
        c.setFillColor(INK)
        c.rect(0, 0, w, h, fill=1, stroke=0)
        c.setFillColor(LIME)
        c.rect(0, h - 18 * mm, w, 18 * mm, fill=1, stroke=0)
        c.setFillColor(INK)
        c.setFont("Times-Bold", 11)
        c.drawString(16 * mm, h - 11 * mm, "LUMENFIELD")
        c.setFont("Times-Roman", 9)
        c.drawRightString(w - 16 * mm, h - 11 * mm, "Adaptive exposure brief")

    def footer(page: int):
        c.setFillColor(MINT)
        c.setFont("Times-Roman", 8)
        c.drawString(16 * mm, 10 * mm, f"{client}  ·  prepared by {prepared}")
        c.drawRightString(w - 16 * mm, 10 * mm, f"{page}")

    header()
    c.setFillColor(SAND)
    c.setFont("Times-Bold", 26)
    y = h - 36 * mm
    c.drawString(16 * mm, y, "The test has to move")
    y -= 10 * mm
    c.setFont("Times-Roman", 12)
    c.setFillColor(MINT)
    c.drawString(16 * mm, y, client)
    y -= 14 * mm
    y = _wrap(
        c,
        "A penetration test that cannot adopt a bug published this week is a photograph of last quarter. "
        "Lumenfield keeps a living board of exploited exposure classes, scores how relevant each one still is "
        "to this estate, and files the fix in language a client can act on. This brief is the leave-behind.",
        16 * mm,
        y,
        w - 32 * mm,
        11,
        15,
        SAND,
    )
    y -= 6 * mm
    avg = round(sum(f["relevance"] for f in findings) / max(len(findings), 1))
    kev = sum(1 for f in findings if f["cve"].startswith("CVE"))
    boxes = [
        (str(len(findings)), "Items on this brief"),
        (str(kev), "Mapped to public KEV"),
        (f"{avg}", "Mean relevance"),
    ]
    x = 16 * mm
    for value, label in boxes:
        c.setFillColor(FIELD)
        c.roundRect(x, y - 22 * mm, 56 * mm, 24 * mm, 4, fill=1, stroke=0)
        c.setFillColor(LIME)
        c.setFont("Times-Bold", 16)
        c.drawString(x + 4 * mm, y - 8 * mm, value)
        c.setFillColor(SAND)
        c.setFont("Times-Roman", 8)
        c.drawString(x + 4 * mm, y - 16 * mm, label)
        x += 60 * mm
    y -= 36 * mm
    y = _wrap(
        c,
        "Why evolving tests are the service. Edge appliances, VPNs, mail gateways, and support portals "
        "are re-exposed every time a vendor build lags or a management interface is published. "
        "CISA's Known Exploited Vulnerabilities list is the public queue. Lumenfield matches new rows "
        "to tagged assets, asks an analyst to confirm, and only then puts the item in front of the client. "
        "Automation files the lead. A person signs the brief.",
        16 * mm,
        y,
        w - 32 * mm,
        10,
        13,
        SAND,
    )
    footer(1)
    c.showPage()

    page = 2
    for finding in findings:
        header()
        y = h - 30 * mm
        c.setFillColor(LIME)
        c.setFont("Times-Bold", 9)
        c.drawString(16 * mm, y, finding["id"])
        c.setFillColor(AMBER)
        c.drawRightString(w - 16 * mm, y, f"Relevance {finding['relevance']}")
        y -= 8 * mm
        c.setFillColor(SAND)
        c.setFont("Times-Bold", 16)
        title = finding["title"]
        if c.stringWidth(title, "Times-Bold", 16) > w - 32 * mm:
            c.setFont("Times-Bold", 13)
        c.drawString(16 * mm, y, title[:78])
        y -= 7 * mm
        c.setFillColor(MINT)
        c.setFont("Times-Roman", 9)
        c.drawString(
            16 * mm,
            y,
            f"{finding['cve']}   ·   {finding['vendor']} {finding['product']}   ·   {finding['status']}",
        )
        y -= 12 * mm
        c.setFillColor(FIELD)
        c.roundRect(16 * mm, y - 28 * mm, w - 32 * mm, 32 * mm, 3, fill=1, stroke=0)
        c.setFillColor(LIME)
        c.setFont("Times-Bold", 8)
        c.drawString(20 * mm, y - 6 * mm, "IN THE CLIENT'S WORDS")
        c.setFillColor(SAND)
        _wrap(c, finding["client_line"], 20 * mm, y - 12 * mm, w - 40 * mm, 10, 13, SAND)
        y -= 40 * mm
        c.setFillColor(LIME)
        c.setFont("Times-Bold", 8)
        c.drawString(16 * mm, y, "WHY IT STILL MATTERS")
        y -= 6 * mm
        y = _wrap(c, finding["why_ongoing"], 16 * mm, y, w - 32 * mm, 10, 13, SAND)
        y -= 4 * mm
        c.setFillColor(LIME)
        c.setFont("Times-Bold", 8)
        c.drawString(16 * mm, y, "WHAT TO DO")
        y -= 6 * mm
        c.setFillColor(SAND)
        c.setFont("Times-Roman", 10)
        for step in finding["fix"]:
            y = _wrap(c, f"—  {step}", 16 * mm, y, w - 32 * mm, 10, 13, SAND)
            y -= 1 * mm
        y -= 4 * mm
        c.setFillColor(MINT)
        c.setFont("Times-Roman", 8)
        c.drawString(
            16 * mm,
            max(y, 18 * mm),
            f"Defensive check shipped: {finding['check_name']}  ·  no exploit payload is included.",
        )
        footer(page)
        page += 1
        c.showPage()

    header()
    y = h - 32 * mm
    c.setFillColor(SAND)
    c.setFont("Times-Bold", 16)
    c.drawString(16 * mm, y, "How the library grows")
    y -= 12 * mm
    y = _wrap(
        c,
        "Each week the intake reads the public CISA KEV JSON feed and compares dateAdded with the engagement watermark. "
        "New rows that match a tagged vendor become analyst tasks. The analyst writes the client line, attaches a defensive "
        "check, and sets relevance. Relevance falls when the fixed build is attested on every node, and stays high when "
        "a management plane is still public or a past-due item has no evidence. That loop is the product.",
        16 * mm,
        y,
        w - 32 * mm,
        11,
        15,
        SAND,
    )
    y -= 8 * mm
    c.setFillColor(LIME)
    c.setFont("Times-Bold", 9)
    c.drawString(16 * mm, y, "ENGAGEMENT BOUNDARY")
    y -= 6 * mm
    y = _wrap(
        c,
        "Lumenfield is an authorised assessment and education service. Checks read local posture, version attestations, "
        "and public advisory metadata. They do not exploit vulnerabilities, scan third parties without permission, "
        "or include proof-of-concept attack scripts. Closure requires evidence, not a verbal all-clear.",
        16 * mm,
        y,
        w - 32 * mm,
        10,
        13,
        SAND,
    )
    footer(page)
    c.save()
    return path
