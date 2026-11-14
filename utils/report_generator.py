"""
utils/report_generator.py
----------------------------
Generates downloadable CSV and PDF reports for password analyses, URL
analyses, and the overall security dashboard.
"""

import csv
import html
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer


def generate_password_csv(analyses) -> io.BytesIO:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Date", "Length", "Entropy", "Strength Score", "Category", "ML Prediction",
        "Dictionary Word", "Keyboard Pattern", "Repeated Chars", "Sequential Chars",
        "Estimated Crack Time",
    ])
    for a in analyses:
        writer.writerow([
            a.created_at.strftime("%Y-%m-%d %H:%M"), a.password_length, a.entropy,
            a.strength_score, a.strength_category, a.ml_prediction or "-",
            a.is_dictionary_word, a.is_keyboard_pattern, a.has_repeated_chars,
            a.has_sequential_chars, a.estimated_crack_time_display or "-",
        ])
    out = io.BytesIO(buffer.getvalue().encode("utf-8"))
    out.seek(0)
    return out


def generate_url_csv(analyses) -> io.BytesIO:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Date", "URL", "Domain", "Verdict", "Confidence", "Threat Level",
        "HTTPS", "IP Address", "Shortened", "Suspicious Keywords",
    ])
    for a in analyses:
        writer.writerow([
            a.created_at.strftime("%Y-%m-%d %H:%M"), _safe_csv_cell(a.url), a.domain, a.verdict,
            f"{a.confidence}%", a.threat_level, a.uses_https, a.has_ip_address,
            a.is_shortened, a.has_suspicious_keywords,
        ])
    out = io.BytesIO(buffer.getvalue().encode("utf-8"))
    out.seek(0)
    return out


def _safe_csv_cell(value):
    """Prevent spreadsheet formula execution for user-controlled CSV cells."""
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def generate_network_scan_pdf(scan, findings) -> io.BytesIO:
    """Build a bounded scan report that labels version matches as potential."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch
    )
    styles = _pdf_styles()
    story = [
        Paragraph("BastionIX - Network Assessment Report", styles["ReportTitle"]),
        Paragraph(f"Scan ID: {scan.id}", styles["Normal"]),
        Paragraph(f"Authorized target: {html.escape(scan.target)}", styles["Normal"]),
        Paragraph(f"Status: {html.escape(scan.status)}", styles["Normal"]),
        Paragraph(f"Created: {scan.created_at.isoformat()}", styles["Normal"]),
        Paragraph(
            "CVE version matches are potential matches, not proof of vulnerability or exploitability.",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("Findings", styles["SectionHeading"]),
    ]
    rows = [["Host:Port", "Type / CVE", "Severity / CVSS", "Details / Remediation"]]
    for finding in findings:
        port = finding.port
        location = f"{port.host.address}:{port.port}" if port else "Asset"
        details = (
            f"<b>{html.escape(finding.title)}</b><br/>"
            f"{html.escape(finding.description[:900])}<br/><br/>"
            f"<b>Remediation:</b> {html.escape(finding.remediation[:600])}"
        )
        rows.append([
            Paragraph(html.escape(location), styles["Normal"]),
            Paragraph(html.escape(finding.cve_id or finding.classification), styles["Normal"]),
            Paragraph(
                html.escape(
                    f"{finding.severity}"
                    + (
                        f" (CVSS {finding.cvss_version}: {finding.cvss_score})"
                        if finding.cvss_version and finding.cvss_score is not None
                        else ""
                    )
                ),
                styles["Normal"],
            ),
            Paragraph(details, styles["Normal"]),
        ])
    if len(rows) == 1:
        rows.append(["No findings recorded.", "", "", ""])
    table = Table(rows, colWidths=[95, 85, 65, 235], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#10243a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    return buffer


def _pdf_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=20, spaceAfter=14, textColor=colors.HexColor("#0b1f3a")))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=13, spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#0b6e4f")))
    return styles


def generate_security_pdf(stats: dict, recent_password, recent_url, username: str) -> io.BytesIO:
    """Builds an overall security summary PDF report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = _pdf_styles()
    story = []

    story.append(Paragraph("BastionIX - Security Report", styles["ReportTitle"]))
    story.append(Paragraph(f"Generated for: {html.escape(username)}", styles["Normal"]))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Summary Statistics", styles["SectionHeading"]))
    summary_data = [["Metric", "Value"]] + [[k, str(v)] for k, v in stats.items()]
    table = Table(summary_data, colWidths=[280, 200])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Recent Password Analyses", styles["SectionHeading"]))
    pwd_rows = [["Date", "Category", "Score", "Crack Time"]]
    for a in recent_password:
        pwd_rows.append([
            a.created_at.strftime("%Y-%m-%d %H:%M"), a.strength_category,
            f"{a.strength_score}/100", a.estimated_crack_time_display or "-",
        ])
    if len(pwd_rows) > 1:
        t = Table(pwd_rows, colWidths=[120, 120, 100, 140])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b6e4f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No password analyses yet.", styles["Normal"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Recent URL Analyses", styles["SectionHeading"]))
    url_rows = [["Date", "Domain", "Verdict", "Threat Level"]]
    for a in recent_url:
        url_rows.append([
            a.created_at.strftime("%Y-%m-%d %H:%M"), (a.domain or "-")[:30], a.verdict, a.threat_level,
        ])
    if len(url_rows) > 1:
        t2 = Table(url_rows, colWidths=[120, 160, 100, 100])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b6e4f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No URL analyses yet.", styles["Normal"]))

    doc.build(story)
    buffer.seek(0)
    return buffer
