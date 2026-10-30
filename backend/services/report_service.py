from io import BytesIO
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

from backend.services.evidence_service import list_scan_evidence
from backend.services.scan_service import (
    get_scan,
    list_scan_endpoints,
    list_scan_findings,
)
from backend.services.target_service import get_target


OWASP_CATEGORIES = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#991B1B"),
    "HIGH": colors.HexColor("#DC2626"),
    "MEDIUM": colors.HexColor("#D97706"),
    "LOW": colors.HexColor("#2563EB"),
    "INFO": colors.HexColor("#64748B"),
}


def _safe(value):
    """Escape dynamic values before rendering them as PDF paragraphs."""
    return escape(str(value if value is not None else "N/A"))


def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        fontSize=27,
        leading=33,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#163A5F"),
        spaceAfter=12,
    ))

    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading1"],
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#163A5F"),
        spaceBefore=12,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        alignment=TA_LEFT,
    ))

    styles.add(ParagraphStyle(
        name="FindingTitle",
        parent=styles["Heading3"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#163A5F"),
        spaceBefore=6,
        spaceAfter=4,
    ))

    return styles


def _draw_page(canvas, document):
    canvas.saveState()

    width, height = A4

    canvas.setStrokeColor(colors.HexColor("#DCE5EE"))
    canvas.line(18 * mm, 15 * mm, width - 18 * mm, 15 * mm)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))

    canvas.drawString(
        18 * mm,
        10 * mm,
        "ACCESSLENS | API SECURITY ASSESSMENT"
    )

    canvas.drawRightString(
        width - 18 * mm,
        10 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


def _section(title, styles):
    return Paragraph(title, styles["SectionTitle"])


def _build_severity_table(findings):
    counts = {
        severity: 0
        for severity in SEVERITY_ORDER
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")

        if severity in counts:
            counts[severity] += 1

    data = [
        ["Severity", "Findings"]
    ]

    for severity in SEVERITY_ORDER:
        data.append([
            severity,
            str(counts[severity])
        ])

    table = Table(
        data,
        colWidths=[90 * mm, 50 * mm],
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#163A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4,
         colors.HexColor("#DCE5EE")),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))

    return table


def generate_vapt_report(scan_id: str) -> bytes:
    """
    Generate an evidence-backed VAPT PDF for an existing scan.

    Returns:
        PDF document as bytes.
    """

    scan = get_scan(scan_id)

    if not scan:
        raise ValueError("Scan not found.")

    if scan.get("status") != "COMPLETED":
        raise ValueError(
            "A final report can only be generated for a completed scan."
        )

    target_id = scan.get("target_id")
    target = get_target(target_id) if target_id else None
    target_url = (
        target.get("target_url", "Unknown target")
        if target
        else "Unknown target"
    )

    finding_result = list_scan_findings(scan_id) or {}
    endpoint_result = list_scan_endpoints(scan_id) or []

    findings = finding_result.get("findings", []) if isinstance(finding_result, dict) else finding_result
    endpoints = endpoint_result.get("endpoints", []) if isinstance(endpoint_result, dict) else endpoint_result
    evidence_records = list_scan_evidence(scan_id) or []

    evidence_by_id = {
        item["evidence_id"]: item
        for item in evidence_records
    }
    evidence_by_id = {
        item["evidence_id"]: item
        for item in evidence_records
    }

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=22 * mm,
        title=f"AccessLens VAPT Report - {scan_id}",
        author="AccessLens",
    )

    styles = _build_styles()
    story = []

    # COVER PAGE
    story.append(Spacer(1, 35 * mm))

    story.append(Paragraph(
        "ACCESSLENS",
        styles["CoverTitle"]
    ))

    story.append(Paragraph(
        "API SECURITY ASSESSMENT REPORT",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 15 * mm))

    story.append(Paragraph(
        f"<b>Scan ID:</b> {_safe(scan_id)}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>Target:</b> {_safe(target_url)}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"<b>Generated:</b> {_safe(datetime.now(timezone.utc).isoformat())}",
        styles["BodyText"]
    ))

    story.append(Spacer(1, 15 * mm))

    story.append(Paragraph(
        "CONFIDENTIAL SECURITY ASSESSMENT",
        styles["Heading2"]
    ))

    story.append(PageBreak())

    # EXECUTIVE SUMMARY
    story.append(_section("1. Executive Summary", styles))

    status_counts = {
        "PASS": 0,
        "FAIL": 0,
        "INCONCLUSIVE": 0,
        "NOT_APPLICABLE": 0,
    }

    for finding in findings:
        status = finding.get("status")

        if status in status_counts:
            status_counts[status] += 1

    story.append(Paragraph(
        f"Assessment status: <b>{_safe(scan['status'])}</b>",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"Endpoints discovered: <b>{len(endpoints)}</b>",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        f"Findings recorded: <b>{len(findings)}</b>",
        styles["BodyText"]
    ))

    story.append(Spacer(1, 5 * mm))

    story.append(_build_severity_table(findings))

    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph(
        f"PASS: {status_counts['PASS']} | "
        f"FAIL: {status_counts['FAIL']} | "
        f"INCONCLUSIVE: {status_counts['INCONCLUSIVE']} | "
        f"NOT APPLICABLE: {status_counts['NOT_APPLICABLE']}",
        styles["BodyText"]
    ))

    story.append(Paragraph(
        "This report describes only the checks and evidence recorded "
        "for this scan. It does not imply that unexecuted security "
        "checks passed.",
        styles["BodyText"]
    ))

    # TARGET AND SCAN DETAILS
    story.append(_section("2. Assessment Details", styles))

    details = [
        ["Property", "Value"],
        ["Target URL", _safe(target_url)],
        ["Scan ID", _safe(scan_id)],
        ["Scan Status", _safe(scan["status"])],
        ["Endpoints", str(len(endpoints))],
        ["Evidence Records", str(len(evidence_records))],
    ]

    detail_table = Table(
        details,
        colWidths=[55 * mm, 110 * mm],
    )

    detail_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#163A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4,
         colors.HexColor("#DCE5EE")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))

    story.append(detail_table)

    # ENDPOINT INVENTORY
    story.append(_section("3. Discovered Endpoints", styles))

    endpoint_data = [
        ["Method", "Path", "Source"]
    ]

    for endpoint in endpoints:
        endpoint_data.append([
            _safe(endpoint.get("method")),
            Paragraph(
                _safe(endpoint.get("path")),
                styles["BodySmall"]
            ),
            _safe(endpoint.get("source")),
        ])

    endpoint_table = Table(
        endpoint_data,
        colWidths=[25 * mm, 105 * mm, 35 * mm],
        repeatRows=1,
    )

    endpoint_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#163A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4,
         colors.HexColor("#DCE5EE")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(endpoint_table)

    # FINDINGS
    story.append(_section("4. Security Findings", styles))

    if not findings:
        story.append(Paragraph(
            "No findings are currently recorded for this scan. "
            "This must not be interpreted as proof that the target "
            "is free of vulnerabilities.",
            styles["BodyText"]
        ))

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "INFO")
        evidence_id = finding.get("evidence_id")
        evidence = evidence_by_id.get(evidence_id)

        blocks = [
            Paragraph(
                f"{index}. {_safe(finding.get('title'))}",
                styles["FindingTitle"]
            ),
            Paragraph(
                f"<b>OWASP:</b> "
                f"{_safe(finding.get('owasp_id'))} - "
                f"{_safe(OWASP_CATEGORIES.get(finding.get('owasp_id'), 'Unknown category'))}",
                styles["BodySmall"]
            ),
            Paragraph(
                f"<b>Severity:</b> {_safe(severity)}",
                styles["BodySmall"]
            ),
            Paragraph(
                f"<b>Status:</b> {_safe(finding.get('status'))}",
                styles["BodySmall"]
            ),
            Paragraph(
                f"<b>Confidence:</b> {_safe(finding.get('confidence'))}",
                styles["BodySmall"]
            ),
            Paragraph(
                f"<b>Endpoint:</b> {_safe(finding.get('method'))} "
                f"{_safe(finding.get('endpoint'))}",
                styles["BodySmall"]
            ),
            Paragraph(
                f"<b>Rationale:</b> {_safe(finding.get('rationale'))}",
                styles["BodySmall"]
            ),
            Paragraph(
                f"<b>Remediation:</b> {_safe(finding.get('remediation'))}",
                styles["BodySmall"]
            ),
        ]

        if evidence:
            request_data = evidence.get("request", {})
            response_data = evidence.get("response", {})

            blocks.append(Paragraph(
                f"<b>Evidence ID:</b> {_safe(evidence_id)}",
                styles["BodySmall"]
            ))

            blocks.append(Paragraph(
                f"<b>Request:</b> {_safe(request_data.get('method'))} "
                f"{_safe(request_data.get('url'))}",
                styles["BodySmall"]
            ))

            blocks.append(Paragraph(
                f"<b>Response status:</b> "
                f"{_safe(response_data.get('status_code'))}",
                styles["BodySmall"]
            ))

            blocks.append(Paragraph(
                f"<b>Evidence notes:</b> {_safe(evidence.get('notes'))}",
                styles["BodySmall"]
            ))

        story.append(KeepTogether(blocks))
        story.append(Spacer(1, 4 * mm))

    # OWASP COVERAGE
    story.append(PageBreak())
    story.append(_section("5. OWASP API Security Top 10 Coverage", styles))

    story.append(Paragraph(
        "Coverage below is derived from recorded findings. "
        "A category without a recorded result is marked NOT ASSESSED, "
        "not PASS.",
        styles["BodyText"]
    ))

    coverage_data = [
        ["OWASP ID", "Category", "Recorded status"]
    ]

    for owasp_id, category in OWASP_CATEGORIES.items():
        category_findings = [
            item for item in findings
            if item.get("owasp_id") == owasp_id
        ]

        if category_findings:
            statuses = sorted({
                item.get("status", "INCONCLUSIVE")
                for item in category_findings
            })
            result = ", ".join(statuses)
        else:
            result = "NOT ASSESSED"

        coverage_data.append([
            owasp_id,
            Paragraph(_safe(category), styles["BodySmall"]),
            result,
        ])

    coverage_table = Table(
        coverage_data,
        colWidths=[25 * mm, 105 * mm, 35 * mm],
        repeatRows=1,
    )

    coverage_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#163A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4,
         colors.HexColor("#DCE5EE")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(coverage_table)

    # LIMITATIONS
    story.append(_section("6. Assessment Limitations", styles))

    story.append(Paragraph(
        "This report is based on the endpoints, checks, findings, "
        "and evidence available in the AccessLens backend at report "
        "generation time. Categories marked NOT ASSESSED were not "
        "verified by this report. Categories marked INCONCLUSIVE "
        "require additional authorization, identities, business "
        "context, or testing infrastructure.",
        styles["BodyText"]
    ))

    story.append(Spacer(1, 10 * mm))

    story.append(Paragraph(
        "Generated by AccessLens | HackFusion 2.0",
        styles["BodyText"]
    ))

    document.build(
        story,
        onFirstPage=_draw_page,
        onLaterPages=_draw_page,
    )

    return buffer.getvalue()