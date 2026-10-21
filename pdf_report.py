"""PDF renderer for paid ObsidianCyber Exposure Briefs."""
from __future__ import annotations

import io
import json
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

INK = colors.HexColor("#111827")
DARK = colors.HexColor("#111820")
TEAL = colors.HexColor("#11D9C5")
PALE = colors.HexColor("#E8F8F6")
MUTED = colors.HexColor("#586575")
LINE = colors.HexColor("#D9E2E8")


def _value(value, empty="No disponible"):
    if value is None or value == "":
        return empty
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _p(value, style, empty="No disponible"):
    raw = _value(value, empty)
    safe = escape(raw).replace("\r\n", "\n").replace("\n", "<br/>")
    return Paragraph(safe, style)


def _kv(label, value, styles):
    return Paragraph(f"<b>{escape(str(label))}</b>: {escape(_value(value))}", styles["BodySmall"])


def _table(rows, widths=None, header=True):
    if not rows:
        return Paragraph("No hay datos disponibles para esta sección.", getSampleStyleSheet()["BodyText"])
    normal = ParagraphStyle("Cell", fontName="Helvetica", fontSize=8.2, leading=11, textColor=INK, spaceAfter=1)
    head = ParagraphStyle("CellHead", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white)
    converted = []
    for ri, row in enumerate(rows):
        converted.append([Paragraph(escape(_value(cell, "—")), head if header and ri == 0 else normal) for cell in row])
    tab = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        commands += [("BACKGROUND", (0, 0), (-1, 0), DARK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        if len(rows) > 1:
            commands.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8FA")]))
    else:
        commands.append(("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F5F8FA")]))
    tab.setStyle(TableStyle(commands))
    return tab


def build_paid_report_pdf(report: dict) -> bytes:
    """Render a report dict returned by the server's verified paid-report flow."""
    if not isinstance(report, dict):
        raise ValueError("El informe no tiene un formato válido.")
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("OC_Title", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=DARK, alignment=TA_LEFT, spaceAfter=4))
    styles.add(ParagraphStyle("OC_Subtitle", parent=styles["Normal"], fontSize=10, leading=14, textColor=MUTED, spaceAfter=8))
    styles.add(ParagraphStyle("OC_Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=DARK, spaceBefore=12, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle("OC_Body", parent=styles["BodyText"], fontSize=9, leading=13, textColor=INK, spaceAfter=5))
    styles.add(ParagraphStyle("BodySmall", parent=styles["BodyText"], fontSize=8, leading=11, textColor=INK, spaceAfter=3))
    styles.add(ParagraphStyle("OC_Label", parent=styles["Normal"], fontSize=8, leading=10, textColor=MUTED))

    def draw_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(DARK)
        canvas.rect(0, h - 15 * mm, w, 15 * mm, fill=1, stroke=0)
        canvas.setFillColor(TEAL)
        canvas.rect(0, h - 15 * mm, 3 * mm, 15 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(16 * mm, h - 9.5 * mm, "OBSIDIAN CYBER")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - 16 * mm, h - 9.5 * mm, "EXPOSURE BRIEF · PAGO CONFIRMADO")
        canvas.setStrokeColor(LINE)
        canvas.line(16 * mm, 13 * mm, w - 16 * mm, 13 * mm)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(16 * mm, 8 * mm, "Confidencial · Evidencia observada en la fecha indicada · Alcance limitado DNS/TLS")
        canvas.drawRightString(w - 16 * mm, 8 * mm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=23*mm, bottomMargin=19*mm, title="ObsidianCyber Exposure Brief", author="ObsidianCyber")
    story = []
    domain = report.get("domain", "Dominio no disponible")
    story.extend([
        Paragraph("Ficha de exposición digital", styles["OC_Title"]),
        Paragraph(f"Activo evaluado: {escape(_value(domain))}", styles["OC_Subtitle"]),
        Paragraph("PAGO CONFIRMADO · INFORME COMERCIAL", ParagraphStyle("paid", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#087F73"), spaceAfter=9)),
    ])
    if (report.get("commercial") or {}).get("domain_control") == "declared":
        story.append(Paragraph("Control del dominio: declarado por el cliente, no verificado técnicamente (sin registro DNS TXT).", styles["OC_Subtitle"]))
    summary_rows = [
        ["Referencia", _value(report.get("case_id")), "Generado", _value(report.get("generated_at"))],
        ["Score de atención TLS", ("—" if report.get("score") is None else f"{report.get('score')}/100"), "Alcance", _value(report.get("scope", "DNS + comprobaciones HTTPS/TLS limitadas"))],
        ["Comprobaciones TLS", f"{_value(report.get('tls_checks_performed', 0))} / {_value(len(report.get('addresses') or []))}", "Hallazgos TLS", str(len(report.get("findings") or []))],
        ["Reputación", f"{_value(report.get('reputation_checks_performed', 0))} / {_value(report.get('reputation_checks_limit', 4))} consultas", "Señales reputación", str(len(report.get("reputation_findings") or []))],
    ]
    story.append(_table(summary_rows, widths=[33*mm, 48*mm, 29*mm, 58*mm], header=False))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Confianza, cobertura y límites", styles["OC_Section"]))
    story.append(_p(report.get("confidence_summary", "La confianza depende de las fuentes y del alcance limitado de las comprobaciones."), styles["OC_Body"]))
    story.append(_p("El score refleja únicamente las reglas TLS aplicadas en esta ejecución; no es una puntuación global de seguridad ni un veredicto de reputación. La ausencia de señales no demuestra que un activo sea seguro.", styles["OC_Body"]))

    dns = report.get("dns") or {}
    story.append(Paragraph("Resolución DNS", styles["OC_Section"]))
    story.append(_table([["Estado", "Fuente", "Observado", "Detalle"], [_value(dns.get("status")), _value(dns.get("source")), _value(dns.get("observed_at")), _value(dns.get("message"))]], widths=[23*mm, 38*mm, 35*mm, 72*mm]))

    story.append(Paragraph("Direcciones IP y comprobaciones", styles["OC_Section"]))
    addresses = report.get("addresses") or []
    if addresses:
        rows = [["IP / versión", "Geolocalización / ASN", "HTTPS / TLS", "Score / certificado", "Reputación"]]
        for item in addresses:
            geo = item.get("geolocation") or {}
            tls = item.get("tls") or {}
            rep = item.get("reputation") or {}
            location = ", ".join(str(x) for x in (geo.get("city"), geo.get("region"), geo.get("country")) if x) or _value(geo.get("status"), "Sin dato")
            asn = " · ".join(str(x) for x in (geo.get("asn"), geo.get("asn_org")) if x) or "ASN no disponible"
            loc_asn = location + "\n" + asn
            tls_status = _value(tls.get("status"))
            tls_expiry = _value(tls.get("not_after"))
            score = "—" if item.get("score") is None else f"{item.get('score')}/100"
            rep_info = _value(rep.get("status"))
            if rep.get("status") == "available":
                rep_info += "\nAbuse confidence: " + _value(rep.get("abuse_confidence_score"))
            rows.append([f"{_value(item.get('ip'))}\n{_value(item.get('version'), '')}", loc_asn, tls_status, f"{score}\nExpira: {tls_expiry}", rep_info])
        story.append(_table(rows, widths=[27*mm, 43*mm, 31*mm, 36*mm, 31*mm]))
    else:
        story.append(Paragraph("No se obtuvieron direcciones públicas utilizables en esta ejecución.", styles["OC_Body"]))

    story.append(Paragraph("Hallazgos TLS priorizados", styles["OC_Section"]))
    findings = report.get("findings") or []
    if findings:
        rows = [["Hallazgo", "Severidad / puntuación", "Detalle", "Fuente"]]
        for item in findings:
            rows.append([_value(item.get("title", item.get("rule_id"))), _value(item.get("severity", item.get("points"))), _value(item.get("detail", item.get("description", item.get("rationale")))), _value(item.get("source"))])
        story.append(_table(rows, widths=[39*mm, 31*mm, 67*mm, 31*mm]))
    else:
        story.append(Paragraph("No se registraron hallazgos TLS priorizados en los datos devueltos por esta ejecución.", styles["OC_Body"]))

    story.append(Paragraph("Metodología de puntuación", styles["OC_Section"]))
    story.append(_p(report.get("score_methodology", "La puntuación se limita a las señales incluidas en las reglas configuradas."), styles["OC_Body"]))
    breakdown = report.get("score_breakdown") or []
    if breakdown:
        rows = [["Regla", "Puntos", "Justificación", "IP", "Fuente"]]
        for item in breakdown:
            rows.append([_value(item.get("title", item.get("rule_id"))), _value(item.get("points")), _value(item.get("rationale")), _value(item.get("ip")), _value(item.get("source"))])
        story.append(_table(rows, widths=[34*mm, 17*mm, 64*mm, 25*mm, 28*mm]))
    rules = report.get("score_rules") or []
    if rules:
        story.append(Spacer(1, 4))
        story.append(Paragraph("Reglas activas", styles["OC_Label"]))
        for rule in rules:
            story.append(_kv(f"{_value(rule.get('id'))} · {_value(rule.get('condition'))}", f"{_value(rule.get('points'))} puntos · {_value(rule.get('meaning'))}", styles))

    rep_findings = report.get("reputation_findings") or []
    if rep_findings:
        story.append(Paragraph("Señales de reputación (separadas del score TLS)", styles["OC_Section"]))
        rows = [["Señal", "IP", "Fuente", "Detalle"]]
        for item in rep_findings:
            rows.append([_value(item.get("title", item.get("type", "Señal"))), _value(item.get("ip")), _value(item.get("source")), _value(item.get("detail", item.get("message", item.get("rationale"))))])
        story.append(_table(rows, widths=[35*mm, 30*mm, 36*mm, 67*mm]))

    story.append(Paragraph("Cronología de evidencias", styles["OC_Section"]))
    timeline = report.get("timeline") or []
    if timeline:
        rows = [["Fecha / UTC", "Evento", "Confianza", "Fuente y detalle"]]
        for item in timeline:
            rows.append([_value(item.get("timestamp")), _value(item.get("title")), _value(item.get("confidence")), _value(item.get("source")) + "\n" + _value(item.get("detail"))])
        story.append(_table(rows, widths=[28*mm, 40*mm, 28*mm, 72*mm]))
    else:
        story.append(Paragraph("No hay eventos de evidencia disponibles para esta ejecución.", styles["OC_Body"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Nota de uso", styles["OC_Section"]))
    story.append(Paragraph("Este documento resume observaciones técnicas obtenidas en la fecha indicada mediante resolución DNS y comprobaciones HTTPS/TLS limitadas. Los datos pueden cambiar. No sustituye una auditoría completa, una prueba de penetración ni una verificación de titularidad legal del activo.", styles["OC_Body"]))
    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return output.getvalue()
