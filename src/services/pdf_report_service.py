from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any

from src.models.event import Event
from src.models.event_group import EventGroup
from src.services.report_event_selector import (
    load_report_config,
    select_representative_events_for_report,
)


def generate_pdf_report(
    groups: list[EventGroup],
    ai_analyses: dict[int, str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> bytes:
    """Generate a simple English PDF report for selected groups."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        PageBreak,
    )

    ai_analyses = ai_analyses or {}
    metadata = metadata or {}
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
    )
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Windows Forensic Timeline Analysis Report", styles["Title"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1. Report metadata", styles["Heading2"]))
    ai_used = bool(ai_analyses)
    metadata_rows = [
        ["Generated at", metadata.get("generated_at", datetime.now().isoformat(sep=" ", timespec="seconds"))],
        ["Input directory", metadata.get("input_dir", "-")],
        ["Analyzed artifacts", "Browser History, Prefetch, MFT"],
        ["Selected groups", str(len(groups))],
        ["AI model used", metadata.get("ai_model", "-") if ai_used else "No AI analysis included"],
        ["Note", "AI analysis is auxiliary and does not modify deterministic grouping."],
    ]
    story.append(_kv_table(metadata_rows))
    story.append(Spacer(1, 12))

    story.append(Paragraph("2. Selected activity groups", styles["Heading2"]))
    report_config = load_report_config()
    max_representative_events = int(report_config.get("max_representative_events", 25))
    for idx, group in enumerate(groups, start=1):
        if idx > 1:
            story.append(PageBreak())
        story.append(Paragraph(f"Group {idx}: {_esc(group.short_title)}", styles["Heading3"]))
        story.append(_kv_table([
            ["Time interval", _time_interval(group.events)],
            ["Confidence", group.confidence],
            ["Sources", ", ".join(sorted({e.source for e in group.events}))],
            ["Activity family", group.activity_family_estimate],
            ["Important applications", ", ".join(group.important_apps) if group.important_apps else "-"],
            ["Events", f"{group.core_event_count} core / {group.support_event_count} support"],
        ]))
        story.append(Spacer(1, 8))

        story.append(Paragraph("Deterministic summary", styles["Heading4"]))
        story.append(Paragraph(_deterministic_summary(group), styles["BodyText"]))
        story.append(Spacer(1, 6))

        story.append(Paragraph("Key events", styles["Heading4"]))
        representative_events = select_representative_events_for_report(
            group,
            max_events=max_representative_events,
        )
        story.append(_events_table(representative_events))
        if len(representative_events) < len(group.events):
            story.append(Paragraph(
                "Only representative events are shown. "
                f"The full group contains {group.core_event_count} core events and "
                f"{group.support_event_count} support events.",
                styles["BodyText"],
            ))
        story.append(Spacer(1, 6))

        story.append(Paragraph("Findings", styles["Heading4"]))
        if group.findings:
            for finding in group.findings:
                story.append(Paragraph(
                    f"- {_esc(finding.rule_name)}: {_esc(finding.explanation)}",
                    styles["BodyText"],
                ))
        else:
            story.append(Paragraph("No deterministic findings for this group.", styles["BodyText"]))

        analysis = ai_analyses.get(id(group))
        if analysis:
            story.append(Spacer(1, 6))
            story.append(Paragraph("AI interpretation", styles["Heading4"]))
            for line in analysis.splitlines():
                if line.strip():
                    story.append(Paragraph(_esc(line.strip()), styles["BodyText"]))

    story.append(PageBreak())
    story.append(Paragraph("3. Limitations", styles["Heading2"]))
    story.append(Paragraph(
        "The grouping is based on temporal proximity and artifact type. "
        "Some Windows background activity may appear in the timeline. "
        "AI-generated text is only an auxiliary interpretation and may require human validation.",
        styles["BodyText"],
    ))

    doc.build(story)
    return buffer.getvalue()


def _kv_table(rows: list[list[str]]):
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Table, TableStyle

    table = Table(rows, colWidths=[4.2 * cm, 12 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _events_table(events: list[Event]):
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet

    styles = getSampleStyleSheet()
    rows = [["Time", "Role", "Source", "Type", "Description"]]
    key_events = sorted(events, key=lambda e: e.timestamp)
    for event in key_events:
        rows.append([
            event.timestamp.strftime("%H:%M:%S"),
            event.raw_data.get("role", ""),
            event.source,
            event.event_type,
            Paragraph(_esc(event.description[:180]), styles["BodyText"]),
        ])

    table = Table(rows, colWidths=[2.1 * cm, 1.8 * cm, 2.0 * cm, 3.0 * cm, 7.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def _deterministic_summary(group: EventGroup) -> str:
    apps = ", ".join(group.important_apps) if group.important_apps else "no dominant application"
    return (
        f"{group.short_title}. The group spans {_time_interval(group)} and contains "
        f"{group.core_event_count} core events plus {group.support_event_count} supporting events. "
        f"It is classified as {group.activity_family_estimate}, with confidence {group.confidence}. "
        f"Important applications: {apps}."
    )


def _time_interval(events_or_group) -> str:
    events = events_or_group.events if hasattr(events_or_group, "events") else events_or_group
    if not events:
        return "-"
    timestamps = sorted(e.timestamp for e in events)
    return (
        f"{timestamps[0].isoformat(sep=' ', timespec='seconds')} - "
        f"{timestamps[-1].isoformat(sep=' ', timespec='seconds')}"
    )


def _esc(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
