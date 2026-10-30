"""The report files: JSON, PDF and DOCX, made from one document.

Pure functions with no file or network access: each takes the document and
returns bytes, and the API saves them. The document is built from the locked
copy the API sent (findings, counts and tool runs, never changed) and the two
texts the model wrote. Every text in it is masked again before any file is made.
"""

import json
from io import BytesIO
from pathlib import Path
from typing import Any

from docx import Document
from jinja2 import Environment, FileSystemLoader, select_autoescape

from reconix_ai.contracts import SEVERITY_ORDER, severity_rank
from reconix_ai.harness import mask_secrets

TEMPLATE_DIR = Path(__file__).resolve().parent
TEMPLATES = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),  # every value is escaped in the HTML
)


def report_document(
    report: dict[str, Any], executive_summary: str, methodology: str, meta: dict[str, str]
) -> dict[str, Any]:
    """The whole report. meta is what the API knows, e.g. the assessment code,
    the version and the snapshot hash."""
    counts = report["severity_counts"]
    unknown = set(counts) - set(SEVERITY_ORDER)
    if unknown:
        raise ValueError(f"Unknown severities in the counts: {sorted(unknown)}")
    document = {
        "meta": meta,
        "executive_summary": executive_summary,
        "methodology": methodology,
        "severity_counts": {level: counts.get(level, 0) for level in SEVERITY_ORDER},
        "findings": sorted(report["findings"], key=severity_rank),
        "tool_runs": report["tool_runs"],
    }
    return masked(document)


def masked(value: Any) -> Any:
    """The same value with every string in it masked, however deep."""
    if isinstance(value, str):
        return mask_secrets(value)[0]
    if isinstance(value, dict):
        return {key: masked(item) for key, item in value.items()}
    if isinstance(value, list):
        return [masked(item) for item in value]
    return value


def to_json(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")


def to_html(document: dict[str, Any]) -> str:
    return TEMPLATES.get_template("report.html").render(**document, levels=SEVERITY_ORDER)


def to_pdf(document: dict[str, Any]) -> bytes:
    # Imported here: WeasyPrint needs the Pango system library, and only the
    # report needs it, so nothing else fails on a machine without it.
    from weasyprint import HTML

    return HTML(string=to_html(document), url_fetcher=refuse_fetch).write_pdf()


def refuse_fetch(url: str, *args: Any, **kwargs: Any) -> Any:
    """A report never loads anything: no image, font or style from a file or the web."""
    raise ValueError(f"A report file never loads {url!r}.")


def to_docx(document: dict[str, Any]) -> bytes:
    doc = Document()
    doc.add_heading(document["meta"].get("title", "Reconix assessment report"), level=0)
    for name, value in document["meta"].items():
        if name != "title":
            doc.add_paragraph(f"{name}: {value}")
    doc.add_heading("Executive summary", level=1)
    doc.add_paragraph(document["executive_summary"])
    doc.add_heading("Findings by severity", level=1)
    add_table(doc, ["Severity", "Findings"], document["severity_counts"].items())
    doc.add_heading("Methodology", level=1)
    doc.add_paragraph(document["methodology"])
    doc.add_heading("Findings", level=1)
    for finding in document["findings"]:
        add_finding(doc, finding)
    doc.add_heading("Tool runs", level=1)
    rows = [
        (
            run["tool"],
            run["target"],
            " ".join(run["args"]),
            run["risk_level"],
            run["approval_check"],
        )
        for run in document["tool_runs"]
    ]
    add_table(doc, ["Tool", "Target", "Options", "Risk", "Approval"], rows)
    out = BytesIO()
    doc.save(out)
    return out.getvalue()


def add_finding(doc: Any, finding: dict[str, Any]) -> None:
    doc.add_heading(f"{finding['code']} {finding['title']}", level=2)
    doc.add_paragraph(f"Severity: {finding['severity_status']}   Target: {finding['target']}")
    doc.add_paragraph(finding["description"])
    ids = finding["cwe_ids"] + finding["owasp_id"] + finding["cve_ids"]
    if ids:
        doc.add_paragraph("References: " + ", ".join(ids))


def add_table(doc: Any, header: list[str], rows: Any) -> None:
    table = doc.add_table(rows=1, cols=len(header))
    table.style = "Table Grid"
    for cell, text in zip(table.rows[0].cells, header, strict=True):
        cell.text = text
    for row in rows:
        for cell, value in zip(table.add_row().cells, row, strict=True):
            cell.text = str(value)
