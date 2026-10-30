"""The report files, made by the AI Service's reports package.

Like core/agent.py for the agent, this is the one place the API reaches into
reconix_ai for files. The bytes come back; services/reports.py saves them.
"""

from typing import Any

from reconix_ai.reports import files

FORMATS = {"PDF": "pdf", "DOCX": "docx", "JSON": "json"}  # format -> file extension
MEDIA_TYPES = {
    "PDF": "application/pdf",
    "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "JSON": "application/json",
}


def render(
    snapshot: dict[str, Any], executive_summary: str, methodology: str, meta: dict[str, str]
) -> dict[str, bytes]:
    """The 3 files, by format. Every text in them is masked again by reconix_ai."""
    document = files.report_document(snapshot, executive_summary, methodology, meta)
    return {
        "PDF": files.to_pdf(document),
        "DOCX": files.to_docx(document),
        "JSON": files.to_json(document),
    }
