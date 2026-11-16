# Phase 5: Reporting & Deliverables Runbook

Once testing is complete, Reconix generates executive and technical deliverables summarizing results.

## 1. Generating & Downloading Reports with `rcx.py`

Request report compilation and download the output deliverable:

```bash
# 1. Trigger compilation
python3 scripts/rcx.py report --assessment-id "<assessment-id>" --format html
# Output: {"id": "rep_38a0c", "status": "COMPLETED"}

# 2. Download compiled deliverable
python3 scripts/rcx.py report \
  --download-id "rep_38a0c" \
  --output "reports/assessment-report.html"
```

Supported formats: `html`, `pdf`, `json`.

---

## 2. Report Structure

The generated report contains:
- **Executive Summary**: High-level risk posture, count of vulnerabilities by severity, overall risk score.
- **Assessment Scope & Window**: Target IPs/CIDRs, approved time boundaries, tools utilized.
- **Technical Findings Detail**:
  - Finding Title, Severity, CVSS v3 score, and CWE ID.
  - Affected endpoint / port / asset.
  - Masked reproduction evidence.
  - Actionable remediation instructions.
- **Methodology & Audit**: Total actions executed, approval history, Kali tool execution log.

---

## 3. Secret Sanitization Check

Before delivering the report to the client:
- Verify that API keys, passwords, and session tokens appear as `[MASKED:api_key]`, `[MASKED:password]`, or `[MASKED:token]`.
- Ensure no raw internal network credentials leaked into the report text.
