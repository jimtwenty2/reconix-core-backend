# Phase 4: Findings Triage Runbook

Raw scanner output from tools (`nmap`, `nuclei`, `nikto`, etc.) is normalized into structured findings by Reconix parsers.

## 1. Querying Findings with `rcx.py`

Fetch findings for the assessment:

```bash
# Query all findings
python3 scripts/rcx.py findings --assessment-id "<assessment-id>"

# Filter by high or critical severity
python3 scripts/rcx.py findings --assessment-id "<assessment-id>" --severity HIGH
```

---

## 2. Severity Classification

Reconix uses standard UPPERCASE severity levels:
- `CRITICAL`: Immediate remote code execution, unauthenticated admin access, remote credential exposure.
- `HIGH`: SQL injection, SSRF, arbitrary file read, broken access control.
- `MEDIUM`: Cross-Site Scripting (XSS), missing authorization checks on sensitive actions, outdated components with known vulnerabilities.
- `LOW`: Information disclosure, server banners, SSL/TLS weak ciphers.
- `NONE`: Informational findings (open ports, discovered technologies).

---

## 3. Triage & Evidence Verification

For each high-severity finding:
1. **Inspect Evidence**: Check the masked snippet in the finding details.
2. **Review Confidence & Status**:
   - `OPEN`: Initial unreviewed finding.
   - `FALSE_POSITIVE`: Verified to be non-exploitable or misidentified.
   - `FIXED`: Remediation applied and verified.
3. **Validate Proof-of-Concept**: Suggest a safe, in-scope verification command to confirm the finding without causing denial of service.
