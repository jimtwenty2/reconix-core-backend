# Phase 1: Scoping Runbook

Target boundaries are the primary defense in Reconix. Nothing may ever run outside the approved scope.

## 1. Defining Targets

Targets must be explicit network entities authorized by the client or target owner.

### Supported Target Formats
- **Single IP Address**: `192.168.1.100`, `10.0.0.5`
- **CIDR Subnet**: `192.168.1.0/24`, `10.10.0.0/16`
- **Domain Name**: `target.local`, `app.internal.domain`
- **URL**: `https://api.internal.domain/v1`

### Denied & Out-of-Scope Targets
- Public / non-authorized external domains or IP ranges unless explicitly stated in the agreement.
- Cloud metadata services: `169.254.169.254`, `metadata.google.internal`.
- Reconix host local services (unless authorized as localhost lab): `127.0.0.1`, `localhost`.

---

## 2. Risk Gating (`max_risk`)

Set the ceiling risk allowed for this assessment:
- `LOW`: Passive reconnaissance and non-intrusive port/service discovery (e.g., standard `nmap -sS`, `nuclei` info tags). Runs automatically.
- `MEDIUM`: Active vulnerability scanning and service probing (e.g., `nikto`, `nuclei` medium templates). Pauses at the human gate for operator approval.
- `HIGH`: Active exploitation, credential brute-forcing, injection testing (e.g., `sqlmap`, `hydra`). Pauses for human gate and requires typed target confirmation.

> [!IMPORTANT]
> Any action proposing a risk level higher than the scope's `max_risk` is immediately **BLOCKED (HTTP 422)** by the Reconix safety check pipeline (`harness/checks/risk.py`).

---

## 3. Registering Scope with `rcx.py`

Run the helper command:

```bash
python3 scripts/rcx.py scope \
  --target "192.168.1.0/24" \
  --max-risk MEDIUM \
  --exclude "192.168.1.1,192.168.1.254"
```

Verify that the returned JSON contains `"id"` and confirms `"max_risk": "MEDIUM"`.
