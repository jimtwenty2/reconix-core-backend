"""Flow 1: the main flow, one template at a time (5 cases each, every case end to end).

Every message quoted here is the app's own wording (checked by tests/test_test_guide.py
where the store can say it). Steps use "→" between what you do and what you see.
"""

from .model import Case, Flow

LOGIN_WEB = (
    "Login: the login form opens. Email or username demo.tester, any password "
    "(it never shows) → Save login; then the one-time code 123456 → Submit code."
)
API_FORM = (
    'The "API TEMPLATE: BASE URL AND SPEC" form opens first: press Esc to skip it '
    "(MF-API-02 attaches a spec)."
)
APPROVE_HIGH = (
    'HIGH → Approve & run → "◆ HIGH-RISK · second confirmation" → move down to Yes, run … → Enter.'
)
REPORT_EXPORT = 'Report screen (Alt+8) → press {key} → "✓ REPORT SAVED" shows the file path.'

WEB = Flow(
    id="MF-WEB",
    number="1.1",
    title="Web URL (a website)",
    intro=(
        "A URL like https://shop.example.com picks Web URL at once. A bare hostname asks "
        '"Which kind of target is it?".',
    ),
    facts=(
        (
            "Scope",
            "methods GET and POST; never touches /admin; tools whatweb, Katana, Nuclei and "
            "testssl.sh; time limit 30 min",
        ),
        ("Login", "a session cookie (Nuclei sends it)"),
        ("MEDIUM", "Baseline request (read-only) · GET /api/orders/10482"),
        ("HIGH", "Cross-account read check · GET /api/orders/10483 (test account B)"),
        ("Blocked in the run", "Blocked: GET /admin · Path outside approved scope. Not executed."),
        (
            "Findings",
            "001 MEDIUM Broken object-level authorization · 002 MEDIUM Reflected input "
            "in search page · 003 LOW Session cookie missing SameSite",
        ),
    ),
    cases=(
        Case(
            "MF-WEB-01",
            "The whole flow, approve everything",
            (
                'Scope: "Approve this scope manifest?" → Approve scope → the scope is locked.',
                'Plan: "Run this plan?" → Run plan.',
                LOGIN_WEB,
                'MEDIUM: "Run Baseline request (read-only) on …?" → Approve & run.',
                APPROVE_HIGH,
                'Execution: the log shows "Blocked: GET /admin · Path outside approved scope. '
                'Not executed."',
                "Findings (Alt+6): 3 findings. Open 001 (Enter): evidence shows usr_••••42 and "
                "token: •••• (masked).",
                REPORT_EXPORT.format(key="p (PDF)"),
            ),
            "Every step on the step line ends at ✓; no password, token or cookie shows anywhere.",
            ask="Check https://shop.example.com for web security issues",
        ),
        Case(
            "MF-WEB-02",
            "Bare hostname: you pick the template",
            (
                'Template: "Which kind of target is it?" (4 choices) → Web URL.',
                "Scope → Edit manifest → Excluded paths: /admin, /checkout · "
                "Time limit (minutes): 20 → Save scope.",
                "The scope card now shows /checkout and 20 min → Approve scope → Run plan.",
                LOGIN_WEB,
                "MEDIUM → View details: scope limits, the exact request and its sha256 hash → "
                "Back to the choices → Approve & run.",
                "HIGH → Approve & run → second confirmation → press Enter on the default "
                "No, go back → you are back at the approval; nothing ran.",
                APPROVE_HIGH,
                REPORT_EXPORT.format(key="j (JSON)"),
            ),
            'The approved scope has /checkout and 20 min; the first "No, go back" ran nothing.',
            ask="Assess staging.example.com",
        ),
        Case(
            "MF-WEB-03",
            "Wrong scope values are refused",
            (
                'Scope → Edit manifest → Excluded paths: /admin, checkout → Save scope → "Excluded '
                "paths start with '/': checkout.\"",
                'Time limit (minutes) 500 → "Keep the time limit between 1 and 480 minutes."',
                'Tools: Nuclei, OWASP ZAP, metasploit → "Unknown tool: metasploit."',
                'Allowed methods: empty → "Keep at least one allowed method."',
                "Each time the scope card is unchanged. Now Time limit (minutes) 45 → "
                "Save scope → it shows 45 min.",
                "Approve scope → Run plan → finish with Approve everywhere.",
            ),
            "A wrong value changes nothing (all or nothing); the final scope shows 45 min.",
            ask="Scan the website https://shop.example.com",
        ),
        Case(
            "MF-WEB-04",
            "Edit the approval's parameters",
            (
                "Approve scope → Run plan → login (as MF-WEB-01).",
                'MEDIUM → Edit params → /admin → Save params → "Blocked by policy: Path '
                "outside approved "
                'scope."',
                "Edit params → /api/orders 10482 → \"That path can't be used: one value, no "
                'spaces, at most 200 characters."',
                "Edit params → /api/orders/10490 → accepted; the request now shows "
                "/api/orders/10490 → Approve & run.",
                APPROVE_HIGH,
                "Findings → open 002 → t (triage) → False positive → the list shows the "
                "new status.",
                REPORT_EXPORT.format(key="w (DOCX)"),
            ),
            "Blocked values never run; the accepted edit is what ran; the triage is in the report.",
            ask="Test https://shop.example.com for access control problems",
        ),
        Case(
            "MF-WEB-05",
            "Reject at HIGH, the plan goes on",
            (
                "Approve scope → Run plan → login → MEDIUM Approve & run.",
                'HIGH → Reject (↑/↓ then Enter; it has no number) → "Rejected: '
                'Cross-account read check. Not executed — the plan goes on with its next step." '
                "(on Execution's live output; scroll it up on a short terminal)",
                'The run goes on to the end: "Assessment completed. 3 findings: 0 confirmed, 3 '
                'marked for review." and "Open the report (Alt+8 or /report) to export it."',
                "/findings → 001 stays Unconfirmed: the validation that would confirm it was "
                "rejected.",
                REPORT_EXPORT.format(key="p (PDF)"),
            ),
            "Cross-account read check never runs; the same assessment completes and its report "
            "can be exported.",
            ask="Check https://shop.example.com for web security issues",
        ),
    ),
)

API = Flow(
    id="MF-API",
    number="1.2",
    title="API (REST / GraphQL)",
    intro=(
        "A URL with an API path (/v1, /api, /graphql) or the word api, endpoints, swagger "
        "or openapi picks API at once.",
        API_FORM,
    ),
    facts=(
        (
            "Scope",
            "methods GET and POST; never touches /internal and /admin; tools httpx, "
            "Katana and Nuclei (+ schemathesis with a spec); time limit 30 min",
        ),
        ("Login", "a session cookie (the API tools send it)"),
        ("MEDIUM", "Baseline request (read-only) · GET /v1/orders/8842 (token A)"),
        ("HIGH", "Cross-account read check · GET /v1/orders/8843 (token B's order)"),
        (
            "Blocked in the run",
            "Blocked: GET /internal/metrics · Path outside approved scope. Not executed.",
        ),
        (
            "Findings",
            "001 MEDIUM Broken object-level authorization · 002 MEDIUM Missing "
            "authorization on export endpoint · 003 LOW No rate limiting on login",
        ),
    ),
    cases=(
        Case(
            "MF-API-01",
            "The whole flow, approve everything",
            (
                API_FORM,
                "Scope → Approve scope → Plan → Run plan.",
                "Login: Session cookie → type session=test-cookie-123 → Save login.",
                "MEDIUM → Approve & run.",
                APPROVE_HIGH,
                'Execution: "Blocked: GET /internal/metrics · Path outside approved scope. Not '
                'executed."',
                "Findings: 3 → " + REPORT_EXPORT.format(key="p (PDF)"),
            ),
            "Every step at ✓; the cookie value never shows in the log, the findings or the report.",
            ask="Test the REST API at https://api.example.com/v1 for authorization issues",
        ),
        Case(
            "MF-API-02",
            "Attach an OpenAPI spec",
            (
                "The API form opens: keep the base URL, OpenAPI spec: "
                "scripts/sample/openapi-demo.yaml (reconix was started in apps/tui) → Save.",
                "The scope review now offers Replace OpenAPI spec and Remove OpenAPI spec.",
                "Remove OpenAPI spec → gone; Attach OpenAPI spec → the same file again.",
                'A wrong path (nope.yaml) → "No file at that path."',
                "Approve scope → Run plan → cookie → approve MEDIUM and HIGH.",
                REPORT_EXPORT.format(key="j (JSON)"),
            ),
            "The spec (4 endpoints, GET and POST) is read but never widens the scope.",
            ask="Assess the api at api.example.com",
        ),
        Case(
            "MF-API-03",
            "Reject the scope",
            (
                API_FORM,
                'Scope → Reject (↑/↓ then Enter; it has no number) → the toast "Scope rejected '
                '— nothing was tested."',
                "You stay in the same assessment: the Template step shows ✕, the screen says "
                '"◆ reconix this assessment stopped before testing: you rejected the scope" and '
                'asks "Start again?" (Start a new assessment / Back to the start).',
                'Ctrl+O on Execution (or /audit) → "Scope rejected. Nothing was tested." and '
                '"Assessment stopped. Nothing else will run. Type /new to start a new '
                'assessment."',
                "/audit → the rejection is in the audit trail.",
                '"Start again?" → Start a new assessment → /assessments still lists the rejected '
                "one as Stopped.",
            ),
            "Nothing ran: no plan step started and there are no findings. Reject never opens a "
            "new assessment by itself.",
            ask="Check https://api.example.com/v1 endpoints",
        ),
        Case(
            "MF-API-04",
            "Edit the scope, find the blocked request in the audit",
            (
                API_FORM,
                "Scope → Edit manifest → Allowed methods: GET, POST, DELETE · "
                "Excluded paths: /internal, "
                "/admin, /v1/admin → Save.",
                "Edit manifest → Excluded paths: v1/x → \"Excluded paths start with '/': v1/x.\"",
                "Approve scope → Run plan → cookie → approve MEDIUM and HIGH.",
                "/audit → the blocked GET /internal/metrics is listed with its reason.",
                "Report → p (PDF): the exported report's scope section lists DELETE and "
                "/v1/admin.",
            ),
            "The exported report shows exactly the scope you approved; the blocked request is "
            "in the audit trail.",
            ask="Test https://api.example.com/v1 for API security issues",
        ),
        Case(
            "MF-API-05",
            "Reject at MEDIUM",
            (
                API_FORM,
                "Approve scope → Run plan → cookie.",
                "MEDIUM → Reject (↑/↓ then Enter) → the app goes straight to the HIGH "
                'approval, which shows "✕ Skipped: Baseline request (read-only) (rejected)". The '
                'line "Rejected: Baseline request (read-only). Not executed — the plan goes on '
                'with its next step." is in the Execution log (Ctrl+O) and in /audit.',
                "The HIGH step still asks for its own approval: Approve & run → second "
                "confirmation → Yes.",
                'The run completes: "Assessment completed. …" /audit lists approval.rejected '
                "for the MEDIUM step.",
            ),
            "The rejected MEDIUM request never runs; the plan goes on and HIGH runs only after "
            "its own approval.",
            ask="Test the REST API at https://api.example.com/v1 for authorization issues",
        ),
    ),
)

NETWORK = Flow(
    id="MF-NET",
    number="1.3",
    title="Network (IP address or range)",
    intro=(
        "An IPv4 address or CIDR range (10.0.0.0/24, 192.0.2.10) picks Network at once. "
        "Ports typed in the question fill the scope.",
    ),
    facts=(
        (
            "Scope",
            "TCP connect; ports 22, 80, 443, 8080 and 8443; tools nmap and testssl.sh; "
            "time limit 30 min; no login",
        ),
        ("MEDIUM", "Banner and TLS check (read-only) · TCP 10.0.0.1:8443"),
        ("HIGH", "Default login probe · one default credential on /manager"),
        (
            "Blocked in the run",
            "Blocked: TCP 198.51.100.9 · Host outside approved scope. Not executed.",
        ),
        (
            "Findings",
            "001 HIGH Management console exposed · 002 MEDIUM Deprecated TLS 1.0 "
            "offered · 003 LOW SSH banner reveals version",
        ),
    ),
    cases=(
        Case(
            "MF-NET-01",
            "The whole flow, approve everything",
            (
                "Scope → Approve scope → Plan → Run plan (no login step).",
                "MEDIUM → Approve & run.",
                APPROVE_HIGH,
                'Execution: "Blocked: TCP 198.51.100.9 · Host outside approved scope. Not '
                'executed."',
                "Findings: 001 HIGH, 002 MEDIUM, 003 LOW → " + REPORT_EXPORT.format(key="p (PDF)"),
            ),
            "Every step at ✓ and no login was asked.",
            ask="Scan 10.0.0.0/24 for open ports and weak services",
        ),
        Case(
            "MF-NET-02",
            "Ports in the question fill the scope",
            (
                "Scope card: Ports 22, 443 and 8443 (only the ones you typed).",
                "Approve scope → Run plan → approve MEDIUM and HIGH.",
                "Findings and the report use only those ports.",
            ),
            "The scope, findings and report hold exactly ports 22, 443 and 8443.",
            ask="scan 192.0.2.0/28 ports 22, 443 and 8443 with nmap",
        ),
        Case(
            "MF-NET-03",
            "Wrong addresses are refused",
            (
                "scan 10.0.0.300 → \"10.0.0.300 isn't a valid IPv4 address — four numbers from 0 "
                'to 255."',
                'scan 10.0.0.0/8 → "10.0.0.0/8 is too wide to test — use a /16 or smaller range."',
                'scan 10.0.0.20-10.0.0.1 → "… runs backwards — put the lower address first …"',
                "scan 10.0.0.1-10.0.0.20 → \"Dash ranges aren't supported by the scope yet — use "
                'CIDR, e.g. 10.0.0.0/27."',
                'scan my network → "Network needs an IPv4 address or range, or a hostname — e.g. '
                '10.0.0.0/24"',
                "Each refused line stays in the prompt, selected: typing replaces it (type "
                "/new and the command list opens instead of adding to the address).",
                "Then scan 10.0.0.0/28 → accepted → finish the flow.",
            ),
            "Each bad address shows its message and nothing starts; the CIDR range starts.",
            ask="scan 10.0.0.300",
        ),
        Case(
            "MF-NET-04",
            "Scope edit and ports suggested in chat",
            (
                "Scope → Edit manifest → Allowed ports 0 → "
                '"Not a valid port (1–65535): 0."; 99999 → '
                'the same; empty → "Keep at least one allowed port."',
                'Excluded 10.0.0.0/33 → "Exclude a host, range or host:port (e.g. '
                '10.0.0.5:22): 10.0.0.0/33."; Excluded 10.0.0.5:22 → Save scope.',
                'Chat about this → type add port 3389 → "Only you can change the scope. Tick what '
                'it allows, then press Enter to save." and a tick list with 3389 unticked; the '
                "list opens on the 3389 row.",
                "Press Space (ticks 3389), then Enter → the scope card shows port 3389.",
                'Type add ports 1-1024 → "The scope lists single ports, not a range (1-1024)…"; '
                'add 10.0.0.99 to the scope → "Hosts can\'t change here…" (no tick list).',
                "Approve scope → Run plan → finish.",
            ),
            "Only your tick changed the scope; the wrong values changed nothing.",
            ask="Scan 10.0.0.0/24 for open ports",
        ),
        Case(
            "MF-NET-05",
            "The HIGH double check and blocked parameters",
            (
                "Approve scope → Run plan → MEDIUM Approve & run.",
                'HIGH → Edit params → 10.9.9.9:22 → "Blocked by policy: Host outside approved '
                'scope."',
                '10.0.0.7:8081 → "Blocked by policy: Port 8081 not in the approved list."',
                '10.0.0.7 → "Give a host and a port, e.g. 10.0.0.1:8443."',
                "10.0.0.7:8443 → accepted.",
                "Approve & run → second confirmation → No, go back (nothing runs) → Approve & run "
                "→ Yes.",
                "Findings → f → Critical & High → open 001 (on 10.0.0.1:8443): it stays "
                "UNCONFIRMED with the evidence \"Not collected: the check ran on 10.0.0.7:8443, "
                "not on this finding's own host and port, so it can't confirm it.\" → "
                + REPORT_EXPORT.format(key="w (DOCX)"),
            ),
            "Only an in-scope host:port can be set; HIGH runs only after the second Yes; a check "
            "moved to another host never confirms the finding.",
            ask="Check 10.0.0.0/24 for exposed management consoles",
        ),
    ),
)

SOURCE = Flow(
    id="MF-SRC",
    number="1.4",
    title="Source Code (git repo or folder)",
    intro=(
        "A GitHub repo (https://github.com/owner/repo, git@github.com:owner/repo, "
        "github.com/owner/repo) or a "
        "local folder path picks Source Code at once.",
    ),
    facts=(
        (
            "Scope",
            "read only; never touches .git, node_modules, vendor and secrets; tools "
            "Semgrep, gitleaks and trivy; no login",
        ),
        ("MEDIUM", "Read the flagged line (read-only) · app/config/settings.py:42"),
        ("HIGH", "Check the flagged credential once · one try on a test database"),
        (
            "Blocked in the run",
            "Blocked: read .git/config · Path excluded from the review. Not executed.",
        ),
        (
            "Findings",
            "001 HIGH Hardcoded database password · 002 MEDIUM SQL built by string "
            "concatenation · 003 LOW Vulnerable dependency",
        ),
    ),
    cases=(
        Case(
            "MF-SRC-01",
            "The whole flow, approve everything",
            (
                "Scope → Approve scope → Plan → Run plan.",
                "MEDIUM → Approve & run.",
                APPROVE_HIGH,
                'Execution: "Blocked: read .git/config · Path excluded from the review. Not '
                'executed."',
                "Findings → open 001: the password is masked (••••) → "
                + REPORT_EXPORT.format(key="p (PDF)"),
            ),
            "Every step at ✓; the hardcoded password never shows in plain text.",
            ask="Review the repo https://github.com/acme/app for secrets and "
            "insecure code",
        ),
        Case(
            "MF-SRC-02",
            "Other ways to name a repository",
            (
                "review git@github.com:acme/app.git → Source Code.",
                "/new → scan the source code in ./demo-app → Source Code (a folder path).",
                "/new → review repo github.com/acme → \"github.com/acme isn't a repository — e.g. "
                'https://github.com/acme/app".',
                "/new → the first line again → finish the flow.",
            ),
            "All repository forms are understood; the incomplete one is explained.",
            ask="review git@github.com:acme/app.git",
        ),
        Case(
            "MF-SRC-03",
            "Paths that leave the repository are blocked",
            (
                "Approve scope → Run plan.",
                'MEDIUM → Edit params → ../../etc/passwd → "Blocked by policy: Path leaves the '
                'repository."',
                '/etc/passwd and ~/.ssh/id_rsa → "Give a file in the repository, e.g. '
                'app/config/settings.py."',
                'secrets/prod.env → "Blocked by policy: Path excluded from the review."',
                "app/db/queries.py → accepted → Approve & run.",
                APPROVE_HIGH,
            ),
            "Only files inside the repository and outside the excluded paths can be read.",
            ask="Check https://github.com/acme/app for hardcoded secrets",
        ),
        Case(
            "MF-SRC-04",
            "Reorder the gated checks in the plan",
            (
                'Approve scope → at the plan: Chat about this → move 3b before 3a → "Only you can '
                'change the order…" and an order list.',
                'Move "Check the flagged credential once" up (Shift+↑) → Enter → "Plan updated" '
                "and the plan card shows 3a Check the flagged credential once (HIGH), "
                "3b Read the flagged line (MEDIUM).",
                "Type move step 1 to the end → the order list again: only the gated checks can "
                "move; phases 1–5 stay fixed.",
                "Run plan → HIGH is asked first, then MEDIUM → approve both.",
                REPORT_EXPORT.format(key="j (JSON)"),
            ),
            "The run follows the order you saved; the phases never move.",
            ask="Review https://github.com/acme/app for security issues",
        ),
        Case(
            "MF-SRC-05",
            "Stop during the run",
            (
                'Approve scope → Run plan → while it runs press Ctrl+C → "Stop this '
                'assessment?" → Keep running → it goes on.',
                'Ctrl+C again → Stop now → "You stopped it. Nothing else will run."',
                "/findings → only what was found so far. /summary → the stop.",
                "/new → start again.",
            ),
            "Keep running loses nothing; Stop now runs nothing else and keeps what was found.",
            ask="Review the repo https://github.com/acme/app for secrets and "
            "insecure code",
        ),
    ),
)

FLOWS = (WEB, API, NETWORK, SOURCE)

# What every template walks through, in order (the guide's overview for Flow 1).
GATES = (
    ("Scope review", "\"Approve this scope manifest?\" → Approve scope / Edit manifest / Reject "
                     "(API also: Attach OpenAPI spec). Edit manifest is all or nothing; after "
                     "Approve the scope is locked. Reject (red) has no number: a digit never "
                     "picks it, use ↑/↓ and Enter."),
    ("Plan", "\"Run this plan?\" → Run plan / Edit steps / Cancel (red, no number). The other "
             "rows run on their own; the target login (when the tools need one), 3a (MEDIUM) "
             "and 3b (HIGH) wait for you."),
    ("Target login", "Only when the scope's tools need one (Web URL: account + one-time code; "
                     "API: session cookie). What you type is never shown or saved."),
    ("MEDIUM approval", "\"Run <action> on <target>?\" → Approve & run / Reject / View details / "
                        "Edit params. Reject (red) has no number: use ↑/↓ and Enter. A "
                        "rejected action is skipped and the plan goes on. On a short terminal "
                        "the screen opens on the request; a note says to press ↓ for the "
                        "choices."),
    ("HIGH approval", "The same menu, then \"◆ HIGH-RISK · second confirmation\"; its default "
                      "is No, go back."),
    ("Execution", "One request outside the scope is proposed and blocked: \"Blocked: … Not "
                  "executed.\" Ctrl+C asks \"Stop this assessment?\"."),
    ("Findings and report", "3 findings per template (Enter open, f filter, s sort, t triage); "
                            "on the Report screen p PDF, j JSON, w DOCX once the run is "
                            "complete (saved in apps/tui/reports/)."),
)
