"""A fake Core API for tests: an in-memory copy of services/api, in its exact response shapes.

Test code only (apps/CLAUDE.md "Data"): product code never imports it. It replaces
`core_api.client._send`, so every call the app makes goes through the real client code
(URL, token, error shape) and lands here instead of on the network.

It keeps the API's own rules where the app depends on them:
- one assessment per session; a scope is approved through its scope approval;
- a plan sends only its first step; LOW runs at once, MEDIUM and HIGH wait for a person;
  HIGH needs the typed target; an approval is single use;
- the next step comes from POST /next-step, until the agent has nothing left (`steps`);
- a tool run's output is "Kali's" canned output (`outputs`), and its findings
  (`findings_for`) appear once it ran;
- errors have the API's shape {"code", "message", "details"} and status.

Tests change `steps`, `outputs`, `findings_for`, `reply`, `down` or `fail` to shape a run.
"""

import json
import re
import shlex
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from reconix.core_api.client import NOT_RUNNING, CoreApiError

TOKEN_PREFIX = "fake-session-token-"  # noqa: S105 - a fake
_NAME = re.compile(rb'name="([^"]+)"')
_FILENAME = re.compile(rb'filename="((?:[^"\\]|\\.)*)"')
# KnowledgeAddOnKind: the API picks it from the uploaded file's own name.
_KIND = {"txt": "TXT", "md": "MD", "json": "JSON", "yaml": "YAML", "yml": "YAML",
         "docx": "DOCX", "pdf": "PDF"}


def form_of(data: bytes) -> Tuple[Dict[str, str], str, bytes]:
    """One multipart/form-data body as the API reads it: (text fields, file name, file)."""
    fields: Dict[str, str] = {}
    file_name, file_data = "", b""
    boundary = data.split(b"\r\n", 1)[0]               # the leading "--<boundary>" line
    for part in data.split(boundary)[1:]:
        if not part.startswith(b"\r\n"):               # the closing "--" and anything after
            continue
        head, _, rest = part.partition(b"\r\n\r\n")
        key = _NAME.search(head)
        if key is None:
            continue
        value = rest[:-2]                              # the \r\n before the next boundary
        name = _FILENAME.search(head)
        if name:
            file_name = name.group(1).decode().replace('\\"', '"').replace("\\\\", "\\")
            file_data = value
        else:
            fields[key.group(1).decode()] = value.decode()
    return fields, file_name, file_data


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def nmap_output(target: str) -> str:
    return (
        f"Nmap scan report for {target}\nPORT     STATE SERVICE\n"
        "22/tcp   open  ssh\n80/tcp   open  http\n3000/tcp open  ppp\n"
    )


# The steps the fake agent suggests, in order: (title, phase, tool, args, risk, reason).
DEFAULT_STEPS: List[Tuple[str, str, str, List[str], str, str]] = [
    ("Find open ports", "discovery", "NMAP", ["-sV"], "LOW", "Start with what is listening."),
    ("Check for known issues", "scan", "NUCLEI", [], "MEDIUM", "Then look for weaknesses."),
    (
        "Confirm the login weakness",
        "validation",
        "SQLMAP",
        ["--batch"],
        "HIGH",
        "Prove the finding with one request.",
    ),
]


_VERIFIER_TOOLS = {"SQLMAP", "DALFOX", "COMMIX", "SCHEMATHESIS", "NUCLEI_DAST"}


def _confidence(validation: str, finding_status: str, severity: str, tools: list) -> str:
    """Mirror the API's derived FindingOut.confidence so the fake stays faithful."""
    if validation == "CONFIRMED":
        return "CONFIRMED"
    if finding_status == "FALSE_POSITIVE" or severity == "NONE":
        return "INFORMATIONAL"
    upper = {t.upper() for t in tools}
    if upper & _VERIFIER_TOOLS or len(upper) >= 2:
        return "FIRM"
    return "TENTATIVE"


def finding_row(
    code: str,
    title: str,
    target: str,
    severity: str,
    tool: str,
    description: str = "",
    evidence: str = "",
) -> dict:
    """A FindingOut without its ids (the fake fills them in)."""
    return {
        "confidence": _confidence("UNCONFIRMED", "OPEN", severity, [tool]),
        "code": code,
        "title": title,
        "target": target,
        "description": description or title,
        "severity_status": severity,
        "cvss_score": None,
        "cwe_ids": [],
        "owasp_id": [],
        "cve_ids": [],
        "impact": "An attacker learns more about the target.",
        "remediation": "Close what is not needed.",
        "validation_status": "UNCONFIRMED",
        "finding_status": "OPEN",
        "reviewed_by": None,
        "reviewed_at": None,
        "tools": [tool],
        "evidence_text": evidence,
    }


def code_finding_row() -> dict:
    """A CodeFindingOut (a finding with its place in the uploaded code and the AI review)."""
    return {
        **finding_row("SEMGREP-SQLI", "SQL injection", "/workspace/code/s", "HIGH", "SEMGREP"),
        "path": "app/db.py", "line": 12, "end_line": 12,
        "rule_id": "python.lang.security.audit.sqli", "snippet": "cur.execute(q + user)",
        "file_sha256": "0" * 64, "verdict": "LIKELY_TRUE_POSITIVE",
        "explanation": "User input reaches the query.", "fix_recommendation": "Use parameters.",
    }


class FakeApi:
    """Answers the calls the app makes, and records them (method, path, body, auth)."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Any, str]] = []
        self.down = False
        self.fail: Optional[Tuple[int, str, str]] = None  # every call (but /sessions) fails
        self.fail_on: Dict[str, Tuple[int, str, str]] = {}  # "METHOD /path-prefix" -> error
        self.reply = "The API's answer."
        self.steps = [list(step) for step in DEFAULT_STEPS]
        self.outputs: Dict[str, str] = {}  # tool -> output (else a default)
        self.findings_for: Dict[str, List[dict]] = {
            "NMAP": [
                finding_row(
                    "NMAP-OPEN-PORT",
                    "Open port 3000/tcp (http)",
                    "{target}:3000",
                    "LOW",
                    "NMAP",
                    evidence="3000/tcp open ppp",
                )
            ],
            "NUCLEI": [
                finding_row(
                    "NUCLEI-EXPOSED-PANEL",
                    "Exposed admin panel",
                    "{target}",
                    "MEDIUM",
                    "NUCLEI",
                    evidence="[admin-panel] [http] [medium]",
                )
            ],
        }
        self.analysis_summary = "Two issues found; the admin panel is the one to fix first."
        self.pending_activation = False
        # GET /system/kali: tests flip these to shape the status chip.
        self.kali_connected = True
        self.kali_host = "reconix-kali-container:8000"
        self.provider_test_ok = True  # POST /llm-providers/{id}/test answers ok
        self.n = 0
        self.sessions: Dict[str, str] = {}  # token -> session id
        self.providers: List[dict] = []
        self.manifests: Dict[str, dict] = {}
        self.assessments: Dict[str, dict] = {}
        self.approvals: Dict[str, dict] = {}
        self.actions: Dict[str, dict] = {}
        self.runs: Dict[str, dict] = {}
        self.findings: Dict[str, dict] = {}
        self.reports: Dict[str, dict] = {}
        self.messages: List[dict] = []
        self.uploads: List[bytes] = []  # the tar.gz bodies PUT to /code
        self.add_on_bodies: List[bytes] = []  # the multipart bodies POSTed to /knowledge-add-ons
        self.add_ons: Dict[str, dict] = {}  # knowledge_add_on_id -> KnowledgeAddOnOut
        self.add_on_n = 0
        self.code_files: Dict[str, str] = {}  # relative path -> sha256 the "API" holds
        self.code_polls = 1  # a code scan answers RUNNING this many times before COMPLETED
        self.code_findings: List[dict] = [code_finding_row()]
        self.code_notes = ["SYFT 12 packages"]
        self.scans: Dict[str, dict] = {}

    # --- helpers for tests ------------------------------------------------------------------
    def paths(self) -> List[str]:
        return [f"{method} {path}" for method, path, _, _ in self.calls]

    def bodies(self, method: str, start: str) -> List[Any]:
        return [body for m, path, body, _ in self.calls if m == method and path.startswith(start)]

    def tool_runs(self) -> List[str]:
        """The tools Kali ran, in order."""
        return [a["tool"] for a in self.actions.values() if a["tool_runs"]]

    # --- the transport -----------------------------------------------------------------------
    def send(self, request, timeout=None) -> Any:
        if self.down:
            raise CoreApiError("UNREACHABLE", NOT_RUNNING)
        path = request.full_url.split("/api/v1", 1)[1]
        gzipped = request.headers.get("Content-type") == "application/gzip"
        multipart = request.headers.get("Content-type", "").startswith("multipart/")
        body = (
            {"multipart_bytes": len(request.data)} if multipart else
            {"gzip_bytes": len(request.data)} if gzipped
            else json.loads(request.data) if request.data else None
        )
        if gzipped:
            self.uploads.append(request.data)
        if multipart:
            self.add_on_bodies.append(request.data)
        auth = request.headers.get("Authorization", "")
        method = request.get_method()
        self.calls.append((method, path, body, auth))
        if path == "/health":  # open, no token (api/system.py)
            return {"status": "OK"}
        for key, (status, code, message) in self.fail_on.items():
            want_method, _, prefix = key.partition(" ")
            if method == want_method and path.startswith(prefix):
                raise CoreApiError(code, message, status)
        if self.fail and not path.startswith("/sessions"):
            status, code, message = self.fail
            raise CoreApiError(code, message, status)
        if path != "/sessions" and auth.replace("Bearer ", "") not in self.sessions:
            raise CoreApiError("UNAUTHORIZED", "Sign in again.", 401)
        return self.answer(method, path.split("?")[0], body, path)

    def _id(self, kind: str) -> str:
        self.n += 1
        return f"{kind}-{self.n:04d}"

    def error(self, status: int, code: str, message: str, **details: Any) -> CoreApiError:
        return CoreApiError(code, message, status, details)

    # --- the routes --------------------------------------------------------------------------
    def answer(self, method: str, path: str, body: Any, full: str) -> Any:  # noqa: C901
        parts = path.strip("/").split("/")
        if path == "/system/kali" and method == "GET":
            return {
                "connected": self.kali_connected,
                "host": self.kali_host if self.kali_connected else None,
                "checked_at": now(),
            }
        if path == "/sessions" and method == "POST":
            token, session_id = TOKEN_PREFIX + self._id("t"), self._id("s")
            self.sessions[token] = session_id
            return {
                "session_id": session_id,
                "token": token,
                "interface": "CLI",
                "session_status": "ACTIVE",
                "created_at": now(),
                "closed_at": None,
            }
        if path == "/sessions/web-sign-in-codes" and method == "POST":
            return {"code": "fake-web-code-" + self._id("c"), "expires_at": now()}
        if path == "/llm-providers":
            return self.providers if method == "GET" else self._add_provider(body)
        if path.endswith("/activate"):
            return self._activate(parts[1])
        if path.endswith("/test") and parts[0] == "llm-providers":
            return self._test_provider(parts[1])
        if path.endswith("/models") and parts[0] == "llm-providers":
            return self._provider_models(parts[1])
        if parts[0] == "llm-providers" and method == "PATCH":
            return self._patch_provider(parts[1], body)
        if parts[0] == "llm-providers" and method == "DELETE":
            return self._delete_provider(parts[1])
        if parts[0] == "llm-providers" and len(parts) == 2 and method == "GET":
            return self._provider(parts[1])
        if path.endswith("/scope-manifests") and method == "POST":
            return self._new_manifest(parts[1], body)
        if parts[0] == "scope-manifests" and method == "PATCH":
            self.manifests[parts[1]]["draft"] = body
            return {"manifest_id": parts[1]}
        if path.endswith("/submit"):
            return self._submit(parts[1], body)
        if parts[0] == "approvals" and len(parts) == 3:
            return self._decide(parts[1], parts[2], body or {})
        if parts[0] == "approvals" and len(parts) == 2:
            return self.approvals[parts[1]]
        if path == "/approvals":
            return [
                a
                for a in self.approvals.values()
                if "status=PENDING" not in full or a["approval_status"] == "PENDING"
            ]
        if parts[0] == "knowledge-add-ons":
            return self._add_on(method, parts)
        if "/code" in path or parts[0] == "code-scans":
            return self._code(method, parts, body)
        if path.endswith("/chat"):
            return {"reply": {"content_masked": self.reply}}
        if path.endswith("/messages"):
            self.messages.append(body)
            return {"message_id": self._id("msg")}
        if path.endswith("/plan"):
            return self._plan(parts[1], draft="draft=true" in full)
        if path.endswith("/send"):
            return self._send_draft(parts[1])
        if path.endswith("/cancel") and parts[0] == "agent-runs":
            self.runs[parts[1]]["agent_runs_status"] = "CANCELLED"
            return self._run_out(self.runs[parts[1]])
        if path.endswith("/next-step"):
            return self._next(parts[1])
        if parts[0] == "actions":
            return self.actions[parts[1]]
        if path.endswith("/actions") and method == "GET":
            return [a for a in self.actions.values() if a["assessment_id"] == parts[1]]
        if path == "/findings":
            return [f for f in self.findings.values() if f["assessment_id"] in full]
        if parts[0] == "findings" and method == "PATCH":
            self.findings[parts[1]]["finding_status"] = body["finding_status"]
            return self.findings[parts[1]]
        if parts[0] == "findings":
            return self.findings[parts[1]]
        if path.endswith("/analyze"):
            return self._analyze(parts[1], body)
        raise AssertionError(f"the fake API has no route for {method} {path}")

    # --- code scans (a source scope) ---------------------------------------------------------
    def _code(self, method: str, parts: List[str], body: Any) -> Any:  # noqa: C901
        if parts[0] == "sessions" and parts[2] == "code":
            if parts[3:] == ["sync"]:
                held = {f["path"]: f["sha256"] for f in body["files"]}
                missing = [p for p, h in held.items() if self.code_files.get(p) != h]
                self._listed = held
                self.code_files = {p: h for p, h in self.code_files.items() if p in held}
                return {"missing": missing, "target": f"/workspace/code/{parts[1]}"}
            if method == "PUT":
                self.code_files = dict(self._listed)
                return {"files": 0, "size_bytes": body["gzip_bytes"],
                        "target": f"/workspace/code/{parts[1]}"}
            if parts[3:] == ["clone"]:
                raise self.error(503, "GIT_NOT_FOUND", "git is not installed on this computer")
        if parts[0] == "sessions" and parts[2] == "code-scans":
            run_id = self._id("scan")
            self.scans[run_id] = {"polls": 0, "tools": body.get("tools"), "session": parts[1]}
            return self._code_scan_out(run_id)
        if parts[0] == "code-scans" and len(parts) == 2:
            self.scans[parts[1]]["polls"] += 1
            return self._code_scan_out(parts[1])
        if parts[0] == "code-scans" and parts[2] == "findings":
            return [{**row, "finding_id": f"cf-{i}"} for i, row in enumerate(self.code_findings)]
        raise AssertionError(f"the fake API has no code route for {method} {parts}")

    def _code_scan_out(self, run_id: str) -> dict:
        scan = self.scans[run_id]
        running = scan["polls"] < self.code_polls
        counts = {} if running else {"HIGH": len(self.code_findings)}
        return {
            "agent_run_id": run_id,
            "agent_runs_status": "RUNNING" if running else "COMPLETED",
            "stage": "SCANNING" if running else "DONE",
            "progress": 40 if running else 100,
            "started_at": now(),
            "finished_at": None if running else now(),
            "session_id": scan["session"],
            "assessment_id": "a-code",
            "counts": counts,
            "notes": [] if running else self.code_notes,
            "error": None,
        }

    # --- knowledge add-ons (/add-on uploads) --------------------------------------------------
    def _add_on(self, method: str, parts: List[str]) -> Any:
        """POST one uploaded file (multipart/form-data) or DELETE one add-on by id, as
        api/knowledge_add_ons.py does. Only what the app reads back is real: its id."""
        if method == "POST":
            fields, file_name, file_data = form_of(self.add_on_bodies[-1])
            if not file_name:
                raise self.error(422, "VALIDATION_ERROR", "The request is not valid.",
                                 fields=[{"field": "body.file", "message": "Field required"}])
            if fields.get("interface") not in ("web", "cli"):
                raise self.error(422, "VALIDATION_ERROR", "The request is not valid.")
            add_on_id = self._add_on_id()
            row = {
                "knowledge_add_on_id": add_on_id,
                "name": file_name,
                "kind": _KIND.get(file_name.rsplit(".", 1)[-1].lower(), "TXT"),
                "size_bytes": len(file_data),
                "chunk_count": 1,
                "interface": fields["interface"],
                "created_at": now(),
                "cut": None,
            }
            self.add_ons[add_on_id] = row
            return row
        if method == "DELETE" and len(parts) == 2:
            if parts[1] not in self.add_ons:
                raise self.error(404, "KNOWLEDGE_ADD_ON_NOT_FOUND", "No add-on has this id.")
            del self.add_ons[parts[1]]
            return None
        raise AssertionError(f"the fake API has no add-on route for {method} {parts}")

    def _add_on_id(self) -> str:
        self.add_on_n += 1
        return f"00000000-0000-4000-8000-{self.add_on_n:012d}"

    # --- providers ---------------------------------------------------------------------------
    def _provider(self, provider_id: str) -> dict:
        return next(r for r in self.providers if r["llm_provider_id"] == provider_id)

    def _add_provider(self, body: dict) -> dict:
        row = {
            "llm_provider_id": self._id("p"),
            "provider_type": body["provider_type"],
            "display_name": body.get("display_name", ""),
            "base_url": body.get("base_url"),
            "model_name": body["model_name"],
            "is_active": False,
            "is_local": (body.get("base_url") or "").startswith("http://127.0.0.1"),
            "api_key_last4": (body.get("api_key") or "")[-4:] or None,
            "created_by": "operator",
            "created_at": now(),
            "updated_at": now(),
        }
        self.providers.append(row)
        return row

    def _patch_provider(self, provider_id: str, body: dict) -> dict:
        row = self._provider(provider_id)
        if row["created_by"] == "system":
            raise self.error(409, "BUILT_IN_PROVIDER", "The built-in provider can't be changed.")
        if row["is_active"]:
            raise self.error(409, "PROVIDER_IS_ACTIVE", "The active provider can't be changed.")
        if body.get("api_key"):
            row["api_key_last4"] = body["api_key"][-4:]
        if body.get("base_url"):
            row["base_url"] = body["base_url"]
        row["updated_at"] = now()
        return row

    def _delete_provider(self, provider_id: str) -> None:
        row = self._provider(provider_id)
        if row["created_by"] == "system":
            raise self.error(409, "BUILT_IN_PROVIDER", "The built-in provider can't be deleted.")
        if row["is_active"]:
            raise self.error(409, "PROVIDER_IS_ACTIVE", "The active provider can't be deleted.")
        self.providers.remove(row)
        return None

    def _test_provider(self, provider_id: str) -> dict:
        row = self._provider(provider_id)
        return {
            "ok": self.provider_test_ok,
            "model_name": row["model_name"],
            "latency_ms": 12,
            "code": None if self.provider_test_ok else "MODEL_UNAVAILABLE",
            "message": None if self.provider_test_ok else "the model did not answer",
        }

    def _provider_models(self, provider_id: str) -> dict:
        row = self._provider(provider_id)
        if row["provider_type"] != "OLLAMA":
            raise self.error(422, "MODEL_LIST_NOT_SUPPORTED", "Only Ollama lists its models.")
        return {"models": [row["model_name"], "bge-m3:latest"]}

    def _make_active(self, provider_id: str) -> None:
        for row in self.providers:
            row["is_active"] = row["llm_provider_id"] == provider_id

    def _activate(self, provider_id: str) -> dict:
        row = self._provider(provider_id)
        if row["is_local"]:
            self._make_active(provider_id)
            return {"llm_provider": row, "approval": None}
        if self.pending_activation:
            raise self.error(409, "APPROVAL_PENDING", "waits", approval_id="a-old")
        approval = self._approval("configuration", {"llm_provider_id": provider_id}, None)
        approval["config_change"] = {"llm_provider_id": provider_id}
        return {"llm_provider": row, "approval": approval}

    # --- scope -------------------------------------------------------------------------------
    def _new_manifest(self, session_id: str, draft: dict) -> dict:
        manifest_id = self._id("m")
        self.manifests[manifest_id] = {
            "session_id": session_id,
            "draft": draft,
            "assessment_id": None,
        }
        return {"manifest_id": manifest_id, **draft, "manifest_status": "DRAFT"}

    def _submit(self, manifest_id: str, body: dict) -> dict:
        manifest = self.manifests[manifest_id]
        if any(
            a["session_id"] == manifest["session_id"] and a["status"] != "DRAFT"
            for a in self.assessments.values()
        ):
            raise self.error(409, "ASSESSMENT_ALREADY_ACTIVE", "This session has an assessment.")
        assessment_id = self._id("as")
        targets = [t["value"] for t in manifest["draft"]["targets"] if not t.get("excluded")]
        self.assessments[assessment_id] = {
            "assessment_id": assessment_id,
            "name": body.get("name", ""),
            "status": "DRAFT",
            "manifest_id": manifest_id,
            "session_id": manifest["session_id"],
            "targets": targets,
            "next": 0,
        }
        manifest["assessment_id"] = assessment_id
        approval = self._approval("scope", {"manifest_id": manifest_id}, None)
        approval["manifest_id"] = manifest_id
        return {
            "approval_id": approval["approval_id"],
            "assessment": {"assessment_id": assessment_id, "assessment_status": "DRAFT"},
        }

    # --- approvals ---------------------------------------------------------------------------
    def _approval(self, kind: str, subject: dict, risk: Optional[str]) -> dict:
        approval_id = self._id("ap")
        row = {
            "approval_id": approval_id,
            "kind": kind,
            "subject_snapshot": subject,
            "subject_hash": "f" * 64,
            "risk_level": risk,
            "approval_status": "PENDING",
            "confirmation_verified": False,
            "reason": None,
            "decided_by": None,
            "requested_at": now(),
            "decided_at": None,
            "consumed_at": None,
            "expires_at": now(),
            "action_id": None,
            "manifest_id": None,
            "report_id": None,
            "evidence_id": None,
            "config_change": None,
        }
        self.approvals[approval_id] = row
        return row

    def _decide(self, approval_id: str, verb: str, body: dict) -> dict:
        row = self.approvals[approval_id]
        if row["approval_status"] != "PENDING":
            raise self.error(409, "APPROVAL_ALREADY_DECIDED", "This approval was already decided.")
        if verb == "reject":
            row.update(approval_status="REJECTED", reason=body.get("reason"))
            if row["action_id"]:
                self.actions[row["action_id"]]["action_status"] = "REJECTED"
            return row
        if row["risk_level"] == "HIGH":
            action = self.actions[row["action_id"]]
            if (body.get("typed_target") or "") != action["target"]:
                raise self.error(
                    422,
                    "TARGET_CONFIRMATION_MISMATCH",
                    "Type the exact target to approve a HIGH action.",
                )
            row["confirmation_verified"] = True
        row.update(approval_status="APPROVED", decided_at=now(), consumed_at=now())
        if row["kind"] == "scope":
            self.assessments[self.manifests[row["manifest_id"]]["assessment_id"]].update(
                status="ACTIVE"
            )
        if row["kind"] == "configuration":
            self._make_active(row["subject_snapshot"]["llm_provider_id"])
        if row["action_id"]:
            self._run_tool(self.actions[row["action_id"]])
        return row

    # --- plan, steps, actions ----------------------------------------------------------------
    def _assessment(self, assessment_id: str) -> dict:
        assessment = self.assessments[assessment_id]
        if assessment["status"] != "ACTIVE":
            raise self.error(409, "ASSESSMENT_NOT_ACTIVE", "Approve the scope first.")
        return assessment

    def _plan_step(self, i: int, target: str) -> dict:
        title, phase, tool, args, _risk, reason = self.steps[i]
        return {
            "order": i + 1,
            "title": title,
            "phase": phase,
            "reason": reason,
            "action": {
                "tool": tool,
                "target": target,
                "arguments": list(args),
                "is_validation": phase == "validation",
                "finding_id": None,
            },
        }

    def _run_out(self, run: dict) -> dict:
        return {
            k: run[k]
            for k in (
                "agent_run_id",
                "agent_runs_status",
                "model_name",
                "plan",
                "started_at",
                "finished_at",
                "session_id",
                "assessment_id",
            )
        }

    def _plan(self, assessment_id: str, draft: bool) -> dict:
        assessment = self._assessment(assessment_id)
        target = assessment["targets"][0]
        plan = [self._plan_step(i, target) for i in range(len(self.steps))]
        run_id = self._id("r")
        run = {
            "agent_run_id": run_id,
            "agent_runs_status": "WAITING_APPROVAL" if draft else "RUNNING",
            "model_name": "fake-model",
            "started_at": now(),
            "finished_at": None,
            "session_id": assessment["session_id"],
            "assessment_id": assessment_id,
            "plan": {"task": "PLAN", "text": "A plan in 3 steps.", "steps": plan, "draft": draft},
        }
        self.runs[run_id] = run
        assessment["next"] = 0
        if draft:
            return {
                "agent_run": self._run_out(run),
                "text": "A plan in 3 steps.",
                "plan": plan,
                "blocked": [],
                "action": None,
                "draft": True,
            }
        return self._send_step(run, assessment)

    def _send_draft(self, run_id: str) -> dict:
        run = self.runs[run_id]
        if not run["plan"].get("draft") or run["agent_runs_status"] != "WAITING_APPROVAL":
            raise self.error(409, "NOT_A_DRAFT", "This plan was already sent.")
        run["plan"]["draft"] = False
        return self._send_step(run, self.assessments[run["assessment_id"]])

    def _next(self, assessment_id: str) -> dict:
        assessment = self._assessment(assessment_id)
        if not any(
            a["tool_runs"] for a in self.actions.values() if a["assessment_id"] == assessment_id
        ):
            raise self.error(409, "NO_TOOL_RESULTS", "No tool has run yet.")
        run_id = self._id("r")
        run = {
            "agent_run_id": run_id,
            "agent_runs_status": "RUNNING",
            "model_name": "fake",
            "started_at": now(),
            "finished_at": None,
            "session_id": assessment["session_id"],
            "assessment_id": assessment_id,
            "plan": {"task": "SUGGEST", "text": "Next."},
        }
        self.runs[run_id] = run
        return self._send_step(run, assessment)

    def _send_step(self, run: dict, assessment: dict) -> dict:
        """The agent's next step goes through the API's own path (send_action)."""
        i = assessment["next"]
        action = None
        if i < len(self.steps):
            assessment["next"] = i + 1
            action = self._new_action(
                assessment, self._plan_step(i, assessment["targets"][0]), self.steps[i][4]
            )
        if action is not None and action["approval_id"]:
            run["agent_runs_status"] = "WAITING_APPROVAL"
        else:
            run.update(agent_runs_status="COMPLETED", finished_at=now())
        steps = run["plan"].get("steps", [])
        return {
            "agent_run": self._run_out(run),
            "text": run["plan"]["text"],
            "plan": steps,
            "blocked": [],
            "action": action,
            "draft": False,
        }

    def _new_action(self, assessment: dict, step: dict, risk: str) -> dict:
        planned = step["action"]
        action_id = self._id("ac")
        action = {
            "action_id": action_id,
            "tool": planned["tool"],
            "args": planned["arguments"],
            "target": planned["target"],
            "purpose": step["phase"] or "scan",
            "risk_level": risk,
            "action_status": "PENDING",
            "guardrail_report": {
                "decision": "ALLOW",
                "risk_level": risk,
                "checks": ["INPUT", "SCOPE", "COMMAND", "RISK", "LOOP"],
            },
            "source": "AGENT",
            "created_at": now(),
            "assessment_id": assessment["assessment_id"],
            "manifest_id": assessment["manifest_id"],
            "approval_id": None,
            "tool_runs": [],
            "title": step["title"],
            "reason": step["reason"],
        }
        self.actions[action_id] = action
        if risk == "LOW":
            self._run_tool(action)
        else:
            command = shlex.join(
                [planned["tool"].lower(), *planned["arguments"], planned["target"]]
            )
            approval = self._approval(
                "action",
                {
                    "tool": planned["tool"],
                    "target": planned["target"],
                    "arguments": planned["arguments"],
                    "command": command,
                },
                risk,
            )
            approval["action_id"] = action_id
            action.update(approval_id=approval["approval_id"], action_status="PENDING")
        return {k: v for k, v in action.items() if k not in ("title", "reason")}

    def _run_tool(self, action: dict) -> None:
        """'Kali' runs the tool: its canned output, then the findings that output gives."""
        target = action["target"]
        output = self.outputs.get(action["tool"]) or (
            nmap_output(target)
            if action["tool"] == "NMAP"
            else f"{action['tool'].lower()} finished on {target}\n"
        )
        run_id = self._id("tr")
        action["tool_runs"].append(
            {
                "tool_run_id": run_id,
                "attempt_no": 1,
                "tool_run_status": "COMPLETED",
                "exit_code": 0,
                "error": None,
                "masked_count": 0,
                "request_count": 1,
                "output_masked": output,
                "started_at": now(),
                "finished_at": now(),
                "approval_id": action["approval_id"],
            }
        )
        action["action_status"] = "COMPLETED"
        for row in self.findings_for.get(action["tool"], []):
            self._add_finding(action, run_id, row)

    def _add_finding(self, action: dict, run_id: str, row: dict) -> None:
        finding_id = self._id("f")
        evidence = row.get("evidence_text") or ""
        target = action["target"]
        finding = {
            k: (v.replace("{target}", target) if isinstance(v, str) else v)
            for k, v in row.items()
            if k != "evidence_text"
        }
        finding.update(
            finding_id=finding_id,
            created_at=now(),
            assessment_id=action["assessment_id"],
            source_tool_run_ids=[run_id],
            latest_validation=None,
            evidence=[
                {
                    "evidence_id": self._id("ev"),
                    "kind": "TOOL_OUTPUT",
                    "content": evidence,
                    "location": None,
                    "created_at": now(),
                    "tool_run_id": run_id,
                }
            ]
            if evidence
            else [],
        )
        self.findings[finding_id] = finding

    def _set_summary_evidence(self, finding: dict, summary: str) -> None:
        """Keep the AI's plain reading as one analysis_summary evidence row, as the real API
        does, replacing any earlier one."""
        for row in finding.get("evidence", []):
            if row.get("kind") == "analysis_summary":
                row["content"] = summary
                return
        finding.setdefault("evidence", []).append(
            {
                "evidence_id": self._id("ev"),
                "kind": "analysis_summary",
                "content": summary,
                "location": None,
                "created_at": now(),
                "tool_run_id": None,
            }
        )

    def _analyze(self, assessment_id: str, body=None) -> dict:
        assessment = self._assessment(assessment_id)
        run_id = self._id("r")
        run = {
            "agent_run_id": run_id,
            "agent_runs_status": "COMPLETED",
            "model_name": "fake",
            "started_at": now(),
            "finished_at": now(),
            "session_id": assessment["session_id"],
            "assessment_id": assessment_id,
            "plan": None,
        }
        self.runs[run_id] = run
        rows = [f for f in self.findings.values() if f["assessment_id"] == assessment_id]
        wanted = set((body or {}).get("finding_ids") or [])
        if wanted:  # per-step analysis targets just this step's findings
            rows = [f for f in rows if f["finding_id"] in wanted]
        analysis = []
        for f in rows:
            # The ANALYZE step writes a plain-language analysis onto each finding, as the
            # real API now does, so GET /findings afterwards returns the filled-in texts.
            f["description"] = f"In plain terms: {f['title']}."
            f["impact"] = f"An attacker could abuse {f['title']}."
            f["remediation"] = f["remediation"] or "Close what is not needed."
            summary_text = f"The evidence shows {f['title']} plainly."
            self._set_summary_evidence(f, summary_text)
            analysis.append(
                {
                    "code": f["code"],
                    "explanation": f["description"],
                    "related": [],
                    "severity_status": f["severity_status"],
                    "cvss_score": None,
                    "evidence": "",
                    "evidence_summary": summary_text,
                    "impact": f["impact"],
                    "remediation": f["remediation"],
                    "cwe_ids": [],
                    "owasp_id": [],
                    "cve_ids": [],
                    "next_step": None,
                    "unsure": "",
                }
            )
        return {
            "agent_run": self._run_out(run),
            "summary": self.analysis_summary,
            "analysis": analysis,
        }
