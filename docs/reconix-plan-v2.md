# Reconix Plan v2

_Reconix · day 0 was Fri 23 Oct 2026 · Markdown copy of plan v2, exported Wed 28 Oct 2026._

_Updated Fri 30 Oct 2026: Reconix has no viewer or operator roles. Anyone with a session token can do everything._

What each of the 7 members does every week, from day 0 to the closing. The backend, the AI Service and the Kali tool container must be finished on Mon 2 Nov. Everything must be finished on Fri 20 Nov. The main rule: the AI suggests, the backend decides, and the tool container runs the tools.

## Official deadlines

| Date | Deadline |
|---|---|
| Thu 22 Oct | Design: scope, workflow, UX/UI, data dictionary, ERD |
| Mon 2 Nov | Backend, AI Service, Kali tool container 100% · book part 2 |
| Wed 4 Nov | Implementation 50% (first check) |
| Mon 16 Nov | Book part 3 |
| Fri 20 Nov | Implementation 100% |
| Fri 27 Nov | Testing and deployment done |
| Mon 30 Nov | Top team check |
| 1–3 Dec | Closing |

## Weeks at a glance

| Week | Dates | Theme |
|---|---|---|
| Week 1 | Fri 23 – Wed 28 Oct | Backend core and first flow |
| Week 2 | Thu 29 Oct – Mon 2 Nov | Backend 100% |
| Week 3 | Tue 3 – Wed 11 Nov | 50% check, frontend catches up |
| Week 4 | Thu 12 – Fri 20 Nov | Finish, freeze, v1.0.0 |
| Week 5 | Sat 21 – Fri 27 Nov | Test and deploy |

## Backend 100% on Mon 2 Nov

- **Backend API:** every endpoint, all 5 approval types, reports with sign-off and download, AI provider settings, web sign-in, timeline, and Docker.
- **Safety checks:** input, scope, command, risk and loop checks, hiding secrets, showing hidden values with approval, settings, AI provider safety, and the audit log.
- **AI Service:** knowledge search, the AI agent, the full analysis from workflow v5, choosing the AI provider, and the report text and files.
- **Kali tool container:** nmap, nuclei, ZAP, semgrep and gitleaks, reading their output, findings, evidence, and checking findings.

## Everything 100% on Fri 20 Nov

- The terminal app has every Figma screen and state.
- The local web has sign-in, the Terminal page, the timeline and reports.
- The VS Code extension (.vsix) and the public website are ready.
- We release v1.0.0. Then we test and put it online by Fri 27 Nov.

## Team rules

1.  We have 4 repos: **Reconix-Core** (backend API, AI agent, guardrails, database, terminal app, local web and the shared contracts), **Reconix-Kali-MCP** (Kali container, tools and execution wrappers), **Reconix-Public-Web** (public website and docs) and **Reconix-Vscode** (VS Code extension). Only change files in your own repo and folder.
2.  Parts only connect through the 6 shared functions and `openapi.json`.
3.  If someone's part is not ready, use its fake version. We swap in the real one on merge day.
4.  Use the names from ERD V3 and UPPERCASE values everywhere.
5.  Short 15-minute team check-in every morning. After Tue 17 Nov, only fix bugs.
6.  Youlong presents at every rehearsal (Mon and Thu, 2 to 5 PM). Sakphearoth backs Youlong up and assists. Everyone sends Youlong a 3-line update by 12 PM that day.

## If we fall behind, cut these first

1.  Findings shown inside the VS Code editor (keep the chat panel)
2.  The AI remembering past findings
3.  Word (DOCX) reports (keep PDF and JSON)
4.  Reports that combine several runs
5.  ZAP (keep the other 4 tools)
6.  Cloud AI providers: OpenAI, Anthropic, DeepSeek and OpenAI-compatible (keep RECONIX and Ollama on this computer)

Never cut: the scope check, approvals, hiding secrets, the audit log, and the full test.

> This plan follows AI Analysis Workflow v5, ERD V3 (16 tables), Conceptual ERD V4, Data Dictionary V3, the business rules from 21 Oct, and the Figma designs for the terminal app and the local web. The phone app and relay come later.

## Team

| Member | Role | Repo · folder |
|---|---|---|
| Yann Vanneth | Backend API, database, release, helps with the AI Service | Reconix-Core · services/api/ · services/ai/ (with Sakphearoth) |
| Chhim Pojim | Safety checks, Kali MCP safety, VS Code extension and project lead | Reconix-Core · services/ai/src/reconix_ai/harness/ · Reconix-Kali-MCP · Reconix-Vscode |
| Nut Youlong | Kali tool container, parsers and findings, VS Code extension, main presenter | Reconix-Kali-MCP · Reconix-Core parsers/ findings/ · Reconix-Vscode |
| Khin Sakphearoth | AI Service (with Vanneth), public website and backup presenter | Reconix-Core · services/ai/ · Reconix-Public-Web |
| Horn Vanhong | Terminal app (TUI and commands) | Reconix-Core · apps/tui/ |
| Nhoeun Sokpiseth | Local web app, Terminal app | Reconix-Core · apps/web/ · apps/tui/ |
| Choeng Sreyleak | Book, docs, public website, VS Code extension | Reconix-Public-Web · Reconix-Vscode (with Youlong and Pojim) |

## Week 1 · Backend core and first flow (Fri 23 – Wed 28 Oct)

**By the end of the week:** The main backend works with the real safety checks and the Kali tool container. On Tue 27 Oct we want to see one action travel all the way from a chat session to saved findings. The terminal app and the web should also show their first screens, using sample data for now.

**Key days**

- **Fri 23 Oct:** Day one: 2-hour team meeting
- **Mon 26 Oct:** Rehearsal, 2 to 5 PM
- **Tue 27 Oct:** Merge day

**Whole team**

- On day one we create the 4 repos together and agree on three things: the 6 shared functions, the table and value names from ERD V3, and how we name repos, folders and branches.
- We also close the gaps in the ERD. There is no `sessions.role` (Reconix has no roles); we use NONE for severity (V3 already chose NONE, not INFO), and use UNKNOWN wherever workflow v5 says NEEDS_REVIEW. We also decide how to handle imported findings and finding categories.
- Tue 27 Oct is merge day. We join everyone's code, run all the tests, and replace the fake parts with the real ones.
- On Wed 28 Oct each person shows the team that their week 1 "done when" check really works.

### Yann Vanneth: Backend API, database, release, helps with the AI Service

**Goal this week:** By the end of the week the project runs, all 16 tables exist, and the first flow works through the API: session, scope, action, approval and tool run.

- [ ] Start by creating the 4 GitHub repos: Reconix-Core for the backend, the AI, the terminal app and the local web; Reconix-Kali-MCP for the Kali tool container; Reconix-Public-Web for the website; and Reconix-Vscode for the extension. Give each member write access to the repo they work in. Set up automatic checks on every repo, so tests and code style run on each pull request.
- [ ] On day one, write the 6 shared functions that connect everyone's parts: who the operator is, the safety check, reading the approved scope, writing to the audit log, asking the AI agent, and calling a tool. Write a fake version of each one too, and push them the same day, so everyone can start without waiting for the others.
- [ ] Write the Docker Compose file. One command should start the database (PostgreSQL 16), the search store (Qdrant), the local AI model (Ollama) and the Kali tool container. The Kali container sits on a private network that nothing outside can reach. Until the first release, use the latest test image from the Kali repo.
- [ ] Build the SQLAlchemy models for all 16 tables. Use exactly the names and UPPERCASE values from ERD V3 and Data Dictionary V3. Keep it to one Alembic migration, and add the built-in RECONIX AI provider as starting data.
- [ ] Make the API safe from the start. It only listens on this computer, it rejects requests with a wrong host name, and it only accepts calls from the local web. Every error has the same shape: a code, a message and details. Also add a health check and a "who am I" endpoint.
- [ ] Build sessions, chat messages and scope, so a person can draft, edit, submit and approve a scope. When a scope is submitted, create a `scope` approval and a DRAFT assessment with a code like `RCX-2026-0001`. Once the scope is approved, the assessment becomes ACTIVE.
- [ ] Build `POST /assessments/{id}/actions`. Every action passes through the safety checks first. A BLOCKED action returns error 422, a LOW action runs right away, and MEDIUM or HIGH actions wait for a person to approve them. Save a masked copy of the action and its SHA-256 hash. For HIGH, the person must type the target to confirm. An approval expires after 30 minutes and can be used only once.
- [ ] Once an action is approved, run it. First check that the action was not changed after approval. Then save a new tool run, sign a one-time job pass, and call the tool through the MCP client. Save the output with secrets hidden, how many secrets were hidden, how many requests were sent and the final status, then hand the result to Youlong's code, which turns it into findings.
- [ ] Help Sakphearoth with the AI Service: connect the agent's saved progress (LangGraph) to the same PostgreSQL database, and test together that the API can call the AI Service directly as a Python package.

**Done when:** At the Tue 27 Oct merge you can use curl to open a session, approve a scope, send an action and approve it. nmap runs and the findings are saved.

**Gives:** the shared functions and the API description file (`openapi.json`) to everyone on day one. After every merge, publish a fresh copy in Reconix-Core, and the other repos copy it from there.

### Chhim Pojim: Safety checks, Kali MCP safety, VS Code extension and project lead

**Goal this week:** Every safety check works, so the first flow is safe from day one.

- [ ] On day one, lead the 2-hour team meeting. Help the team agree on the 6 shared functions, the names and values from ERD V3, and the rules for repos, folders and branches, then write a short summary in `Reconix-Core/docs/project-context.md`. The functions themselves live in code, in `core/interfaces.py`.
- [ ] Set up the safety checks inside the AI Service (the `harness` folder). It holds the 5 checks, the step that runs them in order, the secret hiding and the audit log. Start with a simple version of secret hiding for passwords and tokens; the full version comes in week 2. The checks never read the database themselves; the API gives them what they need. The agent runs the checks on every step it suggests, and the API runs them again just before any tool runs, so the agent can never skip them.
- [ ] Input check: block text longer than 4,000 characters, hidden control characters, and phrases that try to trick the AI (prompt injection).
- [ ] Scope check: a target is only allowed if it is an IP in an allowed range, an exact or allowed domain, an allowed URL start, or a repo or folder inside an allowed path. Block `..` in paths, and always block excluded targets. The check also looks at the time window and the allowed tools, actions and methods.
- [ ] Command check: only the 5 tools are allowed, each with its own list of allowed options, copied from `tool_specs.json` in the Kali repo (latest on `main` until the first release). Block shell characters, and always pass arguments as a list, never as one long string.
- [ ] Risk check: a rule table gives each tool and option a level of LOW, MEDIUM or HIGH. Anything unknown counts as HIGH, and checking a finding is at least MEDIUM. Anything above the scope's max risk is blocked.
- [ ] Loop check: block the same command on the same target if it runs more than 3 times in 10 minutes. Also block more than 20 actions in one minute, or more than 200 runs in one assessment.
- [ ] Run the checks in this order: input, scope, command, risk, loop. The first check that blocks stops everything. For the audit log, write one JSON line per event, with assessment_id, session_id, actor and the event types the web timeline needs.
- [ ] On day one, also add the instruction files for AI coding assistants to Reconix-Core: one main rules file for the repo, one short rules file for each part (API, AI, terminal app, web), and the shared skills and settings. You can start from the files in `core-agent-files.zip`.

**Done when:** Every check has unit tests, and Vanneth is using the real checks at the Tue 27 Oct merge.

**Gives:** the real safety checks to Vanneth by Mon 26 Oct.

### Nut Youlong: Kali tool container, parsers and findings, VS Code extension, main presenter

**Goal this week:** One Kali tool container runs all 5 tools safely through the MCP server.

- [ ] Build the lab: a Docker network called `reconix-lab` with OWASP Juice Shop, plus a small code repo that has known bugs and a fake secret. The tool container has no internet access.
- [ ] Together with Pojim, build the Kali tool container in its own repo, Reconix-Kali-MCP. Copy the layout and the build method of the open-source project `DansPK/kali-mcp-server`: a fixed Kali base image, fixed package versions, and a file that lists every installed version. Keep only our 5 tools (nmap, nuclei, ZAP, semgrep and gitleaks) and leave out the other 76, including Metasploit, password crackers and the free shell command. Unlike the original, run as a normal user, not as root, and give it only the network permission nmap needs. The container has no internet, so put the nuclei templates inside the image. Set up the repo so every merge publishes a test image and every release publishes a numbered image. Add the starter instruction files from `kali-mcp-agent-files.zip`.
- [ ] With Pojim, write the MCP server, the same way the original project does: the backend calls one web address, and each tool has its own small file that describes its options and builds its command. Every run goes through one shared helper that sets a time limit, checks the options and cuts output that is too long. Add our own check for the one-time job pass. The server only sends back the raw result: the status, the exit code, the screen output, the tool's own result file, how long it took, and whether the output was cut. It never reads the results or makes findings; the backend does that. The container opens no port to the outside, so only the backend can reach it, and it always asks for the access key, even though the original makes this optional.
- [ ] Build each command only from fixed fields, such as the target, the ports and the scan profile, and never from free text. Write the 5 tool descriptions to one shared file (`tool_specs.json`). It is the single source of truth: Pojim's command check and Sakphearoth's AI tool list both copy it from the Kali repo (from `main` until the first release, then from each release), so the three never disagree.
- [ ] With Pojim (who owns the safety rules), before running anything, check the one-time job pass: that it was really signed by the backend, that it has not expired, and that it has not been used before.
- [ ] Write the MCP client for the backend in `services/api/src/reconix_api/clients/`, a fake MCP server for the backend tests, and the nmap parser, so the Tue 27 Oct merge already saves findings. The other 4 parsers come in week 2.
- [ ] At the Mon 26 Oct rehearsal you present the plan, the architecture and ERD V3, and show the lab. Collect a 3-line update from each member by 12 PM, and write the mentor's feedback in your local `plan.md`, which is never pushed to GitHub.

**Done when:** Each of the 5 tools runs on the lab with a valid token, and a wrong or used token is refused.

**Gives:** the MCP client to Vanneth by Mon 26 Oct.

### Khin Sakphearoth: AI Service (with Vanneth), public website and backup presenter

**Goal this week:** The AI can talk to the model, find useful knowledge and suggest one step.

- [ ] Set up the AI Service as a Python package that the API calls directly; it has no web server of its own. Every call to an AI model goes through one file, using LiteLLM. By default it uses the built-in RECONIX model, which runs with Ollama on this computer.
- [ ] Set up the knowledge search in Qdrant. It should find text both by meaning (BGE-M3) and by exact words, so results are good for both questions and CVE numbers.
- [ ] Load the knowledge with LlamaIndex: 1,000 sample CVEs, CWE, OWASP Top 10, API Top 10, ATT&CK and the tool guides. Keep each CVE or CWE in its own piece, and cut long guides at their headings into short pieces. Hide any secrets before saving.
- [ ] Write `search_knowledge(query, filters)` on top of the hybrid search.
- [ ] On day two, agree with Vanneth on exactly what the backend sends to the AI, and on the shape of a plan and of a suggested action.
- [ ] Build the first agent steps with LangGraph: understand, find knowledge, plan, suggest and wait. Save its progress in Postgres.
- [ ] At the Mon 26 Oct rehearsal you back up and help Youlong. Prepare the AI flow slide, run the laptop during the demo, and write down every question from the mentor in your local `plan.md`.
- [ ] Write the Reconix agent's instructions as plain text files, not inside the Python code: the main prompt, and one prompt each for planning, analysis, reports and chat, plus the agent rules. Copy the shared tool descriptions from the Kali repo, so the model only sees the real tool options.

**Done when:** For an approved scope, the AI agent suggests one step and then waits.

**Gives:** the agreed AI input and output to Vanneth by Sat 24 Oct.  
**Help:** Vanneth helps with the AI Service from week 1: saving the agent's progress, AI provider settings, report files and speed.

### Horn Vanhong: Terminal app (TUI and commands)

**Goal this week:** The terminal app opens and shows the first Figma screens with sample data.

- [ ] Build the full-screen terminal app with Textual, and the commands (`reconix start`, `reconix web`) with Typer. It lives in the `apps/tui` folder of Reconix-Core. Reuse the screens, widgets, commands and chat shell from the old prototype, but leave its model calls and knowledge search behind: the terminal app only talks to the API.
- [ ] Go through the Figma TUI page (91 screens) and list the screens in the order of the 50% flow: Start, Template, Scope draft, Scope review, Plan, Approval card, Execution and Findings list.
- [ ] Write the code that talks to the API, using the API description file from Reconix-Core. Add a fake mode that reads the shared sample data in `apps/sample-data`, so you are never blocked by the backend.
- [ ] Build Start and chat, Template (network, web, api, source_code), and the Scope draft form with targets, excluded targets, tools, max risk, time window and methods.
- [ ] Add the slash commands, even if some of them do nothing yet: `/template /scope /approve /web /provider /model /help`.

**Done when:** You can go from Start to Scope review using sample data.

### Nhoeun Sokpiseth: Local web app

**Goal this week:** The local web runs with the main pages and sample data.

- [ ] Set up Next.js with TypeScript in `Reconix-Core/apps/web/`. Go through the Figma "Local Web UI" file. The pages are Overview, AI Assistant, Assessments, Findings (list and detail), Scope, Report, Terminal and Docs.
- [ ] Generate the request types from the API description file in Reconix-Core, and build a fake API that reads the same shared sample data as the terminal app (`apps/sample-data`). While you are at it, fix the sample data so each run has its own code and only our 5 tools appear. Reuse the pages, components and styles from the old prototype.
- [ ] Build the page layout and the menu.
- [ ] Build Assessments (a list with each status, including Stopped) and the Overview page for one run, with its plan steps.
- [ ] Build the Findings list with filters for severity, target, category, tool and check result.

**Done when:** The pages open on localhost with sample data.

### Choeng Sreyleak: Book, docs, public website, VS Code extension

**Goal this week:** Everyone works from the same documents, and book part 2 is planned.

- [ ] Update the business rules with what the team decided: no web roles, `report_assessments` and the ERD V3 status values.
- [ ] Tidy up the ERD V3 file: add divider lines inside each table and remove the yellow highlights.
- [ ] Write the outline for book part 2: analysis, planning (you can use this plan), system design and AI design.
- [ ] Draw the system design and the AI design, showing the agent steps and the knowledge search.
- [ ] Update the sample database data in Reconix-Core (`deploy/seed.sql`) to match ERD V3, then rebuild the shared sample files in `apps/sample-data` from it, so the terminal app, the web and the database all show the same examples.

**Done when:** The team agrees on the outline, and the diagrams are drawn.

## Week 2 · Backend 100% (Thu 29 Oct – Mon 2 Nov)

**By the end of the week:** This is the week the backend, the AI Service and the Kali tool container are finished. The full test should run from start to end, from writing a scope all the way to downloading the report.

**Key days**

- **Thu 29 Oct:** Rehearsal, 2 to 5 PM
- **Sat 31 Oct:** Merge day · full test
- **Mon 2 Nov:** Backend 100% · book part 2 due

**Whole team**

- On Sat 31 Oct we join all the backend code and run the full test: scope, plan, approve, run, analyze, check, report and download.
- On Mon 2 Nov morning we fix whatever failed. By the end of that day the backend, the AI Service and the Kali tool container are done.
- Also on Mon 2 Nov we submit book part 2 and show the backend live at the rehearsal.
- Meanwhile on the frontend, the terminal app should already show the main flow using the real backend.

### Yann Vanneth: Backend API, database, release, helps with the AI Service

**Goal this week:** Every backend feature is built by Mon 2 Nov.

- [ ] Build the planning endpoint. It starts an AI run with the chosen provider and model, asks the AI Service for a plan, and saves the steps. The run goes from running, to waiting for approval, and then ends as completed, failed or cancelled. Save where the run stopped, so it can continue after a person approves.
- [ ] Build the endpoints that read data: waiting approvals, actions (list and detail), findings (list and detail), masked evidence, check runs and AI runs.
- [ ] Build the 6 endpoints for AI providers. Encrypt API keys with Fernet and only ever show the last 4 characters. Only one provider can be active at a time, and a provider that runs outside this computer needs a `configuration` approval first.
- [ ] Build reports. Each new version saves a locked, masked copy of the data together with its hash. The status moves from GENERATING to READY or FAILED. A combined report covers 2 to 5 assessments (`report_assessments`), and sign-off is a `review` approval. A report can only be downloaded once it is READY and signed off. Sakphearoth will give you the PDF, DOCX and JSON files.
- [ ] Connect Pojim's parts to the API: showing hidden values, limit settings, the timeline endpoint and the web sign-in.
- [ ] Put every backend service in Docker Compose. Write `install.sh` and the uv install steps so they install `Reconix-Core` (backend, terminal app and local web) and pull the Kali image, and one command starts everything.
- [ ] On Sat 31 Oct, join the code and run the full test. On Mon 2 Nov, fix whatever failed and save the final `openapi.json`.
- [ ] Help Sakphearoth with the AI Service: connect the AI provider settings you store (with encrypted keys) to the AI Service's model calls, and build the report files (PDF, DOCX and JSON) from the locked report copy together.

**Done when:** The full test passes from start to end: scope, plan, approve, run, analyze, check, report and download.

**Needs by Sat 31 Oct:** Pojim's safety parts, Youlong's findings and checks, and Sakphearoth's AI agent and report files.

### Chhim Pojim: Safety checks, Kali MCP safety, VS Code extension and project lead

**Goal this week:** Every safety part is built by Mon 2 Nov.

- [ ] Secret hiding: replace passwords, tokens, API keys, private keys and login tokens with a label such as [MASKED:password], and count how many you hid. This always happens before anything is saved, shown, sent to the AI or stored in the search store.
- [ ] Showing hidden values: keep the real values in a protected folder. With a `disclosure` approval, a person can see one value, one time.
- [ ] Settings: changing a limit creates a `configuration` approval, and the new limit only takes effect after it is approved.
- [ ] AI provider safety: require HTTPS unless the provider runs on this computer. Reject addresses that contain a user name or password, and reject cloud metadata addresses. The API key must never appear in the logs.
- [ ] Web sign-in: `/web` creates a random token, kept only in memory. There are no roles: a signed-in person can do everything. Write a test that every endpoint refuses a request without a token.
- [ ] Timeline: write a function that reads the audit log and returns the lines for one assessment. Vanneth will expose it as `GET /assessments/{id}/timeline`.
- [ ] Tune the risk rules using real commands from the Kali tool container.

**Done when:** A leak test finds no secret in the database, the logs, the AI messages or Qdrant, and every endpoint refuses a request without a token (error 401).

### Nut Youlong: Kali tool container, parsers and findings, VS Code extension, main presenter

**Goal this week:** By Mon 2 Nov every tool result becomes findings, and checking findings works.

- [ ] In Reconix-Core (the `parsers` folder of the API), write the code that reads each tool's raw result file: nmap and ZAP reports, nuclei, semgrep and gitleaks results.
- [ ] Turn every result into the same finding shape: a title, the target, a description, the severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN or NONE), the CVSS score, the CWE, OWASP and CVE ids, and where it was found. If the tool does not give a clear severity, use UNKNOWN instead of guessing. When two tools find the same thing, save one finding that lists both sources.
- [ ] For each piece of proof, save an evidence record: what was found (with secrets hidden), where it was found, and which tool run found it. Also count how many requests each run sent.
- [ ] Finding review: a person marks a finding as OPEN, FALSE_POSITIVE or FIXED. Save who did it and when, and write it to the audit log.
- [ ] Checking a finding: a proof test (PoC) is a normal action marked as a check. Its result is saved as a check run, and the finding always shows the newest check. A person can also check a finding by hand.
- [ ] Errors: give each tool a time limit. If the container is down, show a clear error and set the status to TIMED_OUT or FAILED, so nothing ever stays stuck.
- [ ] You present at the Thu 29 Oct and Mon 2 Nov rehearsals. On 2 Nov, show the backend live: scope, approve, tool run, findings, AI analysis and report. Practise it once on Sat 31 Oct after the merge.
- [ ] Write a short guide for each of the 5 tools as plain documents in the AI Service's knowledge folder: when to use the tool, what its options mean, and how to read its result. Sakphearoth loads them into the knowledge search, so the agent finds them like any other knowledge. The allowed options themselves come only from the shared tool description file.

**Done when:** Each tool gives the expected findings on the lab, and a proof test saves a `validation_runs` row that the finding shows as its newest check.

### Khin Sakphearoth: AI Service (with Vanneth), public website and backup presenter

**Goal this week:** The full AI analysis and the report files are done by Mon 2 Nov.

- [ ] Add the step where the AI reads a result and thinks again before deciding (ReflAct): it writes one line about what it knows now and how close it is to the goal. It may do this up to 5 times, and only with tools that read, never with tools that change anything.
- [ ] Build the 8 parts of the analysis from workflow v5, each with its own rule: identify, connect related results, severity, evidence, impact, fix, mapping and next step. Whenever the AI is not sure, a person makes the call.
- [ ] Use whichever AI provider is set as active. Support all 6 provider types: the built-in RECONIX model, Ollama, OpenAI, Anthropic, DeepSeek, and any OpenAI-compatible service at a custom address. Never show an API key, only its last 4 characters, and save which provider and model each run used.
- [ ] Add limits on the number of steps and the token budget. If the AI gives a bad answer, try once more, and show a clear error when the model is down.
- [ ] Report text and files: write the summary and the method section from the locked copy of the data, and make PDF, DOCX and JSON files. Hand them to Vanneth's report endpoint.
- [ ] Save accepted findings (masked) in Qdrant, so the AI can answer questions about them later.
- [ ] At the Thu 29 Oct and Mon 2 Nov rehearsals, help Youlong and answer the questions about the AI and the reports. Learn the full demo so you can take over if Youlong is away.

**Done when:** On 10 saved tool outputs, the AI follows all 8 rules, and a report exports in all 3 formats.

### Horn Vanhong: Terminal app (TUI and commands)

**Goal this week:** The 50% flow works in the terminal app with the real API.

- [ ] Switch over to the real API: open a session, submit the scope and approve it.
- [ ] Plan screen: show the steps from `agent_runs.plan` along with their status.
- [ ] Approval card: show the tool, target, risk, safety check result and why the AI wants to run it. LOW runs by itself, MEDIUM shows Approve and Reject, and HIGH asks you to type the target.
- [ ] Execution screen: refresh every 2 seconds and show which steps are blocked, waiting, running or finished.
- [ ] Build the findings list (severity, title, target, tool) and a simple detail view with the masked evidence.
- [ ] Practise the demo on Sat 31 Oct and Mon 2 Nov.

**Done when:** The 50% flow runs from the terminal app alone, with no other app needed.

### Nhoeun Sokpiseth: Local web app

**Goal this week:** The web shows real data from the 50% flow.

- [ ] Sign-in: read the token from the link that `/web` prints. Keep it in memory only, and send it with every request.
- [ ] Connect Assessments, Overview and Findings to the real API.
- [ ] Finding detail: show the masked evidence and the check result.
- [ ] Scope page: show the approved version with its targets, excluded targets, tools, max risk and time window.
- [ ] Get the pages ready for the 50% demo on Wed 4 Nov.

**Done when:** After a run in the terminal app, the web shows the same findings.

### Choeng Sreyleak: Book, docs, public website, VS Code extension

**Goal this week:** Book part 2 is submitted on Mon 2 Nov.

- [ ] Write the analysis and planning sections. Ask each member for one paragraph about their part.
- [ ] Add the diagrams and ERD V3 to the book.
- [ ] Make a template for rehearsal notes in the local `plan.md` for Youlong, and share it in the team chat, not on GitHub.
- [ ] Start the user guide: how to install, start and run a first assessment.

**Done when:** Book part 2 is submitted on Mon 2 Nov.

## Week 3 · 50% check, frontend catches up (Tue 3 – Wed 11 Nov)

**By the end of the week:** We pass the 50% check. The backend is tested and stable, and the terminal app and the web now use every backend feature.

**Key days**

- **Tue 3 Nov:** Release v0.1.0
- **Wed 4 Nov:** Implementation 50% (first check)
- **Thu 5 Nov:** Rehearsal at CKCC (check: 5 or 6 Nov)
- **Mon 9 Nov:** Rehearsal, 2 to 5 PM
- **Tue 10 Nov:** Merge day · full test with the frontend

**Whole team**

- On Tue 3 Nov we tag v0.1.0 in all 4 repos and practise the demo one more time.
- On Wed 4 Nov we install Reconix on a fresh computer in the morning, and then we go into the 50% check.
- On Tue 10 Nov we join the code again and run the full flow, both from the terminal app and from the web Terminal page.
- Whenever the frontend team reports a bug, the backend members fix it on the same day.

### Yann Vanneth: Backend API, database, release, helps with the AI Service

**Goal this week:** Keep the backend stable and safe while the frontend connects to it. The 50% check is on Wed 4 Nov.

- [ ] On Tue 3 Nov, release `v0.1.0`. On Wed 4 Nov morning, install everything on a fresh computer using only the README, and then go into the 50% check.
- [ ] Build a WebSocket that opens the terminal app inside the browser. The handshake checks the session token and the `Origin` (the Host check does not cover WebSockets). Sokpiseth's Terminal page will connect to it.
- [ ] Add live updates (`GET /stream`) so the screens see new approvals and run progress straight away.
- [ ] Add security tests for too many requests, a wrong Host, requests from other websites, and a request without a token. Also add tests that check every endpoint still matches `openapi.json`.
- [ ] Add database indexes so the list filters stay fast, and check the speed with the sample data.
- [ ] Answer frontend questions on the same day, and fix the API bugs they find before anything else.
- [ ] Help Sakphearoth time one full AI step on the demo laptop, and fix any slow API calls around it.

**Done when:** The API tests pass, and the web Terminal page runs the terminal app.

### Chhim Pojim: Safety checks, Kali MCP safety, VS Code extension and project lead

**Goal this week:** Prove that nobody can trick the checks, and lead the team through the 50% check.

- [ ] Test the scope and command checks with lots of random inputs using Hypothesis.
- [ ] Try the hard cases too: IPv6, special domain names (punycode), encoded URLs, path tricks, and hidden options such as `-oN /etc/x`.
- [ ] Run all 5 tools on the lab and make sure every secret is hidden and every decision has exactly one line in the audit log.
- [ ] Lead the 50% check on Wed 4 Nov, and keep the 15-minute team check-in going every morning.

**Done when:** None of the hard cases get through.

### Nut Youlong: Kali tool container, parsers and findings, VS Code extension, main presenter

**Goal this week:** Every tool works from the terminal app, and the 50% demo data is ready.

- [ ] Run each tool from the terminal app through the backend, and compare the findings with the list of what you expect.
- [ ] Fix bugs in the output readers, and make the image smaller and faster to start.
- [ ] Prepare clean demo data on the lab for Wed 4 Nov and for the frontend team.
- [ ] You present at the Thu 5 Nov (CKCC) and Mon 9 Nov rehearsals. Show the 50% results and the flow in the terminal app, then fix the demo steps the mentor asks about.
- [ ] VS Code extension, together with Sreyleak: in `Reconix-Vscode`, build the "Scan this folder" command. It sends the open folder to the backend as a source code test with semgrep and gitleaks.

**Done when:** The 50% demo runs on real tools on the first try.

### Khin Sakphearoth: AI Service (with Vanneth), public website and backup presenter

**Goal this week:** The AI is tested, improved and fast enough for the demo.

- [ ] Write 20 test questions with their correct answers, and measure how often the right answer shows up in the top 3 results.
- [ ] Time one full step on the demo laptop. If it is too slow, improve the prompts or switch the model.
- [ ] Start book part 3 with Sreyleak by writing the AI part.
- [ ] At the Thu 5 Nov (CKCC) and Mon 9 Nov rehearsals, help Youlong. Keep a copy of the demo data and the slides on a second laptop, just in case.

**Done when:** The search score is written down, and one step is fast enough on the demo laptop.

### Horn Vanhong: Terminal app (TUI and commands)

**Goal this week:** Every screen we need exists.

- [ ] Finding detail: let the person mark a finding OPEN, FALSE_POSITIVE or FIXED, show the past checks, and add a Request PoC button.
- [ ] Reports: make a new version, see the list, ask for sign-off and export. For a combined report, the person picks 2 to 5 runs.
- [ ] The `/provider` and `/model` screens: list providers, add one (with a hidden key field), test it and make it active.
- [ ] Add the windows for the other approval types: showing a hidden value, changing settings and signing off a report.
- [ ] Make `/web` print the sign-in link.

**Done when:** Every Figma screen we need has a working version.

### Nhoeun Sokpiseth: Local web app

**Goal this week:** A signed-in person can do everything in the browser.

- [ ] Terminal page: use xterm.js to connect to Vanneth's WebSocket, which runs the terminal app. Add the Restart window too.
- [ ] Timeline on Overview: read `/assessments/{id}/timeline` and show a chart grouped by event type.
- [ ] Report page: show one run or a combined report (2 to 5 runs), the version and the sign-off status. Download only works when the report is READY and signed off. Also show the error state when an export fails.
- [ ] AI Assistant page: a signed-in person can chat. Show "No model set up" when there is no AI provider.

**Done when:** A signed-in person can run the full flow from the browser.

### Choeng Sreyleak: Book, docs, public website, VS Code extension

**Goal this week:** The website exists, and work on the VS Code extension has started.

- [ ] Build the public website in the Reconix-Public-Web repo as a simple static Next.js site: a home page, and a getting-started page that explains both ways to install. Add the starter instruction files from `public-web-agent-files.zip`, and set the site to publish to GitHub Pages automatically.
- [ ] Write the docs pages in `Reconix-Public-Web`: commands, templates, scope fields, approvals, safety and limits.
- [ ] VS Code extension, together with Youlong: build the base in the Reconix-Vscode repo, with a chat panel that talks to the Reconix API on this computer. Use the API description file for the request types, and keep the sign-in token in VS Code's secure storage. Add the starter instruction files from `vscode-agent-files.zip`. Ask Vanhong for help with the API code.
- [ ] Start book part 3 with the use case diagram and the screen designs from Figma.

**Done when:** The website runs on your computer, and the VS Code chat panel answers.

## Week 4 · Finish, freeze, v1.0.0 (Thu 12 – Fri 20 Nov)

**By the end of the week:** Every feature is finished and looks good. We release v1.0.0 and submit it.

**Key days**

- **Thu 12 Nov:** Rehearsal, 2 to 5 PM
- **Fri 13 Nov:** Bug hunt
- **Mon 16 Nov:** Book part 3 due
- **Tue 17 Nov:** Feature freeze (no new features)
- **Wed 18 Nov:** Full demo run
- **Thu 19 Nov:** Rehearsal, 2 to 5 PM
- **Fri 20 Nov:** Implementation 100%

**Whole team**

- Fri 13 Nov is our bug hunt. Each person tries to break a part that someone else built.
- On Sat 14 Nov we fix the bugs we found in the bug hunt.
- Tue 17 Nov is feature freeze. From this day on we only fix bugs and add nothing new.
- On Wed 18 and Thu 19 Nov we run the whole demo from start to end and fix anything that breaks.
- On Fri 20 Nov we release v1.0.0 in all 4 repos and submit the 100% implementation.

### Yann Vanneth: Backend API, database, release, helps with the AI Service

**Goal this week:** The API stops changing, and v1.0.0 is released.

- [ ] On Fri 13 Nov, join the bug hunt and fix backend bugs first.
- [ ] From Tue 17 Nov the features are frozen, so you only fix bugs.
- [ ] Help Sreyleak connect the VS Code extension to the API.
- [ ] On Fri 20 Nov, release `v1.0.0` in all 4 repos.

**Done when:** No backend bugs are left, and v1.0.0 is released.

### Chhim Pojim: Safety checks, Kali MCP safety, VS Code extension and project lead

**Goal this week:** Finish the security review, start the freeze and write the demo script.

- [ ] Go through the security of every endpoint together with the team.
- [ ] Lead the bug hunt on Fri 13 Nov, and on Tue 17 Nov tell everyone that the feature freeze has started.
- [ ] Write the demo script for the rehearsals together with Youlong.

**Done when:** No bug on the list blocks the release.

### Nut Youlong: Kali tool container, parsers and findings, VS Code extension, main presenter

**Goal this week:** Every tool is stable for the final demo.

- [ ] Fix the tool bugs from the Fri 13 Nov bug hunt.
- [ ] Write the demo script with Pojim, with help from Sakphearoth.
- [ ] On Wed 18 and Thu 19 Nov, run the full demo from start to end and fix what breaks. Submit on Fri 20 Nov.
- [ ] You present at the Thu 12, Mon 16 and Thu 19 Nov rehearsals. On 16 Nov, show the almost-final demo, and fix what the mentor asks for before Fri 20 Nov.
- [ ] VS Code extension: show the findings in a tree view and as warnings on the right file and line. Test the `.vsix` with Sreyleak on Tue 17 Nov.

**Done when:** The full demo runs on real tools on the first try.

### Khin Sakphearoth: AI Service (with Vanneth), public website and backup presenter

**Goal this week:** Book part 3 is submitted and the AI is stable.

- [ ] Improve the prompts based on what the bug hunt found.
- [ ] Write the AI test results section, and submit book part 3 on Mon 16 Nov.
- [ ] At the Thu 12, Mon 16 and Thu 19 Nov rehearsals, help Youlong. Give Youlong the AI test numbers and help write the demo script. Practise the full talk once yourself, as the backup.

**Done when:** Book part 3 is submitted.

### Horn Vanhong: Terminal app (TUI and commands)

**Goal this week:** Every state works and looks like the Figma design.

- [ ] Add the remaining states: stopped (CANCELLED), approval expired, step failed with a Retry button, blocked, no model set up, and server error.
- [ ] Once Vanneth has live updates ready, use them instead of asking the server again and again.
- [ ] Write tests for the main flow with Textual's test tool (pilot).
- [ ] Polish the screens so they match Figma. Tue 17 Nov is feature freeze.

**Done when:** The main flow test passes, and the screens match Figma.

### Nhoeun Sokpiseth: Local web app

**Goal this week:** The web looks finished and is tested.

- [ ] Add empty, loading and error states to every page.
- [ ] Use live updates for new approvals and progress.
- [ ] Write Playwright tests for the main pages.
- [ ] Tue 17 Nov is feature freeze. After that, help Sreyleak with the VS Code extension if Sreyleak needs it.

**Done when:** The Playwright tests pass.

### Choeng Sreyleak: Book, docs, public website, VS Code extension

**Goal this week:** Book part 3 and the VS Code extension are done.

- [ ] VS Code: connect Youlong's folder scan and findings view to the chat panel, so a person can ask the AI about a finding. Add approve and reject for waiting actions.
- [ ] Build the `.vsix` file on Tue 17 Nov and test that it installs.
- [ ] Write book part 3 with Sakphearoth: implementation, test results, conclusion and references. Submit it on Mon 16 Nov.
- [ ] Finish the website docs and the examples page.

**Done when:** Book part 3 is submitted, and the .vsix installs.

## Week 5 · Test and deploy (Sat 21 – Fri 27 Nov)

**By the end of the week:** Someone who has never used Reconix installs it from the website and runs a full test on the lab without our help.

**Key days**

- **Mon 23 Nov:** Fresh install test · rehearsal, 2 to 5 PM
- **Tue 24 Nov:** Website online · GitHub release
- **Thu 26 Nov:** Best team vote at rehearsal
- **Fri 27 Nov:** Testing and deployment done
- **Mon 30 Nov:** Top team evaluation
- **1–3 Dec:** Closing

**Whole team**

- On Sat 21 Nov we start the full test round. Each person tests a part that someone else built, following a written checklist.
- On Mon 23 Nov we install Reconix on a fresh computer twice: once with uv and once with the bash script.
- On Tue 24 Nov we put the website online and publish the release, together with the VS Code extension file (.vsix).
- On Thu 26 Nov we practise the demo, and it is also the day of the best team vote.
- On Fri 27 Nov we submit testing and deployment.

### Yann Vanneth: Backend API, database, release, helps with the AI Service

**Goal this week:** Reconix installs cleanly on a fresh computer, and the release is public.

- [ ] Install Reconix on a fresh computer twice, once with uv and once with the bash script, and fix anything that fails.
- [ ] Make a GitHub release in each repo: Reconix-Core with the install script, the terminal app and the web, Reconix-Kali-MCP with the tool image, and Reconix-Vscode with the extension file (.vsix).
- [ ] Fix the bugs found in the team test round.

**Done when:** Someone new installs Reconix from the website and runs a full test.

### Chhim Pojim: Safety checks, Kali MCP safety, VS Code extension and project lead

**Goal this week:** Reconix passes a security test from a user's point of view.

- [ ] Go through the security checklist on a fresh install.
- [ ] Check the demo flow with Youlong before Thu 26 Nov and before Mon 30 Nov.

**Done when:** Every item on the checklist passes.

### Nut Youlong: Kali tool container, parsers and findings, VS Code extension, main presenter

**Goal this week:** The presentation is ready.

- [ ] Run every tool on the fresh install.
- [ ] Practise the presentation for Thu 26 Nov and Mon 30 Nov.
- [ ] At the Mon 23 and Thu 26 Nov rehearsals, give the full talk and demo on the fresh install in 15 minutes. Get ready for the best team vote and for Mon 30 Nov.

**Done when:** The talk fits in 15 minutes.

### Khin Sakphearoth: AI Service (with Vanneth), public website and backup presenter

**Goal this week:** The AI works on a fresh install.

- [ ] Check the AI on the fresh install using only the local model.
- [ ] Do the final edit of the book.
- [ ] At the Mon 23 and Thu 26 Nov rehearsals, help Youlong and keep the list of questions and answers. Be ready to give the full talk if needed.

**Done when:** The AI answers during the demo without any errors.

### Horn Vanhong: Terminal app (TUI and commands)

**Goal this week:** The terminal app works on a fresh install.

- [ ] Test it on the fresh computer and fix any bugs.
- [ ] Help the team with the demo.

**Done when:** No bugs are left in the terminal app.

### Nhoeun Sokpiseth: Local web app

**Goal this week:** The web works on a fresh install.

- [ ] Test it on the fresh computer and fix any bugs.
- [ ] Help Sreyleak put the public website online.

**Done when:** No bugs are left in the web app.

### Choeng Sreyleak: Book, docs, public website, VS Code extension

**Goal this week:** The website is online and the docs are correct.

- [ ] Put the website online, for example on GitHub Pages, and link the release and the .vsix file.
- [ ] Check every doc page against the real app.
- [ ] Make the closing slides.

**Done when:** A stranger can install Reconix from the website.

---

## Appendix: project structure

Four repos. `Reconix-Core` has the shared backend API, the AI agent, guardrails, the database, the terminal app, the local web and the shared contracts. `Reconix-Kali-MCP` has the Kali container, the tools and the execution wrappers. `Reconix-Public-Web` is the website and docs. `Reconix-Vscode` is the VS Code extension.

### Rules

1. Top level: `README.md`, `AGENTS.md`, `.gitignore`, `.env.example`, `.github/workflows/`, `services/`, `apps/`, `deploy/`, `docs/`.
2. Each service (`api`, `ai`) and app (`tui`, `web`) has its own folder, `AGENTS.md` and package file. Python packages use the `src/` layout. The Kali tool container lives in its own repo, `Reconix-Kali-MCP`, with the same layout as `DansPK/kali-mcp-server`, cut down to our 5 tools. The backend only talks to it through MCP and pulls its image by tag.
3. Code is split by job: **api** (routes) → **services** (logic) → **repositories** (database) → **models** (tables).
4. Tests mirror the source folders. `tests/unit/x` tests `src/.../x`.
5. Use `snake_case` for Python files and folders.
6. No secrets in Git. Only `.env.example` is committed.
7. Export `openapi.json` to `docs/` after every merge.
8. `docs/` keeps only a short project context, the API contract and the ERD. Your `plan.md` (tasks, rehearsal notes) stays on your own computer. It is in `.gitignore` and is never pushed.

```text
Reconix-Core/
├── README.md
├── AGENTS.md                   # rules for AI coding agents, whole repo
├── CLAUDE.md                   # one line: @AGENTS.md
├── .mcp.json                   # MCP servers for coding agents (optional)
├── pyproject.toml              # uv workspace
├── uv.lock
├── .env.example
├── .gitignore                  # .env, plan.md
├── plan.md                     # local only, never pushed: your tasks and rehearsal notes
├── .github/workflows/ci.yml
│
├── .claude/
│   ├── settings.json           # allowed commands, hooks (ruff, pytest)
│   ├── skills/                 # how-to guides for coding agents
│   │   ├── add-endpoint/SKILL.md
│   │   ├── add-db-migration/SKILL.md
│   │   ├── add-guardrail-check/SKILL.md
│   │   ├── run-full-flow-test/SKILL.md
│   │   └── write-simple-code/SKILL.md
│   └── agents/
│       └── security-reviewer.md
│
├── services/
│   ├── api/                    # Backend API
│   │   ├── AGENTS.md           # rules for this service
│   │   ├── pyproject.toml
│   │   ├── alembic/
│   │   ├── src/reconix_api/
│   │   │   ├── main.py
│   │   │   ├── core/           # config, errors, security, interfaces.py
│   │   │   ├── api/            # routes, one file per resource
│   │   │   ├── services/       # business logic
│   │   │   ├── repositories/   # database queries
│   │   │   ├── models/         # SQLAlchemy tables (ERD V3)
│   │   │   ├── schemas/        # Pydantic requests and responses
│   │   │   ├── clients/        # MCP client, AI Service client
│   │   │   ├── parsers/        # read raw tool output: nmap XML, nuclei JSONL, ZAP, semgrep, gitleaks JSON
│   │   │   └── findings/       # normalize to one finding shape, dedupe_key
│   │   └── tests/
│   │       ├── fakes/
│   │       ├── unit/
│   │       ├── contract/
│   │       ├── security/
│   │       └── e2e/            # full-flow test
│   │
│   └── ai/                     # AI Service
│       ├── AGENTS.md
│       ├── pyproject.toml
│       ├── src/reconix_ai/
│       │   ├── contracts.py    # Plan, ProposedAction
│       │   ├── prompts/        # Reconix agent prompts, one file per step
│       │   │   ├── system.md
│       │   │   ├── plan.md
│       │   │   ├── analyze.md
│       │   │   ├── report.md
│       │   │   └── chat.md
│       │   ├── tool_specs/     # tool schemas the model may call (JSON)
│       │   ├── policies/
│       │   │   └── agent-rules.md  # suggest only, never run, never leave scope
│       │   ├── providers/      # LiteLLM
│       │   ├── knowledge/      # ingest, Qdrant, search
│       │   ├── agent/          # LangGraph graph and nodes
│       │   ├── analysis/       # the 8 parts of workflow v5, incl. severity and OWASP mapping rules
│       │   ├── reports/        # text, PDF, DOCX, JSON
│       │   ├── memory/
│       │   └── harness/        # safety checks (owner: Pojim). The API calls check() before every tool run
│       │       ├── checks/     # input, scope, command, risk, loop
│       │       ├── pipeline.py
│       │       ├── masking.py
│       │       └── audit.py
│       ├── data/
│       │   └── tool-guides/    # one Markdown guide per tool, loaded into the knowledge search
│       └── tests/
│           └── evals/          # 20 test questions, expected answers
│
├── apps/
│   ├── sample-data/            # shared fake data for the TUI fake mode and the web fake API
│   │   ├── make_sample_data.py # builds the JSON files from deploy/seed.sql
│   │   └── *.json              # sessions, assessments, findings, reports
│   │
│   ├── tui/                    # Terminal app (Textual, Typer). Owner: Sokpiseth
│   │   ├── AGENTS.md
│   │   ├── pyproject.toml      # reconix-tui, in the uv workspace
│   │   ├── scripts/
│   │   │   └── export_commands.py  # command list for the docs site
│   │   ├── src/reconix_tui/
│   │   │   ├── app.py          # Textual app
│   │   │   ├── commands/       # Typer: reconix start, reconix web; slash commands
│   │   │   ├── shell/          # chat input, slash-command parser, history
│   │   │   ├── flow/           # which screen comes next (UI flow only, no agent logic)
│   │   │   ├── screens/        # start, template, scope, plan, approval, execution, findings, reports, provider
│   │   │   ├── widgets/        # approval card, finding row, status badge
│   │   │   ├── state/          # in-memory UI state, saves nothing
│   │   │   └── api/            # httpx client + models from openapi.json, fake mode
│   │   └── tests/              # Textual pilot tests
│   │
│   └── web/                    # Local web (Next.js, xterm.js). Owner: Sokpiseth
│       ├── AGENTS.md
│       ├── package.json
│       ├── public/
│       ├── scripts/            # gen-api-types (openapi-typescript)
│       ├── src/
│       │   ├── app/            # overview, assistant, assessments, findings, scope, report, terminal, docs
│       │   ├── components/
│       │   ├── content/        # short in-app docs text
│       │   ├── lib/
│       │   │   ├── api/        # types from openapi.json, fake API reading ../sample-data
│       │   │   └── auth/       # token from the /web link, in memory only
│       │   └── styles/
│       └── tests/
│           ├── unit/
│           └── e2e/            # Playwright
│
├── deploy/
│   ├── docker-compose.yml      # PostgreSQL, Qdrant, Ollama, api, kali-mcp image from Reconix-Kali-MCP (internal network only)
│   ├── lab/                    # Juice Shop and a test repo
│   ├── seed.sql                # sample data (ERD V3)
│   └── install.sh
│
└── docs/                       # project context only
    ├── project-context.md      # one page: what Reconix is, the main rule, the 4 repos, who owns what
    ├── openapi.json            # API contract, the other repos copy it
    └── erd/                    # ERD V3
```

---

### Reconix-Kali-MCP

Owners: Youlong and Pojim. The image is published from this repo on every tag. `Reconix-Core` pulls it by tag and calls it through the MCP client in `services/api/src/reconix_api/clients/`. It returns raw output only. Parsing and findings happen in the backend (`parsers/`, `findings/`).

```text
Reconix-Kali-MCP/               # Kali tool container + MCP server (same layout as DansPK/kali-mcp-server)
├── README.md                   # build, run, what we removed from the base repo and why
├── AGENTS.md                   # rules for AI coding agents
├── CLAUDE.md                   # one line: @AGENTS.md
├── .gitignore                  # .env, plan.md
├── plan.md                     # local only, never pushed
├── .claude/skills/add-tool-runner/SKILL.md
├── .github/workflows/ci.yml    # ruff, pytest, image build; publish :dev on merge, versioned on tag
├── tool_specs.json             # the 5 tool schemas: one source of truth, copied by the backend
├── pyproject.toml              # kali-mcp, mcp>=1.9,<2
├── Dockerfile                  # AMD64 Kali image: kali-last-release by digest, 5 tools, non-root
├── docker-compose.yml          # run this container alone, cache volumes
├── docker-run.sh               # build, run, release tag
├── TOOLS.md                    # reference for the 5 tools and their fields
├── docker/                     # pinned dependencies and container settings
│   ├── scanner-requirements.txt  # semgrep in its own venv
│   ├── server-requirements.txt   # pinned MCP server packages
│   └── config/                 # nuclei templates list, ZAP settings, semgrep rules
├── src/kali_mcp/
│   ├── server.py               # CLI, Streamable HTTP on /mcp, auth, MCP handlers
│   ├── auth.py                 # Reconix add-on: single-use job token (HMAC)
│   ├── result.py               # raw result: status, exit_code, stdout, stderr, output file, duration_ms, truncated
│   └── tools/                  # tool schemas, argument builders, execution gateway
│       ├── base.py             # timeouts, argument checks, output cap
│       ├── network.py          # nmap
│       ├── web.py              # nuclei
│       ├── zap.py              # ZAP daemon: start, spider, active scan, alerts, report
│       └── source.py           # semgrep, gitleaks
├── client/                     # command-line MCP client to list and call tools
└── tests/                      # tools, image (not root, no internet), client calls
```

---

### Reconix-Public-Web

Owners: Sreyleak and Sakphearoth. A static site, so it can go on GitHub Pages. The docs only describe what the app really does; check every page against the app before release.

```text
Reconix-Public-Web/             # public website and docs (static Next.js)
├── README.md
├── AGENTS.md                   # rules for AI coding agents
├── CLAUDE.md                   # one line: @AGENTS.md
├── .gitignore                  # node_modules, out/, plan.md
├── .github/workflows/
│   ├── ci.yml                  # lint, build, link check
│   └── deploy.yml              # publish to GitHub Pages on tag
├── package.json
├── next.config.mjs             # output: export (static site)
├── public/                     # logo, screenshots, install.sh link
├── src/
│   ├── app/
│   │   ├── page.tsx            # home: what Reconix is, the main rule, download
│   │   ├── getting-started/    # install with uv or the bash script, first assessment
│   │   ├── docs/               # docs pages, rendered from content/
│   │   ├── examples/           # sample scope, sample report
│   │   └── download/           # links to the Core release, the Kali image and the .vsix
│   └── components/
├── content/docs/               # Markdown docs, one file per topic
│   ├── commands.md
│   ├── templates.md
│   ├── scope.md
│   ├── approvals.md
│   ├── safety-and-limits.md
│   ├── providers.md
│   └── vscode.md
└── tests/                      # build test, broken link check
```

---

### Reconix-Vscode

Owners: Sreyleak, Youlong and Pojim. The extension only talks to the local Core API on `127.0.0.1`. It never calls the Kali container and never runs tools itself.

```text
Reconix-Vscode/                 # VS Code extension (TypeScript)
├── README.md
├── AGENTS.md                   # rules for AI coding agents
├── CLAUDE.md                   # one line: @AGENTS.md
├── .gitignore                  # node_modules, out/, *.vsix, plan.md
├── .github/workflows/ci.yml    # lint, test, package .vsix on tag
├── package.json                # extension manifest: commands, views, settings
├── tsconfig.json
├── .vscodeignore
├── src/
│   ├── extension.ts            # activate, register commands and views
│   ├── api/                    # client for the local Core API (types from openapi.json)
│   ├── auth.ts                 # session token, kept in SecretStorage
│   ├── chat/                   # chat panel (webview) that talks to the AI agent
│   ├── scan/                   # "Scan this folder": source code test with semgrep and gitleaks
│   ├── findings/
│   │   ├── tree.ts             # findings tree view by severity
│   │   └── diagnostics.ts      # warnings on the right file and line
│   └── approvals/              # approve or reject from VS Code
├── media/                      # icons, webview CSS
└── test/                       # extension tests (@vscode/test-electron)
```

---

#### AI agent files in Reconix-Core

There are two kinds of agent files. Keep them apart.

| Files | Who reads them | Owner |
|---|---|---|
| `AGENTS.md`, `CLAUDE.md`, `.claude/` | AI coding agents that help the team write code (Claude Code, Codex, Cursor) | Pojim (lead), each owner for their service |
| `services/ai/src/reconix_ai/prompts/`, `tool_specs/`, `policies/`, `data/tool-guides/` | The Reconix AI agent at run time | Sakphearoth (prompts, policies), Youlong (tool guides) |

- `AGENTS.md` at the root holds the rules for the whole repo. Each service has its own short `AGENTS.md` with local rules.
- `CLAUDE.md` only contains `@AGENTS.md`, so every coding agent reads the same rules.
- Prompts and skills are plain Markdown in Git. Change them by pull request, like code. The eval tests run on every change.

---

### Branches and releases

- `main` always works. Nobody pushes to it directly.
- Branch name: `<name>/<task>`, for example `pojim/scope-check`.
- Every pull request needs green CI and one review.
- Merge days: Tue 27 Oct, Sat 31 Oct, Tue 10 Nov.
- Tags: `v0.1.0` on Tue 3 Nov, `v1.0.0` on Fri 20 Nov.
