# Techniques

The methodology the plan follows for each assessment type. Code reads the tables
below (agent/techniques.py): it keeps the sections for the scope's targets, and it
shows a step form only when the harness would allow that step on this scope. A
person changes this file by pull request.

Columns: key, name, what to investigate, the Kali catalog tools, the mode, the step
forms and a note. Mode is auto (a tool covers it), partial (a tool covers part of
it; a person finishes it) or manual (a person checks it; never a tool step). A step
form is `TOOL target options`, steps split by `;`. In a target, {url} is an allowed
URL prefix, {host} an allowed IP, range or domain, {schema} the URL of the API's
OpenAPI document inside the scope, and {ports} the scope's allowed ports.

**One run per tool per target.** Many techniques below share the SAME step (one
`nuclei` run with every relevant tag, one `nikto` run, one `-sV` nmap scan). That
is deliberate: run each such command ONCE and read its output for all the
techniques it covers. Never run the same tool on the same target again with the
same or a subset of its options — the harness blocks the repeat and it finds
nothing new.

## web

| key | name | investigates | tools | mode | steps | note |
|---|---|---|---|---|---|---|
| fingerprint | Technology fingerprinting | Web server, framework, CMS, libraries | whatweb, httpx_probe | auto | WHATWEB {url}; HTTPX_PROBE {url} -tech-detect -status-code -title -web-server | Run first: later steps read what it finds. If it names a CMS (WordPress -> wpscan), test that CMS next when the tool is allowed, else recommend it to the operator. |
| versions | Version detection | Outdated Apache, Nginx, PHP, etc. | nuclei, whatweb, nikto | auto | NUCLEI {url} -tags tech,cve,default-login,auth,headers,misconfig,exposure,config,debug,xss,sqli,injection,cors,ssrf; NIKTO {url} | The one nuclei run covers versions, auth, headers, config and input checks; read its output for all of them. |
| directories | Directory discovery | Hidden directories and files | katana, ffuf, gobuster | auto | KATANA {url} -d 3 -jc; FFUF {url}FUZZ -mc 200,204,301,302,307,401,403 | Core supplies the wordlist. FFUF needs FUZZ at the end of the target. When katana finds a URL with a ?query= parameter, feed that exact URL to dalfox (input validation) to test it for XSS. |
| authentication | Authentication testing | Weak login, broken authentication | nuclei | partial | NUCLEI {url} -tags tech,cve,default-login,auth,headers,misconfig,exposure,config,debug,xss,sqli,injection,cors,ssrf | Covered by the one nuclei run. A person tests the login flow itself. |
| authorization | Authorization testing | IDOR, privilege escalation | - | manual | - | Needs two accounts. |
| input_validation | Input validation | SQL injection, XSS, command injection | dalfox, nuclei, sqlmap | partial | NUCLEI {url} -tags tech,cve,default-login,auth,headers,misconfig,exposure,config,debug,xss,sqli,injection,cors,ssrf; DALFOX {url}; SQLMAP {url} | Covered by the one nuclei run. DALFOX confirms XSS on a URL with a query parameter found by crawling. When a scan flags a likely SQL injection on a parameter and sqlmap is an allowed tool, confirm it with SQLMAP on that exact parameterized URL (validation phase); it gates at HIGH (the operator types the target). Never run sqlmap unprompted or on a URL with no parameter. |
| headers | Security headers | CSP, HSTS, X-Frame-Options | nuclei, nikto | auto | NUCLEI {url} -tags tech,cve,default-login,auth,headers,misconfig,exposure,config,debug,xss,sqli,injection,cors,ssrf; NIKTO {url} | Covered by the one nuclei run. |
| tls | TLS assessment | Weak protocols and certificates | testssl | auto | TESTSSL {url} -p -S -U | Only on an https:// URL. |
| file_upload | File upload testing | Unrestricted file uploads | - | manual | - | |
| configuration | Configuration testing | Debug mode, exposed secrets, default pages | nuclei, nikto | auto | NUCLEI {url} -tags tech,cve,default-login,auth,headers,misconfig,exposure,config,debug,xss,sqli,injection,cors,ssrf; NIKTO {url} | Covered by the one nuclei run. |

## api

| key | name | investigates | tools | mode | steps | note |
|---|---|---|---|---|---|---|
| endpoints | Endpoint discovery | Find undocumented API endpoints | katana, ffuf, arjun | auto | KATANA {url} -d 3 -jc; FFUF {url}FUZZ -mc 200,201,204,301,302,401,403,405; ARJUN {url} | ARJUN finds hidden parameters of one endpoint. |
| authentication | Authentication testing | JWT, API keys, OAuth | nuclei | partial | NUCLEI {url} -tags jwt,auth,default-login,sqli,nosqli,injection,exposure,api,swagger,graphql,cors,ssrf | The one nuclei run covers auth, input, data-exposure, CORS and SSRF; read its output for all. A person tests token handling. |
| authorization | Authorization testing | BOLA / IDOR | - | manual | - | Needs two accounts. |
| rate_limit | Rate-limit testing | Brute-force and request abuse protections | - | manual | - | The loop check caps actions at 20 a minute. |
| input_validation | Input validation | SQL injection, NoSQL injection | schemathesis, nuclei, sqlmap | partial | NUCLEI {url} -tags jwt,auth,default-login,sqli,nosqli,injection,exposure,api,swagger,graphql,cors,ssrf; SCHEMATHESIS {schema} --checks all; SQLMAP {url} | Covered by the one nuclei run and the schema fuzz. When a scan flags a likely SQL injection on an endpoint parameter and sqlmap is an allowed tool, confirm it with SQLMAP on that exact parameterized URL (validation phase); it gates at HIGH. Never run sqlmap unprompted or on a URL with no parameter. |
| mass_assignment | Mass assignment | Unauthorized modification of fields | - | manual | - | |
| data_exposure | Data exposure | Sensitive information in API responses | nuclei, schemathesis | partial | NUCLEI {url} -tags jwt,auth,default-login,sqli,nosqli,injection,exposure,api,swagger,graphql,cors,ssrf; SCHEMATHESIS {schema} --checks all | Covered by the one nuclei run. |
| http_methods | HTTP method testing | Unexpected methods enabled | nuclei, httpx_probe | partial | NUCLEI {url} -tags jwt,auth,default-login,sqli,nosqli,injection,exposure,api,swagger,graphql,cors,ssrf | Covered by the one nuclei run. Never send PUT or DELETE to find out. |
| cors | CORS testing | Unsafe cross-origin access | nuclei | auto | NUCLEI {url} -tags jwt,auth,default-login,sqli,nosqli,injection,exposure,api,swagger,graphql,cors,ssrf | Covered by the one nuclei run. |
| schema_validation | Schema validation | Incorrect request/response validation | schemathesis | auto | SCHEMATHESIS {schema} --checks all | Only when the API has an OpenAPI document. |
| ssrf | SSRF testing | Unsafe server-side URL fetching | nuclei, nuclei_dast | partial | NUCLEI {url} -tags jwt,auth,default-login,sqli,nosqli,injection,exposure,api,swagger,graphql,cors,ssrf | Covered by the one nuclei run, which finds only what needs no outside callback. When a parameter takes a URL or host and the plain run shows nothing, confirm BLIND SSRF with NUCLEI_DAST on that exact parameterised URL: a validation-phase, HIGH, operator-approved step on a disposable target that uses an out-of-band callback. |
| api_versions | API version testing | Old or deprecated endpoints | ffuf, katana | auto | FFUF {url}FUZZ -mc 200,301,302,401,403; KATANA {url} -d 3 -jc | |

## network

| key | name | investigates | tools | mode | steps | note |
|---|---|---|---|---|---|---|
| host_discovery | Host discovery | Identify live devices | nmap | auto | NMAP {host} -sn | Only when the scope lists no allowed ports; with ports, every host is scanned with -Pn below. |
| port_scan | Port scanning | Find open TCP/UDP ports | nmap | auto | NMAP {host} -Pn -sV -p {ports} | The one -sV scan finds ports AND their service and version in a single pass; do not run a plain port scan first. |
| services | Service detection | Identify running services | nmap | auto | NMAP {host} -Pn -sV -p {ports} | Covered by the one -sV scan. |
| versions | Version detection | Detect outdated service versions | nmap | auto | NMAP {host} -Pn -sV -p {ports} | Covered by the one -sV scan — read its product/version for each open port. |
| os_fingerprint | OS fingerprinting | Identify operating systems | nmap | partial | NMAP {host} -O | Only when the scope lists no allowed ports. |
| cve_matching | CVE matching | Compare detected versions against known CVEs | nuclei | auto | NUCLEI {url} -tags cve | Needs a URL for the host in the scope. |
| misconfiguration | Misconfiguration checks | Default credentials, insecure services | nuclei, enum4linux, onesixtyone | partial | NUCLEI {url} -tags default-login,misconfig; ENUM4LINUX {host}; ONESIXTYONE {host} | Chain on the open ports the -sV scan found: run ENUM4LINUX only when SMB (139 or 445) is open, ONESIXTYONE only when SNMP (161) is open. NUCLEI needs a URL for the host. |
| tls | SSL/TLS testing | Weak ciphers and protocols | testssl | auto | TESTSSL {url} -p -S -U | Only on an https:// URL. |
| firewall | Firewall assessment | Unexpectedly exposed services | nmap | partial | NMAP {host} -Pn -sV -p {ports} | Covered by the one -sV scan — compare the open ports with what the scope expects. |
| segmentation | Network segmentation | Unauthorized access between network zones | - | manual | - | Needs scans from more than one network zone. |
