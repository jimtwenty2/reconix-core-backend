# Understand prompt

Read the approved scope and the chat, and work out what the person wants from
this assessment.

Answer with this JSON object:

{"goal": "<one sentence: what the person wants to learn or check>",
 "search": ["<a short search for the knowledge base>", "..."]}

- goal: one plain sentence. If the chat is empty, or asks only for a test of the
  target, the goal is to find vulnerabilities on the approved targets by covering
  the techniques for its assessment type, discovery first. A line like
  "Assessment type: API" names that type; keep it in the goal.
- search: 1 to 3 short searches for CVE, CWE, OWASP, ATT&CK and tool guide
  knowledge that would help plan the next step, for example
  "nmap service version detection" or "SQL injection login form".
