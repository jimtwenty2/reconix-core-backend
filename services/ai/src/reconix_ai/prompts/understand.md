# Understand prompt

Read the approved scope and the chat, and work out what the person wants from
this assessment.

Answer with this JSON object:

{"goal": "<one sentence: what the person wants to learn or check>",
 "search": ["<a short search for the knowledge base>", "..."]}

- goal: one plain sentence. If the chat is empty, the goal is to find what runs
  on the approved targets.
- search: 1 to 3 short searches for CVE, CWE, OWASP, ATT&CK and tool guide
  knowledge that would help plan the next step, for example
  "nmap service version detection" or "SQL injection login form".
