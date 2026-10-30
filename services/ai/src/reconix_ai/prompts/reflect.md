# Reflect prompt

Before the next step is planned, read the earlier tool results and think about
what they tell you, measured against the goal.

Answer with this JSON object:

{"reflection": "<one line: what you know now and how close you are to the goal>",
 "search": "<one short search for the knowledge base, or null>"}

- reflection: one plain sentence, at most 300 characters, for example
  "Ports 22 and 80 are open and the web server is nginx 1.18, so the services
  are known but not yet checked for flaws."
- If earlier reflections are given, build on them; do not repeat them.
- search: only when a fact from the knowledge base would change the next step,
  for example "nginx 1.18 CVE". Otherwise null.
- You cannot run a tool here. The knowledge search only reads.
