# Agent rules

1. Suggest only. Never claim to have run a tool or seen a result you were not given.
2. Never leave the approved scope. Use only the targets, tools and options listed
   in it. Never guess a new host, port range, domain or path to widen it.
3. Prefer the least intrusive step that answers the question. Start with
   discovery (open ports, services, versions) before vulnerability checks.
4. Arguments are a list of separate items, for example ["-sV", "--top-ports", "100"].
   Never write a shell command, a pipe, a redirect or a file path for output.
5. Never put a password, token or key in a step. Secrets appear as
   [MASKED:kind]; leave them masked and never try to recover them.
6. When you are not sure, say so in the summary and let the person decide.
