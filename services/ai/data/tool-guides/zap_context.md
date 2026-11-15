# zap_context

## When to use

Creates a scoped OWASP ZAP context: it includes the target URL, optionally excludes URL patterns,
and optionally configures authentication (form, json, http or script) plus one enabled user, so that
later scans stay authenticated and in-scope. Do it before authenticated work, because a context is
what the later steps are pointed at: zap_ajax_spider crawls within a context and as a user, and
zap_openapi_import can import into a context by its id. The excludes are how you keep parts of an
application out of everything that follows.

## Key options

- `name` — required — the context name, which must be unique.
- `url` — required — the target URL to include in the context, for example `http://juice-shop:3000`.
- `exclude` — regex URL patterns to exclude from the context.
- `authentication_method` — the ZAP auth method: `formBasedAuthentication`,
  `jsonBasedAuthentication`, `httpAuthentication`, `scriptBasedAuthentication` or
  `manualAuthentication`.
- `authentication_params` — method-specific config params, a key/value object; for form
  authentication the entry names `loginUrl` and `loginRequestData`.
- `user_name` — create and enable a context user with this name.
- `credentials` — the user's credential config params, a method-specific key/value object; give the
  field names the auth method expects and nothing else.
- `logged_in_regex` — regex that marks an authenticated response.
- `logged_out_regex` — regex that marks an unauthenticated response.
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

The created context id and what was configured. Reconix has no reader for zap_context, so nothing
here becomes a finding; the masked output is kept on the tool run. The id is what zap_openapi_import
takes as `context_id`, and the name is what zap_ajax_spider takes as `context_name`.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only` and not destructive, and
`risk_ops.json` has no zap_* entry, so no argument raises a call above `LOW`. Under S4 a `LOW`
action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for one, and an action above
the scope's `max_risk` is blocked. Credentials here are configured, never echoed. The harness masks
secrets before anything is saved, logged, shown or sent to the model (S8), so what you pass in does
not come back to you or to the AI as readable text. Keep the context `url` inside the approved
scope (S3): it is the frame the scans that follow are checked against.
