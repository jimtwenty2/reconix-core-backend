# zap_openapi_import

## When to use

Imports an OpenAPI or Swagger definition into OWASP ZAP, from a URL or a local file, populating the
site tree with the API's endpoints so they can be spidered or scanned. Use it for an API target,
where a crawl finds little on its own: the definition is what puts the endpoints in front of ZAP.
Bind the import to a context with `context_id` when zap_context already scopes and authenticates
this API, then scan the endpoints the import added.

## Key options

- `schema` — required — the OpenAPI definition, either a URL, for example
  `http://vampi:5000/openapi.json`, or a local file path.
- `base_url` — override the API target and host (`hostOverride`), needed for local files.
- `context_id` — import into this ZAP context id.
- `host` — ZAP daemon address (default `127.0.0.1`).
- `port` — ZAP daemon port (default `8090`).

## Output

A confirmation and the resulting URL count. Reconix has no reader for zap_openapi_import, so the
imported endpoints do not become findings; the masked output is kept on the tool run. What the
import adds to the site tree is what a scan can then work on, and findings come from zap_scan's
SARIF output.

## Risk notes

The catalog baseline is `LOW`, the entry is marked `read_only` and is not destructive, and
`risk_ops.json` has no zap_* entry, so no argument raises a call above `LOW`. Under S4 a `LOW`
action runs now, without waiting for a person; `MEDIUM` and `HIGH` wait for one, and an action above
the scope's `max_risk` is blocked. A `schema` URL is fetched, and `base_url` chooses the host the
endpoints are bound to, so both must sit inside the approved scope (S3). The import itself sends no
attack payloads: the scans that follow are approved on their own risk.
