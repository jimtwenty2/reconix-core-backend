---
name: add-approval-flow
description: Work on approvals in services/api — the scope, action, configuration, disclosure and review approval types, expiry, single use, and the action hash. Use when adding a new thing that needs a person to approve it, or changing how approvals behave.
---

# Add or change an approval flow

Approvals are how a person stays in control. They are **never cut**.

## Approval types (exact enum values come from ERD V3)

| Type | Created when | Effect after approval |
|---|---|---|
| scope | a scope is submitted | assessment `DRAFT` → `ACTIVE` |
| action | the harness rates an action `MEDIUM` or `HIGH` | the action runs |
| configuration | a limit setting changes, or a provider outside this computer is enabled | the new setting takes effect |
| disclosure | someone asks to see one masked value | that value is shown **once** |
| review | a report is signed off | the report can be downloaded |

## Rules

- An approval expires after **30 minutes** and can be used **once**. Using it marks it consumed in the same transaction.
- Only an `OPERATOR` can approve or reject. A viewer gets 403.
- For an action: store the masked copy and its SHA-256 hash at request time. Before running, re-hash and refuse with `ACTION_CHANGED` if it differs.
- `HIGH` risk: the request must include the target typed by the person, and it must match exactly.
- The change only happens **after** approval. Never apply it optimistically and roll back.
- Write one audit event for request, approve, reject and expire.
- Publish approval changes on the live updates stream (`GET /stream`) so the TUI and web refresh at once.

## Tests (in `services/api/tests/`)

- approve → effect happens; reject → nothing happens
- expired approval → `APPROVAL_EXPIRED`; second use → refused
- changed action after approval → refused
- viewer approve → 403
- `HIGH` with the wrong typed target → refused
