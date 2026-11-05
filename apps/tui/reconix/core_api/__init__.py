"""The app's only data source: the local Core API (`services/api`, apps/CLAUDE.md "Data").

The API runs the checks and approvals, calls the model and Kali, and keeps the record;
the app shows what it answers. `client` makes the calls (loopback only, token in memory),
`connect` holds the session, `sync` sends the scope and chat, `run_api` drives a run, and
`adapt` turns API values into the app's.
"""

from .client import CoreApiError, enabled
from .sync import approve_active_model, chat_reply, sync_scope

__all__ = [
    "CoreApiError",
    "approve_active_model",
    "chat_reply",
    "enabled",
    "sync_scope",
]
