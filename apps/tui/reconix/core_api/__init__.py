"""Core API mode: the app asks the local Core API (`services/api`) instead of the model.

Off unless RECONIX_CORE_API is set (the `reconix-ai` launcher starts the API and sets
it). Then chat lines, the scope and the plan draft go through the API, which calls the
model, runs its own safety checks and keeps the record. Without it, or when the API can't
answer, the app calls the model itself as before.
"""

from .client import CoreApiError, enabled
from .sync import approve_active_model, chat_reply, plan_draft, sync_scope

__all__ = [
    "CoreApiError",
    "approve_active_model",
    "chat_reply",
    "enabled",
    "plan_draft",
    "sync_scope",
]
