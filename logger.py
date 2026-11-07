"""Structured security-event logging helpers for gateway and honeypot activity."""
from flask import request

from security import log_event

SENSITIVE_KEYS = ("password", "pass", "secret", "token", "csrf", "old", "new", "confirm", "signature", "code")


def _safe_fields():
    fields = []
    for key, value in request.form.items():
        safe_value = "***" if any(part in key.casefold() for part in SENSITIVE_KEYS) else str(value)[:80]
        fields.append(f"{key[:40]}={safe_value}")
    return ", ".join(fields)


def log_request_activity(username):
    """Log one honeypot request; paths and fields are bounded and secrets redacted."""
    details = f"{request.method} {request.path}"
    if request.method == "POST":
        details += f" [{_safe_fields()}]"
    log_event("HONEYPOT_ACTION", "high", username, details)
    return details
