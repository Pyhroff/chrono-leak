"""Privacy helpers for CHRONO-LEAK external-analysis boundaries."""
import re

SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"xai-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

def redact_secrets(value):
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED-SECRET]", text)
    return text

def sanitize_for_external_analysis(value):
    """Redact obvious secrets before data is sent to an external LLM."""
    if isinstance(value, dict):
        return {k: sanitize_for_external_analysis(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_for_external_analysis(v) for v in value]
    return redact_secrets(value)
