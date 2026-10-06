"""Shared output-encoding helpers for local HTML reports."""
from html import escape


def html_escape(value):
    return escape(str(value), quote=True)


def safe_filename(value, default="report"):
    import re
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(value)).strip("._")
    return cleaned[:100] or default
