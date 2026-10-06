"""Shared output-encoding helpers for local HTML reports."""
from html import escape


def html_escape(value):
    return escape(str(value), quote=True)
