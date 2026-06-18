"""
CHRONO-LEAK | Shared config helper
====================================
A tiny, zero-dependency loader for API keys and tokens.

Every value is read from the process environment first, then from a local
`.env` file at the project root — so you can either `export GITHUB_TOKEN=...`
or just drop it in `.env` (copy `.env.example`). Keeping this in one place
means every module reads its keys exactly the same way.
"""

import os

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_BASE_DIR, ".env")


def get_key(name, default=None):
    """
    Return a config value.

    Lookup order:
      1. environment variable `name`
      2. matching `name=value` line in the project-root .env
      3. `default`
    """
    val = os.environ.get(name)
    if val:
        return val

    if os.path.exists(_ENV_PATH):
        with open(_ENV_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip blanks and comments, and anything that isn't key=value
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, raw = line.partition("=")
                if key.strip() == name:
                    cleaned = raw.strip().strip('"').strip("'")
                    return cleaned or default

    return default
