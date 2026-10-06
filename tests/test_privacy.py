import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "modules"))

from privacy import redact_secrets, sanitize_for_external_analysis

def test_redacts_common_api_keys():
    assert "ghp_EXAMPLE12345678901234567890" not in redact_secrets(
        "token=ghp_EXAMPLE12345678901234567890"
    )

def test_redacts_private_keys():
    value = "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----"
    assert "BEGIN RSA PRIVATE KEY" not in redact_secrets(value)

def test_sanitizes_nested_structures():
    data = {"profile": {"token": "sk-abcdefghijklmnopqrstuvwxyz"}}
    assert "[REDACTED-SECRET]" in sanitize_for_external_analysis(data)["profile"]["token"]


def test_external_ai_requires_explicit_opt_in(monkeypatch):
    import ai_analyst
    monkeypatch.setattr(ai_analyst, "GROK_API_KEY", "configured")
    monkeypatch.setattr(ai_analyst, "ALLOW_EXTERNAL_ANALYSIS", False)
    brief = ai_analyst.generate_brief("demo", [], [], {}, [], {})
    assert "offline" not in brief.lower() or "Exposure score" in brief


def test_timezone_confidence_is_capped_for_sparse_evidence():
    from analyzer import predict_timezone
    heatmap = {hour: (1 if hour in {1, 2, 3} else 0) for hour in range(24)}
    results = predict_timezone(heatmap, 2, sample_count=3)
    assert results
    assert results[0]["status"] == "insufficient_evidence"
    assert results[0]["confidence"] <= 39.9


def test_html_escape_blocks_markup():
    from report_utils import html_escape
    payload = '<script>alert(1)</script>"'
    escaped = html_escape(payload)
    assert '<script>' not in escaped
    assert '</script>' not in escaped
    assert '&lt;script&gt;' in escaped
    assert '&quot;' in escaped


def test_github_rate_limit_helper_retries(monkeypatch):
    import github_scraper

    class Response:
        def __init__(self, status, headers=None, payload=None):
            self.status_code = status
            self.headers = headers or {}
            self._payload = payload or {}
        def json(self):
            return self._payload

    responses = iter([
        Response(429, {"Retry-After": "0"}),
        Response(200, payload={"login": "demo"}),
    ])
    monkeypatch.setattr(github_scraper.requests, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(github_scraper.time, "sleep", lambda _: None)
    payload, status = github_scraper._request_json("https://api.github.com/users/demo")
    assert status == "ok"
    assert payload["login"] == "demo"


def test_github_error_classification(monkeypatch):
    import github_scraper

    class Response:
        status_code = 401
        headers = {}
        def json(self):
            return {}

    monkeypatch.setattr(github_scraper.requests, "get", lambda *args, **kwargs: Response())
    payload, status = github_scraper._request_json("https://api.github.com/users/demo")
    assert payload is None
    assert status == "unauthorized"
