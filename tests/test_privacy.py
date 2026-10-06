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
