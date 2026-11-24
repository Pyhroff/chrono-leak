"""Regression tests for two code paths that raised NameError at runtime."""
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "modules"))

import breach_checker
import exposure_scorer


def test_email_breach_check_builds_documented_url(monkeypatch):
    monkeypatch.setattr(breach_checker, "HIBP_API_KEY", "test-key")
    with mock.patch.object(breach_checker.requests, "get", return_value=mock.Mock(status_code=404)) as get:
        assert breach_checker.check_email_breaches(" a+b@example.com ") == []
    url = get.call_args.args[0]
    assert url == "https://haveibeenpwned.com/api/v3/breachedaccount/a%2Bb%40example.com?truncateResponse=false"


def test_exposure_report_renders_and_escapes(tmp_path, monkeypatch):
    # Point the report directory at tmp_path: the function writes to <repo>/reports.
    real_dirname = exposure_scorer.os.path.dirname
    monkeypatch.setattr(
        exposure_scorer.os.path, "dirname",
        lambda p: str(tmp_path) if p == real_dirname(exposure_scorer.__file__) else real_dirname(p),
    )
    scores = [{"category": "<b>x</b>", "score": 3, "max": 10, "findings": ["<script>"], "recommendations": ["r"]}]
    out = exposure_scorer.save_exposure_report("alice", scores, 30, "LOW", "#fff", "d")
    html = Path(out).read_text(encoding="utf-8")
    assert Path(out).parent == tmp_path / "reports"
    assert "&lt;script&gt;" in html and "<script>" not in html
