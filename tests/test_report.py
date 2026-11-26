import json

from subdangler.checker import Finding, Status
from subdangler.report import render_json, render_text, summarise

FINDINGS = [
    Finding(
        host="sub.example.com",
        status=Status.VULNERABLE,
        cnames=("foo.github.io",),
        service="GitHub Pages",
        target="foo.github.io",
        reason="response matches the GitHub Pages unclaimed-resource fingerprint",
    ),
    Finding(host="plain.example.com", status=Status.NO_CNAME, reason="no CNAME record"),
]


def test_render_text_includes_status_target_and_summary():
    text = render_text(FINDINGS)
    assert "VULNERABLE-LIKELY" in text
    assert "sub.example.com -> foo.github.io (GitHub Pages)" in text
    assert "Checked 2 host(s): 1 vulnerable-likely" in text


def test_render_json_structure():
    payload = json.loads(render_json(FINDINGS, version="0.1.0"))
    assert payload["tool"] == "subdangler"
    assert payload["results"][0]["status"] == "vulnerable-likely"
    assert payload["results"][0]["cnames"] == ["foo.github.io"]
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["vulnerable-likely"] == 1


def test_summarise_counts():
    summary = summarise(FINDINGS)
    assert summary["claimed"] == 0
    assert summary["no-cname"] == 1
