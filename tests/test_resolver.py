import json

import pytest

from subdangler.resolver import DohResolver, ResolverError


def _opener_returning(payload):
    def opener(url, timeout):
        assert "type=CNAME" in url
        return json.dumps(payload).encode("utf-8")

    return opener


def test_doh_resolver_parses_cname_answers():
    payload = {
        "Answer": [
            {"name": "sub.example.com.", "type": 5, "data": "Foo.GitHub.IO."},
            {"name": "foo.github.io.", "type": 1, "data": "185.199.108.153"},
        ]
    }
    resolver = DohResolver(opener=_opener_returning(payload), existence=lambda h: True)
    assert resolver.get_cnames("sub.example.com") == ["foo.github.io"]
    assert resolver.resolves("foo.github.io") is True


def test_doh_resolver_no_answer_means_no_cname():
    resolver = DohResolver(opener=_opener_returning({"Status": 3}))
    assert resolver.get_cnames("missing.example.com") == []


def test_doh_resolver_bad_json_raises():
    resolver = DohResolver(opener=lambda url, timeout: b"not json")
    with pytest.raises(ResolverError):
        resolver.get_cnames("sub.example.com")
