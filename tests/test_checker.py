from subdangler.checker import Status, check_host
from subdangler.resolver import DictFetcher, DictResolver, HttpResponse


def _resolver(cnames, resolves):
    return DictResolver(cnames=cnames, resolves_map=resolves)


def test_vulnerable_via_unclaimed_fingerprint():
    resolver = _resolver(
        {"sub.example.com": ["foo.github.io"]}, {"foo.github.io": True}
    )
    fetcher = DictFetcher(
        {
            "sub.example.com": HttpResponse(
                404, "There isn't a GitHub Pages site here."
            )
        }
    )
    finding = check_host("sub.example.com", resolver, fetcher)
    assert finding.status is Status.VULNERABLE
    assert finding.service == "GitHub Pages"
    assert finding.is_finding


def test_vulnerable_via_dangling_target_dns_only():
    resolver = _resolver(
        {"old.example.com": ["gone.herokuapp.com"]},
        {"gone.herokuapp.com": False},
    )
    finding = check_host("old.example.com", resolver, fetcher=None)
    assert finding.status is Status.VULNERABLE
    assert "dangling" in finding.reason


def test_claimed_when_response_is_clean():
    resolver = _resolver(
        {"www.example.com": ["foo.github.io"]}, {"foo.github.io": True}
    )
    fetcher = DictFetcher(
        {"www.example.com": HttpResponse(200, "<h1>Hello</h1>")}
    )
    finding = check_host("www.example.com", resolver, fetcher)
    assert finding.status is Status.CLAIMED
    assert not finding.is_finding


def test_no_cname():
    resolver = _resolver({}, {})
    finding = check_host("plain.example.com", resolver, fetcher=None)
    assert finding.status is Status.NO_CNAME


def test_unknown_for_unrecognised_service():
    resolver = _resolver(
        {"odd.example.com": ["target.unrecognised.example"]},
        {"target.unrecognised.example": True},
    )
    finding = check_host("odd.example.com", resolver, fetcher=None)
    assert finding.status is Status.UNKNOWN


def test_unknown_when_target_resolves_but_http_not_checked():
    resolver = _resolver(
        {"www.example.com": ["foo.github.io"]}, {"foo.github.io": True}
    )
    finding = check_host("www.example.com", resolver, fetcher=None)
    assert finding.status is Status.UNKNOWN
    assert "DNS-only" in finding.reason


def test_vulnerable_when_fetch_fails_and_target_dangles():
    resolver = _resolver(
        {"dead.example.com": ["gone.herokuapp.com"]},
        {"gone.herokuapp.com": False},
    )
    fetcher = DictFetcher({})  # every fetch raises FetchError
    finding = check_host("dead.example.com", resolver, fetcher)
    assert finding.status is Status.VULNERABLE
