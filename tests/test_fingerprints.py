from subdangler.fingerprints import match_service, matches_unclaimed, normalise_host


def test_match_service_exact_and_subdomain():
    assert match_service("foo.github.io").service == "GitHub Pages"
    assert match_service("github.io").service == "GitHub Pages"
    assert match_service("myapp.herokuapp.com").service == "Heroku"
    assert match_service("bucket.s3.amazonaws.com").service == "AWS S3"


def test_match_service_is_label_bounded_and_case_insensitive():
    # A look-alike suffix must not match.
    assert match_service("evilgithub.io") is None
    assert match_service("notherokuapp.com") is None
    # Case and trailing dot are normalised.
    assert match_service("Foo.GitHub.IO.").service == "GitHub Pages"


def test_match_service_unknown_returns_none():
    assert match_service("example.com") is None
    assert match_service("") is None


def test_matches_unclaimed_is_case_insensitive():
    fingerprint = match_service("foo.github.io")
    assert matches_unclaimed(fingerprint, "there isn't a github pages site here.")
    assert not matches_unclaimed(fingerprint, "welcome to my site")


def test_normalise_host():
    assert normalise_host("  WWW.Example.COM. ") == "www.example.com"
