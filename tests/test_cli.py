import json

import pytest

from subdangler.cli import clean_host_input, main
from subdangler.resolver import DictFetcher, DictResolver, HttpResponse


def _clean_resolver():
    return DictResolver(cnames={}, resolves_map={})


def _vulnerable_setup():
    resolver = DictResolver(
        cnames={"sub.example.com": ["foo.github.io"]},
        resolves_map={"foo.github.io": True},
    )
    fetcher = DictFetcher(
        {"sub.example.com": HttpResponse(404, "There isn't a GitHub Pages site here.")}
    )
    return resolver, fetcher


def test_cli_exit_zero_when_clean(capsys):
    code = main(["plain.example.com"], resolver=_clean_resolver(), fetcher=None)
    assert code == 0
    assert "NO-CNAME" in capsys.readouterr().out


def test_cli_exit_one_on_findings(capsys):
    resolver, fetcher = _vulnerable_setup()
    code = main(["sub.example.com"], resolver=resolver, fetcher=fetcher)
    assert code == 1
    assert "VULNERABLE-LIKELY" in capsys.readouterr().out


def test_cli_exit_two_without_hosts(capsys):
    code = main([], resolver=_clean_resolver())
    assert code == 2


def test_cli_exit_two_on_invalid_hostname(capsys):
    code = main(["not a host"], resolver=_clean_resolver())
    assert code == 2


def test_cli_bad_flag_exits_two():
    with pytest.raises(SystemExit) as excinfo:
        main(["--format", "yaml", "a.example.com"], resolver=_clean_resolver())
    assert excinfo.value.code == 2


def test_cli_json_format(capsys):
    resolver, fetcher = _vulnerable_setup()
    code = main(
        ["--format", "json", "sub.example.com"], resolver=resolver, fetcher=fetcher
    )
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["vulnerable-likely"] == 1


def test_cli_reads_hosts_file(tmp_path, capsys):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("# comment\nplain.example.com\n\n", encoding="utf-8")
    code = main(["--file", str(hosts_file)], resolver=_clean_resolver())
    assert code == 0
    assert "plain.example.com" in capsys.readouterr().out


def test_cli_missing_hosts_file_is_usage_error(tmp_path):
    code = main(["--file", str(tmp_path / "nope.txt")], resolver=_clean_resolver())
    assert code == 2


def test_cli_offline_fixture(tmp_path, capsys):
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "sub.example.com": {
                    "cnames": ["foo.github.io"],
                    "resolves": True,
                    "http_status": 404,
                    "http_body": "There isn't a GitHub Pages site here.",
                }
            }
        ),
        encoding="utf-8",
    )
    code = main(["--fixture", str(fixture), "sub.example.com"])
    assert code == 1
    assert "VULNERABLE-LIKELY" in capsys.readouterr().out


def test_clean_host_input_accepts_urls():
    assert clean_host_input("https://Sub.Example.com/path?q=1") == "sub.example.com"
    assert clean_host_input("sub.example.com:443") == "sub.example.com"
