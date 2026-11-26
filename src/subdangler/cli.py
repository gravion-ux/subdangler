"""Command-line interface.

Exit codes: 0 = no findings, 1 = at least one ``vulnerable-likely``
finding, 2 = usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checker import check_hosts
from .fingerprints import normalise_host
from .report import render_json, render_text
from .resolver import (
    DEFAULT_DOH_URL,
    DictFetcher,
    DictResolver,
    DohResolver,
    HttpFetcher,
    HttpResponse,
    Resolver,
    UrllibFetcher,
)


def clean_host_input(raw: str) -> str:
    """Accept bare hostnames and URLs; return a bare normalised hostname."""
    value = raw.strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if ":" in value:
        value = value.split(":", 1)[0]
    return normalise_host(value)


def _is_plausible_host(host: str) -> bool:
    if not host or " " in host or "_" in host:
        return False
    labels = host.split(".")
    return len(labels) >= 2 and all(labels)


def _read_hosts_file(path: str) -> list[str]:
    hosts: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        hosts.append(stripped)
    return hosts


def _load_fixture(path: str) -> tuple[DictResolver, DictFetcher]:
    """Build offline resolver/fetcher from a JSON fixture file.

    Format::

        {
          "sub.example.com": {
            "cnames": ["foo.github.io"],
            "resolves": {"foo.github.io": true},
            "http_status": 404,
            "http_body": "There isn't a GitHub Pages site here."
          }
        }

    ``resolves`` may also be a plain boolean applying to the last CNAME.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("fixture must be a JSON object keyed by hostname")
    cnames: dict[str, list[str]] = {}
    resolves_map: dict[str, bool] = {}
    responses: dict[str, HttpResponse] = {}
    for host, entry in data.items():
        if not isinstance(entry, dict):
            raise ValueError(f"fixture entry for {host!r} must be an object")
        chain = [str(c) for c in entry.get("cnames", [])]
        cnames[host] = chain
        resolves = entry.get("resolves", {})
        if isinstance(resolves, bool):
            if chain:
                resolves_map[chain[-1]] = resolves
        elif isinstance(resolves, dict):
            for target, value in resolves.items():
                resolves_map[str(target)] = bool(value)
        if "http_body" in entry or "http_status" in entry:
            responses[host] = HttpResponse(
                status=int(entry.get("http_status", 200)),
                body=str(entry.get("http_body", "")),
            )
    return DictResolver(cnames=cnames, resolves_map=resolves_map), DictFetcher(
        responses=responses
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subdangler",
        description=(
            "Check hostnames for dangling CNAMEs that point at "
            "takeover-prone third-party services."
        ),
    )
    parser.add_argument("hosts", nargs="*", help="hostnames to check")
    parser.add_argument(
        "--file",
        metavar="FILE",
        help="file with one hostname per line ('#' comments allowed)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--doh-url",
        default=DEFAULT_DOH_URL,
        help=f"DNS-over-HTTPS JSON endpoint (default: {DEFAULT_DOH_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="per-request timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="DNS-only mode: skip the HTTP fingerprint check",
    )
    parser.add_argument(
        "--fixture",
        metavar="FILE",
        help="offline mode: read canned resolver/HTTP results from a JSON fixture",
    )
    parser.add_argument(
        "--version", action="version", version=f"subdangler {__version__}"
    )
    return parser


def main(
    argv: list[str] | None = None,
    resolver: Resolver | None = None,
    fetcher: HttpFetcher | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    raw_hosts: list[str] = list(args.hosts)
    if args.file:
        try:
            raw_hosts.extend(_read_hosts_file(args.file))
        except OSError as exc:
            print(f"subdangler: cannot read --file: {exc}", file=sys.stderr)
            return 2

    hosts: list[str] = []
    seen: set[str] = set()
    for raw in raw_hosts:
        host = clean_host_input(raw)
        if not _is_plausible_host(host):
            print(f"subdangler: invalid hostname: {raw!r}", file=sys.stderr)
            return 2
        if host not in seen:
            seen.add(host)
            hosts.append(host)
    if not hosts:
        parser.print_usage(sys.stderr)
        print("subdangler: no hostnames given", file=sys.stderr)
        return 2

    if resolver is None:
        if args.fixture:
            try:
                resolver, fixture_fetcher = _load_fixture(args.fixture)
            except (OSError, ValueError) as exc:
                print(f"subdangler: cannot load --fixture: {exc}", file=sys.stderr)
                return 2
            if fetcher is None and not args.no_http:
                fetcher = fixture_fetcher
        else:
            resolver = DohResolver(doh_url=args.doh_url, timeout=args.timeout)
    if fetcher is None and not args.no_http and not args.fixture:
        fetcher = UrllibFetcher(timeout=args.timeout)
    if args.no_http:
        fetcher = None

    findings = check_hosts(hosts, resolver, fetcher)
    if args.format == "json":
        print(render_json(findings, version=__version__))
    else:
        print(render_text(findings))
    return 1 if any(finding.is_finding for finding in findings) else 0
