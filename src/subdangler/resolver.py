"""DNS and HTTP access, stdlib only.

CNAME records come from a DNS-over-HTTPS JSON endpoint (Google Public DNS
by default) via :mod:`urllib.request`; existence checks use
:func:`socket.getaddrinfo`. Both the network opener and the socket lookup
are injectable, and :class:`DictResolver` / :class:`DictFetcher` provide a
fully offline mode driven by canned results (used by the test suite and by
the CLI ``--fixture`` option).
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from .fingerprints import normalise_host

DEFAULT_DOH_URL = "https://dns.google/resolve"
CNAME_RECORD_TYPE = 5
MAX_BODY_BYTES = 65536


class ResolverError(Exception):
    """Raised when a DNS lookup cannot be completed."""


class FetchError(Exception):
    """Raised when an HTTP fetch cannot be completed."""


class Resolver(Protocol):
    """Anything that can answer CNAME and existence questions."""

    def get_cnames(self, host: str) -> list[str]:
        """Return the CNAME chain for ``host`` (empty if there is none)."""
        ...

    def resolves(self, host: str) -> bool:
        """Return True if ``host`` resolves to at least one address."""
        ...


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str


class HttpFetcher(Protocol):
    """Anything that can fetch a hostname over HTTP(S)."""

    def fetch(self, host: str) -> HttpResponse:
        """Fetch ``https://<host>/`` (falling back to HTTP) and return it."""
        ...


def _default_opener(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json", "User-Agent": "subdangler"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _default_existence(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    return bool(infos)


@dataclass
class DohResolver:
    """Live resolver: CNAMEs via DoH JSON, existence via the system resolver."""

    doh_url: str = DEFAULT_DOH_URL
    timeout: float = 5.0
    opener: Callable[[str, float], bytes] = field(default=_default_opener)
    existence: Callable[[str], bool] = field(default=_default_existence)

    def _query(self, name: str, record_type: str) -> dict:
        query = urllib.parse.urlencode({"name": name, "type": record_type})
        url = f"{self.doh_url}?{query}"
        try:
            raw = self.opener(url, self.timeout)
        except (urllib.error.URLError, OSError) as exc:
            raise ResolverError(f"DoH query failed for {name}: {exc}") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ResolverError(f"invalid DoH response for {name}") from exc
        if not isinstance(payload, dict):
            raise ResolverError(f"invalid DoH response for {name}")
        return payload

    def get_cnames(self, host: str) -> list[str]:
        payload = self._query(normalise_host(host), "CNAME")
        answers = payload.get("Answer") or []
        cnames: list[str] = []
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            if answer.get("type") != CNAME_RECORD_TYPE:
                continue
            data = answer.get("data")
            if isinstance(data, str) and data.strip():
                cnames.append(normalise_host(data))
        return cnames

    def resolves(self, host: str) -> bool:
        return self.existence(normalise_host(host))


@dataclass
class DictResolver:
    """Offline resolver backed by canned results.

    ``cnames`` maps a hostname to its CNAME chain; ``resolves_map`` maps a
    hostname to whether it resolves. Unknown hostnames have no CNAMEs and
    do not resolve.
    """

    cnames: Mapping[str, Sequence[str]] = field(default_factory=dict)
    resolves_map: Mapping[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._cnames = {
            normalise_host(host): [normalise_host(c) for c in chain]
            for host, chain in self.cnames.items()
        }
        self._resolves = {
            normalise_host(host): bool(value)
            for host, value in self.resolves_map.items()
        }

    def get_cnames(self, host: str) -> list[str]:
        return list(self._cnames.get(normalise_host(host), []))

    def resolves(self, host: str) -> bool:
        return self._resolves.get(normalise_host(host), False)


@dataclass
class UrllibFetcher:
    """Live HTTP fetcher. HTTP error pages are returned, not raised."""

    timeout: float = 5.0

    def _fetch_url(self, url: str) -> HttpResponse:
        request = urllib.request.Request(url, headers={"User-Agent": "subdangler"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read(MAX_BODY_BYTES)
                return HttpResponse(
                    status=int(response.status),
                    body=body.decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(MAX_BODY_BYTES)
            return HttpResponse(
                status=int(exc.code), body=body.decode("utf-8", errors="replace")
            )

    def fetch(self, host: str) -> HttpResponse:
        host = normalise_host(host)
        try:
            return self._fetch_url(f"https://{host}/")
        except (urllib.error.URLError, OSError, ValueError):
            pass
        try:
            return self._fetch_url(f"http://{host}/")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise FetchError(f"could not fetch {host}: {exc}") from exc


@dataclass
class DictFetcher:
    """Offline fetcher backed by canned responses (missing host = error)."""

    responses: Mapping[str, HttpResponse] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._responses = {
            normalise_host(host): response for host, response in self.responses.items()
        }

    def fetch(self, host: str) -> HttpResponse:
        response = self._responses.get(normalise_host(host))
        if response is None:
            raise FetchError(f"no canned response for {host}")
        return response
