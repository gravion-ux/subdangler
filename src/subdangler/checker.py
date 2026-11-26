"""Classification of hostnames by subdomain-takeover risk.

Statuses:

- ``vulnerable-likely``: the CNAME points at a takeover-prone service and
  either the HTTP response carries the service's unclaimed fingerprint or
  the CNAME target does not resolve at all (a dangling record).
- ``claimed``: the CNAME points at a takeover-prone service, the target
  resolves, and the HTTP response shows no unclaimed fingerprint.
- ``unknown``: there is a CNAME but it cannot be judged — it points at an
  unrecognised service, the lookup failed, or (in DNS-only mode) the
  target resolves but no HTTP fingerprint check was performed.
- ``no-cname``: the hostname has no CNAME record, so this class of
  takeover does not apply.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .fingerprints import Fingerprint, match_service, matches_unclaimed, normalise_host
from .resolver import FetchError, HttpFetcher, Resolver, ResolverError


class Status(str, Enum):
    VULNERABLE = "vulnerable-likely"
    CLAIMED = "claimed"
    UNKNOWN = "unknown"
    NO_CNAME = "no-cname"


@dataclass(frozen=True)
class Finding:
    host: str
    status: Status
    cnames: tuple[str, ...] = ()
    service: str | None = None
    target: str | None = None
    reason: str = ""

    @property
    def is_finding(self) -> bool:
        """Only ``vulnerable-likely`` counts towards the exit code."""
        return self.status is Status.VULNERABLE


def _match_chain(cnames: list[str]) -> Fingerprint | None:
    for cname in cnames:
        fingerprint = match_service(cname)
        if fingerprint is not None:
            return fingerprint
    return None


def check_host(
    host: str, resolver: Resolver, fetcher: HttpFetcher | None = None
) -> Finding:
    """Classify one hostname using the injected resolver/fetcher."""
    host = normalise_host(host)
    try:
        cnames = resolver.get_cnames(host)
    except ResolverError as exc:
        return Finding(host, Status.UNKNOWN, reason=f"CNAME lookup failed: {exc}")
    if not cnames:
        return Finding(host, Status.NO_CNAME, reason="no CNAME record")

    target = cnames[-1]
    fingerprint = _match_chain(cnames)
    if fingerprint is None:
        return Finding(
            host,
            Status.UNKNOWN,
            cnames=tuple(cnames),
            target=target,
            reason="CNAME points at an unrecognised service",
        )

    base = {
        "cnames": tuple(cnames),
        "service": fingerprint.service,
        "target": target,
    }
    try:
        target_resolves = resolver.resolves(target)
    except ResolverError:
        target_resolves = False

    if fetcher is not None:
        try:
            response = fetcher.fetch(host)
        except FetchError as exc:
            if not target_resolves:
                return Finding(
                    host,
                    Status.VULNERABLE,
                    reason=(
                        f"CNAME target {target} does not resolve (dangling) "
                        f"and the site could not be fetched"
                    ),
                    **base,
                )
            return Finding(
                host,
                Status.UNKNOWN,
                reason=f"HTTP check inconclusive: {exc}",
                **base,
            )
        if matches_unclaimed(fingerprint, response.body):
            return Finding(
                host,
                Status.VULNERABLE,
                reason=(
                    f"response matches the {fingerprint.service} "
                    "unclaimed-resource fingerprint"
                ),
                **base,
            )
        return Finding(
            host,
            Status.CLAIMED,
            reason=(
                f"target resolves and the response (HTTP {response.status}) "
                "shows no unclaimed fingerprint"
            ),
            **base,
        )

    if not target_resolves:
        return Finding(
            host,
            Status.VULNERABLE,
            reason=f"CNAME target {target} does not resolve (dangling)",
            **base,
        )
    return Finding(
        host,
        Status.UNKNOWN,
        reason="target resolves; HTTP fingerprint not checked (DNS-only mode)",
        **base,
    )


def check_hosts(
    hosts: list[str], resolver: Resolver, fetcher: HttpFetcher | None = None
) -> list[Finding]:
    """Classify every hostname, preserving input order."""
    return [check_host(host, resolver, fetcher) for host in hosts]
