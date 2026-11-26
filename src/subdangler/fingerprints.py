"""Takeover-prone service fingerprints.

Each entry maps a third-party service to the CNAME suffixes that point at
it and to response-body substrings the service returns when the target
resource (site, app, bucket, shop, ...) does not exist or is unclaimed.
Seeing one of those substrings on a hostname whose CNAME points at the
service is a strong signal that the subdomain can be claimed by someone
else.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Fingerprint:
    """A takeover-prone service and how to recognise its dangling state."""

    service: str
    cname_suffixes: tuple[str, ...]
    unclaimed_fingerprints: tuple[str, ...]
    notes: str = ""


FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint(
        service="GitHub Pages",
        cname_suffixes=("github.io",),
        unclaimed_fingerprints=("There isn't a GitHub Pages site here",),
        notes="Claim by creating a repository/site with the matching name.",
    ),
    Fingerprint(
        service="Heroku",
        cname_suffixes=("herokuapp.com", "herokudns.com"),
        unclaimed_fingerprints=("No such app", "There's nothing here, yet."),
        notes="Claim by creating an app with the matching name.",
    ),
    Fingerprint(
        service="AWS S3",
        cname_suffixes=(
            "s3.amazonaws.com",
            "s3-website-us-east-1.amazonaws.com",
            "s3-website-us-west-2.amazonaws.com",
            "s3-website-eu-west-1.amazonaws.com",
            "s3-website-ap-southeast-2.amazonaws.com",
        ),
        unclaimed_fingerprints=(
            "NoSuchBucket",
            "The specified bucket does not exist",
        ),
        notes="Claim by creating a bucket with the matching name.",
    ),
    Fingerprint(
        service="Microsoft Azure",
        cname_suffixes=(
            "azurewebsites.net",
            "cloudapp.azure.com",
            "cloudapp.net",
            "trafficmanager.net",
            "azureedge.net",
        ),
        unclaimed_fingerprints=("404 Web Site not found",),
        notes="App Service / Traffic Manager names can be re-registered.",
    ),
    Fingerprint(
        service="Netlify",
        cname_suffixes=("netlify.app", "netlify.com"),
        unclaimed_fingerprints=("Not Found - Request ID",),
        notes="Claim by adding the site to a Netlify account.",
    ),
    Fingerprint(
        service="Shopify",
        cname_suffixes=("myshopify.com",),
        unclaimed_fingerprints=("Sorry, this shop is currently unavailable",),
        notes="Shop names can be re-registered when the shop is gone.",
    ),
    Fingerprint(
        service="Fastly",
        cname_suffixes=("fastly.net",),
        unclaimed_fingerprints=("Fastly error: unknown domain",),
        notes="Claim by adding the domain to a Fastly service.",
    ),
    Fingerprint(
        service="Pantheon",
        cname_suffixes=("pantheonsite.io",),
        unclaimed_fingerprints=("404 error unknown site!", "The gods are wise"),
        notes="Claim by creating a site with the matching name.",
    ),
    Fingerprint(
        service="Tumblr",
        cname_suffixes=("domains.tumblr.com",),
        unclaimed_fingerprints=(
            "Whatever you were looking for doesn't currently exist at this address",
        ),
        notes="Claim by registering the blog name.",
    ),
    Fingerprint(
        service="Surge",
        cname_suffixes=("surge.sh",),
        unclaimed_fingerprints=("project not found",),
        notes="Claim by publishing a project on the subdomain.",
    ),
    Fingerprint(
        service="Bitbucket",
        cname_suffixes=("bitbucket.io",),
        unclaimed_fingerprints=("Repository not found",),
        notes="Claim by creating the matching repository/workspace site.",
    ),
    Fingerprint(
        service="Ghost",
        cname_suffixes=("ghost.io",),
        unclaimed_fingerprints=(
            "The thing you were looking for is no longer here",
        ),
        notes="Claim by creating a publication with the matching name.",
    ),
    Fingerprint(
        service="WordPress.com",
        cname_suffixes=("wordpress.com",),
        unclaimed_fingerprints=("Do you want to register",),
        notes="Claim by registering the site name.",
    ),
    Fingerprint(
        service="Zendesk",
        cname_suffixes=("zendesk.com",),
        unclaimed_fingerprints=(
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ),
        notes="Claim by registering the help-center subdomain.",
    ),
    Fingerprint(
        service="Help Scout",
        cname_suffixes=("helpscoutdocs.com",),
        unclaimed_fingerprints=("No settings were found for this company",),
        notes="Claim by creating a docs site with the matching name.",
    ),
    Fingerprint(
        service="ReadMe",
        cname_suffixes=("readme.io",),
        unclaimed_fingerprints=("Project doesnt exist... yet!",),
        notes="Claim by creating a project with the matching name.",
    ),
)


def normalise_host(host: str) -> str:
    """Lower-case a hostname and strip whitespace and the trailing dot."""
    return host.strip().lower().rstrip(".")


def match_service(cname: str) -> Fingerprint | None:
    """Return the fingerprint whose CNAME suffix matches ``cname``.

    Matching is on whole DNS labels: ``foo.github.io`` matches the
    ``github.io`` suffix, but ``evilgithub.io`` does not.
    """
    target = normalise_host(cname)
    if not target:
        return None
    for fingerprint in FINGERPRINTS:
        for suffix in fingerprint.cname_suffixes:
            if target == suffix or target.endswith("." + suffix):
                return fingerprint
    return None


def matches_unclaimed(fingerprint: Fingerprint, body: str) -> bool:
    """Return True if ``body`` contains an unclaimed-response fingerprint."""
    lowered = body.lower()
    return any(marker.lower() in lowered for marker in fingerprint.unclaimed_fingerprints)
