# subdangler

Dangling DNS / subdomain takeover risk checker. Given a list of hostnames,
`subdangler` resolves their CNAME records, flags CNAMEs that point at
takeover-prone third-party services (GitHub Pages, Heroku, AWS S3, Azure,
Netlify, Shopify, Fastly, and more), and checks whether the target looks
unclaimed — either because the HTTP response carries the service's
"no such resource" fingerprint or because the CNAME target no longer
resolves at all.

Pure Python standard library: CNAME lookups use DNS-over-HTTPS JSON
(Google Public DNS by default) via `urllib`, existence checks use
`socket.getaddrinfo`. No third-party dependencies.

## Authorised use

Use this tool only on domains you own or are explicitly authorised to
test (for example, within the scope of a bug bounty program). A
`vulnerable-likely` result is a prompt to verify manually and report
responsibly — never claim a subdomain you do not own.

## Install

```bash
pip install -e .
```

Requires Python 3.11+.

## Usage

```bash
# Check hostnames directly
subdangler blog.example.com shop.example.com

# Check a list from a file (one hostname per line, '#' comments allowed)
subdangler --file hosts.txt

# JSON report (for piping into other tools)
subdangler --file hosts.txt --format json

# DNS-only mode (skip the HTTP fingerprint check)
subdangler --no-http blog.example.com

# Offline mode with canned resolver/HTTP results (no network)
subdangler --fixture fixture.json blog.example.com
```

URLs are accepted too (`https://sub.example.com/path` is cleaned to
`sub.example.com`). Hostnames are de-duplicated.

### Example output

```text
$ subdangler blog.example.com www.example.com plain.example.com
VULNERABLE-LIKELY  blog.example.com -> foo.github.io (GitHub Pages): response matches the GitHub Pages unclaimed-resource fingerprint
CLAIMED            www.example.com -> foo.github.io (GitHub Pages): target resolves and the response (HTTP 200) shows no unclaimed fingerprint
NO-CNAME           plain.example.com: no CNAME record
Checked 3 host(s): 1 vulnerable-likely, 1 claimed, 0 unknown, 1 no-cname.
```

### Statuses

| Status | Meaning |
| --- | --- |
| `vulnerable-likely` | CNAME points at a takeover-prone service and the response matches its unclaimed fingerprint, or the CNAME target does not resolve (dangling). |
| `claimed` | CNAME points at a takeover-prone service, the target resolves, and the response shows no unclaimed fingerprint. |
| `unknown` | A CNAME exists but cannot be judged: unrecognised service, lookup failure, or DNS-only mode with a resolving target. |
| `no-cname` | No CNAME record; this takeover class does not apply. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No `vulnerable-likely` findings. |
| `1` | At least one `vulnerable-likely` finding. |
| `2` | Usage error (no hostnames, unreadable file, invalid input). |

### Offline fixture format

`--fixture` reads canned results so checks can run (and be tested) with no
network access:

```json
{
  "blog.example.com": {
    "cnames": ["foo.github.io"],
    "resolves": {"foo.github.io": true},
    "http_status": 404,
    "http_body": "There isn't a GitHub Pages site here."
  }
}
```

`resolves` may also be a plain boolean applying to the last CNAME in the
chain.

## How it works

1. CNAME chain is fetched from a DNS-over-HTTPS JSON endpoint
   (`https://dns.google/resolve` by default; override with `--doh-url`).
2. Each CNAME is matched, on whole DNS labels, against a built-in table of
   takeover-prone services and their CNAME suffixes
   (`src/subdangler/fingerprints.py`).
3. If a service matches, the hostname is fetched over HTTPS (falling back
   to HTTP) and the body is checked for the service's unclaimed-resource
   fingerprint. The CNAME target's existence is checked with
   `socket.getaddrinfo`; a non-resolving target is a dangling record.

## Limitations

- Only CNAME-based takeovers are covered; dangling A/AAAA records pointing
  at released cloud IPs are out of scope.
- Fingerprints are heuristics. A `vulnerable-likely` result should always
  be confirmed manually before reporting, and a `claimed` result is not a
  guarantee (some services serve fingerprints only on specific paths).
- The fingerprint table is a snapshot; services change their error pages
  over time.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Tests are fully offline: the resolver and HTTP fetcher are injected with
canned results.

## License

MIT — see [LICENSE](LICENSE).
