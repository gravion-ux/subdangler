"""subdangler — dangling DNS / subdomain takeover risk checker."""

from .checker import Finding, Status, check_host, check_hosts

__version__ = "0.1.0"

__all__ = ["Finding", "Status", "__version__", "check_host", "check_hosts"]
