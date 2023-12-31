"""
Check the safety of a redirect URL.

Extracted from Django's [`url_has_allowed_host_and_scheme`](https://github.com/django/django/blob/main/django/utils/http.py).
"""

__version__ = "0.1.1"

import unicodedata
from urllib.parse import urlparse


def url_has_allowed_host_and_scheme(
    url: str, allowed_hosts: str | set[str] | None = None, require_https: bool = False
) -> bool:
    """
    Return ``True`` if the url uses an allowed host and a safe scheme.

    Always return ``False`` on an empty url.

    Args:
        url: The URL to test.
        allowed_hosts: Set of allowed hosts.
        require_https: If ``True``, only 'https' will be considered a valid
        scheme, as opposed to 'http' and 'https' with the default, ``False``.
    """
    url = url.strip()
    if not url:
        return False
    if allowed_hosts is None:
        allowed_hosts = set()
    elif isinstance(allowed_hosts, str):
        allowed_hosts = {allowed_hosts}
    # Chrome treats \ completely as / in paths but it could be part of some
    # basic auth credentials so we need to check both URLs.
    return _url_has_allowed_host_and_scheme(
        url, allowed_hosts, require_https=require_https
    ) and _url_has_allowed_host_and_scheme(
        url.replace("\\", "/"), allowed_hosts, require_https=require_https
    )


def _url_has_allowed_host_and_scheme(
    url: str, allowed_hosts: set[str], require_https: bool = False
):
    # Chrome considers any URL with more than two slashes to be absolute, but
    # urlparse is not so flexible. Treat any url with three slashes as unsafe.
    if url.startswith("///"):
        return False
    try:
        url_info = urlparse(url)
    except ValueError:  # e.g. invalid IPv6 addresses
        return False
    # Forbid URLs like http:///example.com - with a scheme, but without a hostname.
    # In that URL, example.com is not the hostname but, a path component. However,
    # Chrome will still consider example.com to be the hostname, so we must not
    # allow this syntax.
    if not url_info.netloc and url_info.scheme:
        return False
    # Forbid URLs that start with control characters. Some browsers (like
    # Chrome) ignore quite a few control characters at the start of a
    # URL and might consider the URL as scheme relative.
    if unicodedata.category(url[0])[0] == "C":
        return False
    scheme = url_info.scheme
    # Consider URLs without a scheme (e.g. //example.com/p) to be http.
    if not url_info.scheme and url_info.netloc:
        scheme = "http"
    valid_schemes = ["https"] if require_https else ["http", "https"]
    return (not url_info.netloc or url_info.netloc in allowed_hosts) and (
        not scheme or scheme in valid_schemes
    )


__all__ = ["url_has_allowed_host_and_scheme"]
