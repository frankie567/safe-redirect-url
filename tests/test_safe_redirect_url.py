import pytest

from safe_redirect_url import url_has_allowed_host_and_scheme


@pytest.mark.parametrize(
    "url",
    (
        "http://example.com",
        "http:///example.com",
        "https://example.com",
        "ftp://example.com",
        r"\\example.com",
        r"\\\example.com",
        r"/\\/example.com",
        r"\\\example.com",
        r"\\example.com",
        r"\\//example.com",
        r"/\/example.com",
        r"\/example.com",
        r"/\example.com",
        "http:///example.com",
        r"http:/\//example.com",
        r"http:\/example.com",
        r"http:/\example.com",
        'javascript:alert("XSS")',
        "\njavascript:alert(x)",
        "java\nscript:alert(x)",
        "\x08//example.com",
        r"http://otherserver\@example.com",
        r"http:\\testserver\@example.com",
        r"http://testserver\me:pass@example.com",
        r"http://testserver\@example.com",
        r"http:\\testserver\confirm\me@example.com",
        "http:999999999",
        "ftp:9999999999",
        "\n",
        "http://[2001:cdba:0000:0000:0000:0000:3257:9652/",
        "http://2001:cdba:0000:0000:0000:0000:3257:9652]/",
    ),
)
def test_bad_urls(url: str):
    assert url_has_allowed_host_and_scheme(url, {"testserver", "testserver2"}) is False


@pytest.mark.parametrize(
    "url",
    (
        "/view/?param=http://example.com",
        "/view/?param=https://example.com",
        "/view?param=ftp://example.com",
        "view/?param=//example.com",
        "https://testserver/",
        "HTTPS://testserver/",
        "//testserver/",
        "http://testserver/confirm?email=me@example.com",
        "/url%20with%20spaces/",
        "path/http:2222222222",
    ),
)
def test_good_urls(url: str):
    assert url_has_allowed_host_and_scheme(url, {"testserver", "testserver2"}) is True


def test_basic_auth():
    # Valid basic auth credentials are allowed.
    assert (
        url_has_allowed_host_and_scheme(
            r"http://user:pass@testserver/", allowed_hosts={"user:pass@testserver"}
        )
        is True
    )


def test_no_allowed_hosts():
    # A path without host is allowed.
    assert (
        url_has_allowed_host_and_scheme("/confirm/me@example.com", allowed_hosts=None)
        is True
    )
    # Basic auth without host is not allowed.
    assert (
        url_has_allowed_host_and_scheme(
            "http://testserver\\@example.com", allowed_hosts=None
        )
        is False
    )


def test_allowed_hosts_str():
    assert (
        url_has_allowed_host_and_scheme(
            "http://good.com/good", allowed_hosts="good.com"
        )
        is True
    )
    assert (
        url_has_allowed_host_and_scheme("http://good.co/evil", allowed_hosts="good.com")
        is False
    )


@pytest.mark.parametrize(
    "url",
    (
        "https://example.com/p",
        "HTTPS://example.com/p",
        "/view/?param=http://example.com",
    ),
)
def test_secure_param_https_urls(url: str):
    assert (
        url_has_allowed_host_and_scheme(
            url, allowed_hosts={"example.com"}, require_https=True
        )
        is True
    )


@pytest.mark.parametrize(
    "url",
    (
        "http://example.com/p",
        "ftp://example.com/p",
        "//example.com/p",
    ),
)
def test_secure_param_non_https_urls(url: str):
    assert (
        url_has_allowed_host_and_scheme(
            url, allowed_hosts={"example.com"}, require_https=True
        )
        is False
    )
