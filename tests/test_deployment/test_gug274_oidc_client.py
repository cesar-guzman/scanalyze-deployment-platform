"""Tests for the OIDC Public Client."""
import http.client
import json
import os
import pytest
import ssl

from tooling import platform_authority_bootstrap_oidc_client as oidc_client

VALID_ISSUER = "https://example.com"
VALID_AUD = "client-123"
VALID_AUTH_EP = "https://example.com/auth"
VALID_TOKEN_EP = "https://example.com/token"

def test_valid_client_creation():
    client = oidc_client.OidcPublicClient(
        issuer_url=VALID_ISSUER,
        audience=VALID_AUD,
        authorization_endpoint=VALID_AUTH_EP,
        token_endpoint=VALID_TOKEN_EP
    )
    assert client.issuer_url == VALID_ISSUER

@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://example.com:8443",
    "https://user:pass@example.com",
    "https://example.com?foo=bar",
    "https://example.com#frag",
    "https://example.com?",
    "https://example.com#",
    "https://example.com/foo%20bar",
    "https://example.com/foo\\bar",
    "https://example.com:abc/",
    "https://127.0.0.1",
    "https://[::1]",
    "https://localhost",
    "https://test.localhost",
    "https://example.com/ \n",
    "https://example.com.",
    "https://exámple.com",
])
def test_reject_invalid_urls(url):
    with pytest.raises(oidc_client.OidcClientError):
        oidc_client.OidcPublicClient(url, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)

@pytest.mark.parametrize("aud", [
    "client 123",
    "client\n",
    "",
    "client\x00",
    "a" * 257
])
def test_reject_invalid_audience(aud):
    with pytest.raises(oidc_client.OidcClientError):
        oidc_client.OidcPublicClient(VALID_ISSUER, aud, VALID_AUTH_EP, VALID_TOKEN_EP)

class MockResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self._headers = headers
        self._body = body
        self._read = False

    def getheader(self, name, default=""):
        return self._headers.get(name.lower(), default)

    def close(self):
        self.closed = True

    def read(self, amt=None):
        if self._read:
            return b""
        self._read = True
        if amt is not None and len(self._body) > amt:
            return self._body[:amt]
        return self._body

class MockConnection:
    def __init__(self, expected_host, expected_port, response):
        self.expected_host = expected_host
        self.expected_port = expected_port
        self.response = response
        self.request_called = False
        self.closed = False
        self.last_body = None
        self.last_headers = None
        self.last_path = None
        self.last_method = None

    def request(self, method, path, body, headers):
        self.last_method = method
        self.last_path = path
        self.last_body = body
        self.last_headers = headers
        self.request_called = True

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True

def test_exchange_code_success(monkeypatch):
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)

    valid_id_token = "a.b.c"
    resp_body = json.dumps({
        "token_type": "Bearer",
        "id_token": valid_id_token
    }).encode("utf-8")

    conn = MockConnection("example.com", 443, MockResponse(200, {"content-type": "application/json; charset=utf-8"}, resp_body))

    conn_args = {}
    def mock_https_conn(host, port, context, timeout):
        conn_args["host"] = host
        conn_args["port"] = port
        conn_args["context"] = context
        conn_args["timeout"] = timeout
        return conn

    monkeypatch.setattr(http.client, "HTTPSConnection", mock_https_conn)

    res = client.exchange_code(code="mycode123", verifier="a"*43, redirect_uri="http://127.0.0.1:38271/callback")
    assert res == valid_id_token
    assert conn.request_called
    assert conn.closed

    assert conn_args["host"] == "example.com"
    assert conn_args["port"] == 443
    assert isinstance(conn_args["context"], ssl.SSLContext)
    assert conn_args["timeout"] == 10.0

    assert conn.last_method == "POST"
    assert conn.last_path == "/token"
    assert conn.last_headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert conn.last_headers["Host"] == "example.com"

    assert b"grant_type=authorization_code" in conn.last_body
    assert b"client_id=client-123" in conn.last_body
    assert b"code=mycode" in conn.last_body
    assert b"code_verifier=" + (b"a"*43) in conn.last_body
    assert b"redirect_uri=http%3A%2F%2F127.0.0.1%3A38271%2Fcallback" in conn.last_body

@pytest.mark.parametrize("status, headers, body, expected_err", [
    (301, {"content-type": "application/json"}, b'{"id_token": "a.b.c", "token_type": "Bearer"}', "HTTP_STATUS_NOT_200"),
    (400, {"content-type": "application/json"}, b'{"error": "invalid_grant"}', "HTTP_STATUS_NOT_200"),
    (200, {"content-type": "text/plain"}, b'{}', "INVALID_CONTENT_TYPE"),
    (200, {"content-type": "application/json"}, b'not json', "INVALID_JSON"),
    (200, {"content-type": "application/json"}, b'{"id_token": "a.b.c", "id_token": "a.b.c"}', "INVALID_JSON"),
    (200, {"content-type": "application/json"}, b'{"id_token": "a.b.c", "token_type": "Bearer", "refresh_token": "abc"}', "REFRESH_TOKEN_PROHIBITED"),
    (200, {"content-type": "application/json"}, b'{"id_token": "a.b.c", "token_type": "Bearer", "error": "abc"}', "PROVIDER_RETURNED_ERROR"),
    (200, {"content-type": "application/json"}, b'{"id_token": "invalid", "token_type": "Bearer"}', "INVALID_ID_TOKEN_FORMAT"),
    (200, {"content-type": "application/json"}, b'{"id_token": "a.b.", "token_type": "Bearer"}', "INVALID_ID_TOKEN_FORMAT"),
    (200, {"content-type": "application/json"}, b'{"id_token": "a.b.c", "token_type": "mac"}', "INVALID_TOKEN_TYPE"),
    (200, {"content-type": "application/json"}, b'{"id_token": "a.b.c", "token_type": "Bearer", "val": NaN}', "INVALID_JSON"),
])
def test_exchange_code_rejections(monkeypatch, status, headers, body, expected_err):
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    conn = MockConnection("example.com", 443, MockResponse(status, headers, body))
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda host, port, context, timeout: conn)

    with pytest.raises(oidc_client.OidcClientError, match=expected_err):
        client.exchange_code(code="mycode123", verifier="a"*43, redirect_uri="http://127.0.0.1:38271/callback")

def test_exchange_code_oversize(monkeypatch):
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    body = b" " * (24 * 1024 + 10)
    conn = MockConnection("example.com", 443, MockResponse(200, {"content-type": "application/json"}, body))
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda host, port, context, timeout: conn)
    with pytest.raises(oidc_client.OidcClientError, match="RESPONSE_TOO_LARGE"):
        client.exchange_code(code="mycode123", verifier="a"*43, redirect_uri="http://127.0.0.1:38271/callback")

def test_ssl_env_vars(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/cert")
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    with pytest.raises(oidc_client.OidcClientError, match="CUSTOM_SSL_CERT_ENV_PROHIBITED"):
        client.exchange_code(code="mycode123", verifier="a"*43, redirect_uri="http://127.0.0.1:38271/callback")

def test_network_failure(monkeypatch):
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    class FailConn:
        def request(self, *args, **kwargs):
            raise OSError("fail")
        def close(self): pass
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda host, port, context, timeout: FailConn())

    with pytest.raises(oidc_client.OidcClientError, match="NETWORK_TRANSPORT_FAILED"):
        client.exchange_code(code="mycode123", verifier="a"*43, redirect_uri="http://127.0.0.1:38271/callback")

@pytest.mark.parametrize("code, verifier, redirect, err", [
    ("shrt", "a"*43, "http://127.0.0.1:38271/callback", "INVALID_CODE_FORMAT"),
    ("c"*4097, "a"*43, "http://127.0.0.1:38271/callback", "INVALID_CODE_FORMAT"),
    ("bad\ncode", "a"*43, "http://127.0.0.1:38271/callback", "INVALID_CODE_FORMAT"),
    ("mycode123", "short", "http://127.0.0.1:38271/callback", "INVALID_VERIFIER_FORMAT"),
    ("mycode123", "a"*129, "http://127.0.0.1:38271/callback", "INVALID_VERIFIER_FORMAT"),
    ("mycode123", "invalid!verifier" + "a"*30, "http://127.0.0.1:38271/callback", "INVALID_VERIFIER_FORMAT"),
    ("mycode123", "a"*43, "https://other.com/cb", "INVALID_REDIRECT_URI"),
])
def test_invalid_parameters(code, verifier, redirect, err):
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    with pytest.raises(oidc_client.OidcClientError, match=err):
        client.exchange_code(code=code, verifier=verifier, redirect_uri=redirect)

def test_repr_sanitization():
    try:
        raise oidc_client.OidcClientError("JUST_A_CODE")
    except Exception as e:
        assert "JUST_A_CODE" in repr(e)
        assert "mycode" not in repr(e)


@pytest.mark.parametrize("url", [
    "https://127.1", "https://2130706433", "https://0x7f000001",
    "https://127.000.0.1", "https://-invalid.example", "https://invalid_.example",
    "https://example.com:", "https://example.com:wrong", "https://[broken",
    "https://example.com/é", "https://example.com?", "https://example.com#",
])
def test_endpoint_rejects_resolver_aliases_and_malformed_authorities(url):
    with pytest.raises(oidc_client.OidcClientError) as caught:
        oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, url)
    assert url not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("where", ["context", "constructor", "request", "headers", "read", "response_close", "connection_close"])
def test_actual_transport_failures_are_sanitized_and_cleanup_is_attempted(monkeypatch, where):
    sensitive = "synthetic-provider-token-must-not-escape"
    events = []
    class Response(MockResponse):
        def read(self, amount):
            events.append("read")
            if where == "read":
                raise http.client.IncompleteRead(sensitive.encode())
            return super().read(amount)
        def close(self):
            events.append("response_close")
            if where == "response_close":
                raise OSError(sensitive)
    class Connection(MockConnection):
        def request(self, *args, **kwargs):
            if where == "request":
                raise OSError(sensitive)
            return super().request(*args, **kwargs)
        def getresponse(self):
            if where == "headers":
                raise http.client.BadStatusLine(sensitive)
            return super().getresponse()
        def close(self):
            events.append("connection_close")
            if where == "connection_close":
                raise OSError(sensitive)
    response = Response(200, {"content-type": "application/json"}, b'{"token_type":"Bearer","id_token":"a.b.c"}')
    connection = Connection("example.com", 443, response)
    def constructor(*args, **kwargs):
        if where == "constructor":
            raise OSError(sensitive)
        return connection
    monkeypatch.setattr(http.client, "HTTPSConnection", constructor)
    if where == "context":
        def context():
            raise OSError(sensitive)
        monkeypatch.setattr(ssl, "create_default_context", context)
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    with pytest.raises(oidc_client.OidcClientError, match="^NETWORK_TRANSPORT_FAILED$") as caught:
        client.exchange_code(code="mycode123", verifier="a" * 43, redirect_uri="http://127.0.0.1:38271/callback")
    assert sensitive not in str(caught.value) + repr(caught.value)
    assert caught.value.__suppress_context__ is True
    if where not in {"context", "constructor"}:
        assert events[-1] == "connection_close"
    if "read" in events and "response_close" in events:
        assert events.index("read") < events.index("response_close")


@pytest.mark.parametrize("body", [
    b'{"token_type":"Bearer","id_token":"a.b.c","extra":1e999}',
    b'{"token_type":"Bearer","id_token":"a.b.c","extra":' + b'[' * 12 + b'0' + b']' * 12 + b'}',
    b'{"token_type":"Bearer","id_token":"a.b.c","extra":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}',
    b'{"token_type":"Bearer","id_token":"a.b.c","extra":[' + b'0,' * 600 + b'0]}',
])
def test_response_extensions_have_finite_depth_size_and_numeric_bounds(monkeypatch, body):
    conn = MockConnection("example.com", 443, MockResponse(200, {"content-type": "application/json"}, body))
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda *args, **kwargs: conn)
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    with pytest.raises(oidc_client.OidcClientError, match="INVALID_JSON"):
        client.exchange_code(code="mycode123", verifier="a" * 43, redirect_uri="http://127.0.0.1:38271/callback")
    assert conn.closed


def test_response_deadline_interrupts_transport_and_never_returns_a_token(monkeypatch):
    from threading import Event
    stopped = Event()
    class Transport:
        def shutdown(self, how):
            stopped.set()
    class Response(MockResponse):
        def read(self, amount):
            assert stopped.wait(1.0), "The real deadline did not interrupt transport"
            return b'{"token_type":"Bearer","id_token":"a.b.c"}'
    conn = MockConnection("example.com", 443, Response(200, {"content-type": "application/json"}, b""))
    conn.sock = Transport()
    monkeypatch.setattr(oidc_client, "EXCHANGE_TIMEOUT", 0.025)
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda *args, **kwargs: conn)
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    with pytest.raises(oidc_client.OidcClientError, match="EXCHANGE_TIMEOUT"):
        client.exchange_code(code="mycode123", verifier="a" * 43, redirect_uri="http://127.0.0.1:38271/callback")
    assert conn.closed


@pytest.mark.parametrize("chunked", [False, True])
def test_exchange_reads_and_closes_the_real_http_response_parser(monkeypatch, chunked):
    from io import BytesIO
    payload = b'{"token_type":"Bearer","id_token":"a.b.c"}'
    body = (f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n") if chunked else payload
    framing = b"Transfer-Encoding: chunked\r\n" if chunked else f"Content-Length: {len(payload)}\r\n".encode()
    wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + framing + b"\r\n" + body
    class WireSocket:
        def makefile(self, _mode):
            return BytesIO(wire)
    response = http.client.HTTPResponse(WireSocket())
    response.begin()
    conn = MockConnection("example.com", 443, response)
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda *args, **kwargs: conn)
    client = oidc_client.OidcPublicClient(VALID_ISSUER, VALID_AUD, VALID_AUTH_EP, VALID_TOKEN_EP)
    assert client.exchange_code(code="mycode123", verifier="a" * 43, redirect_uri="http://127.0.0.1:38271/callback") == "a.b.c"
    assert conn.closed and response.isclosed()
