"""OIDC Public Client for PKCE exchange."""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
from threading import Event, Timer
from typing import Any
import urllib.parse

EXCHANGE_TIMEOUT = 10.0


class OidcClientError(ValueError):
    """Sanitized error for OIDC client operations. Tokens are not logged."""
    pass


def _validate_https_endpoint(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise OidcClientError("URL_INVALID_FORMAT")
    if any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise OidcClientError("URL_CONTROL_CHARS_PROHIBITED")
    if "\\" in url or "%" in url:
        raise OidcClientError("URL_INVALID_CHARS")

    try:
        parsed = urllib.parse.urlsplit(url)
        _ = parsed.port  # Trigger ValueError if port is invalid
    except ValueError:
        raise OidcClientError("URL_INVALID_PORT_FORMAT") from None

    if parsed.scheme != "https":
        raise OidcClientError("URL_MUST_BE_HTTPS")

    if "?" in url or "#" in url:
        raise OidcClientError("URL_QUERY_FRAGMENT_PROHIBITED")

    if parsed.query or parsed.fragment or "@" in parsed.netloc:
        raise OidcClientError("URL_QUERY_FRAGMENT_USERINFO_PROHIBITED")

    host = parsed.hostname
    if not host:
        raise OidcClientError("URL_MISSING_HOST")
    labels = host.split(".")
    if (
        not url.isascii() or not url.startswith("https://")
        or len(host) > 253 or len(labels) < 2 or parsed.netloc.endswith(":")
        or not any(c.isalpha() for c in labels[-1])
        or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise OidcClientError("URL_HOST_INVALID")

    if not host.isascii():
        raise OidcClientError("URL_HOST_NON_ASCII")
    if host.endswith("."):
        raise OidcClientError("URL_HOST_FQDN_TRAILING_DOT_PROHIBITED")

    if parsed.port is not None and parsed.port != 443:
        raise OidcClientError("URL_INVALID_PORT")

    if host == "localhost" or host.endswith(".localhost"):
        raise OidcClientError("URL_LOCALHOST_PROHIBITED")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip or "[" in parsed.netloc or "]" in parsed.netloc:
        raise OidcClientError("URL_IP_ADDRESS_PROHIBITED")

    return url


@dataclass(frozen=True)
class OidcPublicClient:
    issuer_url: str
    audience: str
    authorization_endpoint: str
    token_endpoint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "issuer_url", _validate_https_endpoint(self.issuer_url))
        object.__setattr__(self, "authorization_endpoint", _validate_https_endpoint(self.authorization_endpoint))
        object.__setattr__(self, "token_endpoint", _validate_https_endpoint(self.token_endpoint))

        if not isinstance(self.audience, str) or not self.audience:
            raise OidcClientError("AUDIENCE_EMPTY")
        if not self.audience.isascii() or " " in self.audience or any(ord(c) <= 32 or ord(c) == 127 for c in self.audience):
            raise OidcClientError("AUDIENCE_INVALID_CHARS")
        if len(self.audience) > 256:
            raise OidcClientError("AUDIENCE_TOO_LONG")

    def exchange_code(self, *, code: str, verifier: str, redirect_uri: str) -> str:
        if not isinstance(code, str) or not (8 <= len(code) <= 4096):
            raise OidcClientError("INVALID_CODE_FORMAT")
        if not code.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in code):
            raise OidcClientError("INVALID_CODE_FORMAT")

        if not isinstance(verifier, str) or not (43 <= len(verifier) <= 128):
            raise OidcClientError("INVALID_VERIFIER_FORMAT")

        if not re.fullmatch(r"[A-Za-z0-9\-._~]+", verifier):
            raise OidcClientError("INVALID_VERIFIER_FORMAT")

        if redirect_uri != "http://127.0.0.1:38271/callback":
            raise OidcClientError("INVALID_REDIRECT_URI")

        if "SSL_CERT_FILE" in os.environ or "SSL_CERT_DIR" in os.environ:
            raise OidcClientError("CUSTOM_SSL_CERT_ENV_PROHIBITED")

        parsed_endpoint = urllib.parse.urlsplit(self.token_endpoint)
        host = parsed_endpoint.hostname
        assert host is not None

        try:
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, 443, context=context, timeout=EXCHANGE_TIMEOUT)
        except (OSError, http.client.HTTPException):
            raise OidcClientError("NETWORK_TRANSPORT_FAILED") from None

        body_str = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": self.audience,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri
        })
        body_bytes = body_str.encode("ascii")

        path = parsed_endpoint.path if parsed_endpoint.path else "/"

        raw_bytes = None
        data = None
        resp = None
        active_socket = None
        expired = Event()

        def expire() -> None:
            expired.set()
            transport = active_socket or getattr(conn, "sock", None)
            if transport is not None:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        deadline = Timer(EXCHANGE_TIMEOUT, expire)
        deadline.daemon = True
        try:
            deadline.start()
            try:
                conn.request("POST", path, body=body_bytes, headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Connection": "close",
                    "Host": host
                })
                # Preserve the socket if getresponse detaches a Connection:
                # close response. Interrupt a slow response after the deadline.
                active_socket = getattr(conn, "sock", None)
                if expired.is_set():
                    raise OidcClientError("EXCHANGE_TIMEOUT")
                resp = conn.getresponse()
                if resp.status != 200:
                    raise OidcClientError("HTTP_STATUS_NOT_200")

                content_type = resp.getheader("Content-Type", "")

                mime_type = content_type.split(";")[0].strip().lower()
                if mime_type != "application/json":
                    raise OidcClientError("INVALID_CONTENT_TYPE")

                raw_bytes = resp.read(24 * 1024 + 1)
                if len(raw_bytes) > 24 * 1024:
                    raise OidcClientError("RESPONSE_TOO_LARGE")
            except (OSError, http.client.HTTPException):
                raise OidcClientError("NETWORK_TRANSPORT_FAILED") from None

            def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                out: dict[str, Any] = {}
                for k, v in pairs:
                    if k in out:
                        raise ValueError("DUPLICATE_KEYS")
                    out[k] = v
                return out

            try:
                data = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda x: float("a"))
                pending, count = [(data, 0)], 0
                while pending:
                    item, depth = pending.pop()
                    count += 1
                    if depth > 8 or count > 512:
                        raise ValueError
                    if type(item) is dict:
                        pending.extend((part, depth + 1) for pair in item.items() for part in pair)
                    elif type(item) is list:
                        pending.extend((part, depth + 1) for part in item)
                    elif type(item) is float and not math.isfinite(item):
                        raise ValueError
            except (ValueError, UnicodeError, RecursionError):
                raise OidcClientError("INVALID_JSON") from None

            if type(data) is not dict:
                raise OidcClientError("INVALID_JSON_OBJECT")

            if "error" in data:
                raise OidcClientError("PROVIDER_RETURNED_ERROR")
            if "refresh_token" in data:
                raise OidcClientError("REFRESH_TOKEN_PROHIBITED")

            token_type = data.get("token_type")
            if not isinstance(token_type, str) or token_type.lower() != "bearer":
                raise OidcClientError("INVALID_TOKEN_TYPE")

            id_token = data.get("id_token")
            if not isinstance(id_token, str) or len(id_token) > 12 * 1024:
                raise OidcClientError("INVALID_ID_TOKEN_SIZE_OR_TYPE")

            parts = id_token.split(".")
            if len(parts) != 3 or not all(parts):
                raise OidcClientError("INVALID_ID_TOKEN_FORMAT")

            if not all(re.fullmatch(r"[A-Za-z0-9\-_]+", p) for p in parts):
                raise OidcClientError("INVALID_ID_TOKEN_FORMAT")

            if expired.is_set():
                raise OidcClientError("EXCHANGE_TIMEOUT")
            return id_token
        finally:
            deadline.cancel()
            body_bytes = raw_bytes = b""
            body_str = code = verifier = ""
            id_token = ""
            if type(data) is dict:
                data.clear()
            try:
                try:
                    if resp is not None:
                        resp.close()
                finally:
                    conn.close()
            except (OSError, http.client.HTTPException):
                raise OidcClientError("NETWORK_TRANSPORT_FAILED") from None
