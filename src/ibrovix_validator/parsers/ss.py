"""Shadowsocks (SS) protocol config parser.

Supports:
  - SIP002: ss://BASE64(method:password)@host:port?params#name
  - Classic: ss://BASE64(method:password)@host:port#name
  - Nested base64: ss://BASE64(ss://...) format
  - Plain: method:password@host:port
"""

import base64
import urllib.parse
import re
from typing import Optional

from .base import BaseParser


class ShadowsocksParser(BaseParser):
    """Parse Shadowsocks share links into normalized config dicts."""

    # Common Shadowsocks encryption methods
    VALID_CIPHERS = frozenset({
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
        "des-cfb", "rc4-md5", "rc4-md5-6",
        "chacha20", "chacha20-ietf", "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305", "salsa20", "xsalsa20",
        "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
        "none", "plain",
    })

    def parse(self, raw_line: str) -> Optional[dict]:
        line = raw_line.strip()
        if not line.lower().startswith("ss://"):
            return None

        rest = line[len("ss://"):].strip()

        # Extract fragment (name)
        name = ""
        if "#" in rest:
            rest, name_part = rest.rsplit("#", 1)
            name = urllib.parse.unquote(name_part)

        # Attempt 1: Try SIP002 format: BASE64(method:password)@host:port
        # where the base64 part is before the @ symbol
        if "@" in rest:
            b64_part, hostport = rest.split("@", 1)

            # Try to decode the userinfo part
            try:
                decoded_userinfo = self._decode_ss_userinfo(b64_part)
            except Exception:
                decoded_userinfo = None

            if decoded_userinfo:
                method, password = decoded_userinfo
            else:
                # Could be plain method:password before @
                if ":" in b64_part:
                    parts = b64_part.split(":", 1)
                    method = parts[0]
                    password = parts[1]
                else:
                    return None

            # Parse host and port
            hostport = hostport.strip()

            # Split query parameters (before host:port parsing)
            query = {}
            if "?" in hostport:
                hostport, query_str = hostport.split("?", 1)
                query = dict(urllib.parse.parse_qsl(query_str))

            # Strip trailing slash from hostport (leftover after ? split)
            hostport = hostport.rstrip("/")

            host_val, port = self._parse_hostport(hostport)
            # If host/port is invalid, return partial config with error instead of None
            if not host_val or not port:
                result = self.normalize({
                    "type": "ss",
                    "name": name,
                    "host": host_val or "",
                    "port": port or 0,
                    "method": method,
                    "password": password,
                    "plugin": "",
                    "raw": raw_line,
                })
                result["error"] = "Missing host or port"
                return result

            plugin = query.get("plugin", "")

            result = {
                "type": "ss",
                "name": name,
                "host": host_val,
                "port": port,
                "uuid": None,
                "password": password,
                "username": None,
                "method": method,
                "plugin": plugin,
                "aid": 0,
                "scy": "auto",
                "net": "tcp",
                "tls": "none",
                "sni": None,
                "path": "",
                "host_header": None,
                "encryption": "none",
                "flow": "",
                "type_field": "none",
                "raw": raw_line,
                "error": None,
            }
            result = self.normalize(result)
            return self._clean_result(result)

        # Attempt 2: The entire rest might be base64-encoded SS URI
        # Try decoding the whole thing and re-parse
        decoded_full = self._try_b64_decode(rest)
        if decoded_full:
            decoded_str = decoded_full.strip()
            if decoded_str.lower().startswith("ss://"):
                return self.parse(decoded_str)
            # Could be plain text: method:password@host:port
            if "@" in decoded_str:
                # Reconstruct a proper URI and parse
                reconstructed = f"ss://{decoded_str}"
                return self.parse(reconstructed)

        return None

    def _decode_ss_userinfo(self, b64_str: str) -> Optional[tuple[str, str]]:
        """Decode the base64-encoded method:password portion of an SS URI.

        SIP002 uses URL-safe base64 without padding.
        """
        # Remove any trailing query params or junk
        b64_str = b64_str.split("?")[0].split("#")[0].strip()

        decoded = self._try_b64_decode(b64_str)
        if not decoded:
            return None

        if ":" in decoded:
            method, password = decoded.split(":", 1)
            method = method.strip()
            password = password.strip()
            if method and password:
                return method, password

        return None

    def _try_b64_decode(self, data: str) -> Optional[str]:
        """Try to decode a string as base64 or URL-safe base64."""
        if not data:
            return None

        # Clean the data
        cleaned = data.strip()

        for variant in ["urlsafe", "standard"]:
            try:
                padded = cleaned
                missing_padding = len(padded) % 4
                if missing_padding:
                    padded += "=" * (4 - missing_padding)

                if variant == "urlsafe":
                    # URL-safe base64 uses - instead of + and _ instead of /
                    decoded_bytes = base64.urlsafe_b64decode(padded)
                else:
                    decoded_bytes = base64.b64decode(padded)

                decoded = decoded_bytes.decode("utf-8", errors="replace")

                # Verify the decoded content looks plausible
                # For SS userinfo, it should be in format method:password
                if ":" in decoded or "@" in decoded or decoded.isprintable():
                    return decoded
            except (ValueError, Exception):
                continue

        return None

    @staticmethod
    def _parse_hostport(hostport: str) -> tuple[Optional[str], Optional[int]]:
        """Parse host:port string, handling IPv6 addresses."""
        hostport = hostport.strip()
        port = None
        host_val = None

        if hostport.startswith("["):
            # IPv6: [::1]:port
            bracket_end = hostport.find("]")
            if bracket_end == -1:
                return None, None
            host_val = hostport[1:bracket_end]
            port_str = hostport[bracket_end+1:]  # includes the leading ":"
            if port_str.startswith(":"):
                port_str = port_str[1:]
            try:
                port = int(port_str) if port_str else None
            except ValueError:
                port = None
        else:
            if ":" in hostport:
                host_val, port_str = hostport.rsplit(":", 1)
                try:
                    port = int(port_str) if port_str else None
                except ValueError:
                    port = None
            else:
                host_val = hostport
                port = None

        return host_val, port

    def _clean_result(self, result: dict) -> dict:
        """Apply post-parse validation."""
        if not result["host"] or not result["port"]:
            result["error"] = "Missing host or port"
        if not result.get("method"):
            result["error"] = "Missing encryption method"
        if not result["password"]:
            result["error"] = "Missing password"
        if result.get("method") and result["method"] not in self.VALID_CIPHERS:
            result["error"] = f"Unknown encryption method: {result['method']}"
        return result

    def normalize(self, data: dict) -> dict:
        """Override normalize to include ss-specific fields."""
        result = dict(data)
        result.setdefault("name", "")
        result.setdefault("host", "")
        result.setdefault("port", 0)
        result.setdefault("method", "aes-256-gcm")
        result.setdefault("password", None)
        result.setdefault("plugin", "")
        result.setdefault("error", None)
        return result
