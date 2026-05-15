"""Trojan protocol config parser.

Supports:
  - Standard: trojan://<password>@<host>:<port>?params#name
  - Base64: base64-encoded trojan:// URLs
  - Legacy: plain password@host:port lines
"""

import base64
import urllib.parse
import re
from typing import Optional

from .base import BaseParser


class TrojanParser(BaseParser):
    """Parse Trojan share links into normalized config dicts."""

    def parse(self, raw_line: str) -> Optional[dict]:
        line = raw_line.strip()

        # Try base64-encoded first
        parsed = self._parse_b64(line)
        if parsed:
            return parsed

        # Try standard trojan:// URL
        if line.startswith("trojan://"):
            return self._parse_url(line)

        # Try legacy format: password@host:port
        if "@" in line and "://" not in line:
            return self._parse_legacy(line)

        return None

    def _parse_b64(self, line: str) -> Optional[dict]:
        """Try to decode as base64-encoded trojan:// URL."""
        try:
            padded = line
            missing_padding = len(padded) % 4
            if missing_padding:
                padded += "=" * (4 - missing_padding)

            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            decoded = decoded.strip()

            if decoded.startswith("trojan://"):
                return self._parse_url(decoded)
        except Exception:
            pass

        try:
            decoded = base64.b64decode(line).decode("utf-8", errors="replace").strip()
            if decoded.startswith("trojan://"):
                return self._parse_url(decoded)
        except Exception:
            pass

        return None

    def _parse_url(self, line: str) -> Optional[dict]:
        rest = line[len("trojan://"):].strip()

        # Fragment (name)
        name = ""
        if "#" in rest:
            rest, name_part = rest.rsplit("#", 1)
            name = urllib.parse.unquote(name_part)

        # Query params
        query = {}
        if "?" in rest:
            rest, query_str = rest.split("?", 1)
            query = dict(urllib.parse.parse_qsl(query_str))

        # password@host:port
        if "@" not in rest:
            return None

        password, hostport = rest.split("@", 1)
        password = urllib.parse.unquote(password)

        host = hostport.strip()
        port = 0

        if host.startswith("["):
            bracket_end = host.find("]")
            if bracket_end == -1:
                return None
            host_val = host[1:bracket_end]
            port_str = host[bracket_end+2:]
        else:
            if ":" in host:
                host_val, port_str = host.rsplit(":", 1)
            else:
                host_val = host
                port_str = "0"

        try:
            port = int(port_str) if port_str else 0
        except ValueError:
            port = 0

        # Trojan often uses "peer" for SNI
        sni = query.get("sni") or query.get("peer") or None

        result = {
            "type": "trojan",
            "name": name,
            "host": host_val,
            "port": port,
            "uuid": None,
            "password": password,
            "username": None,
            "aid": 0,
            "scy": "auto",
            "net": query.get("type", "tcp"),
            "tls": query.get("security", "tls"),   # Trojan always uses TLS
            "sni": sni,
            "path": query.get("path", ""),
            "host_header": query.get("host"),
            "encryption": "none",
            "flow": "",
            "type_field": query.get("headerType", "none"),
            "allowInsecure": query.get("allowInsecure", ""),
            "raw": line,
            "error": None,
        }

        result = self.normalize(result)

        if not result["host"] or not result["port"]:
            result["error"] = "Missing host or port"
        if not result["password"]:
            result["error"] = "Missing password"

        return result

    # Common SSH usernames — used to disambiguate Trojan password@host:port
    # from SSH user@host:port format (since both use @ separator)
    _COMMON_SSH_USERS = frozenset({
        'root', 'admin', 'user', 'ubuntu', 'debian', 'centos',
        'pi', 'ec2-user', 'administrator', 'test', 'guest', 'demo',
        'oracle', 'postgres', 'mysql', 'www', 'nobody', 'ftp', 'git',
        'runner', 'azureuser', 'kali', 'ibro'
    })

    def _parse_legacy(self, line: str) -> Optional[dict]:
        """Legacy format: password@host:port #name"""
        name = ""
        if "#" in line:
            line, name = line.rsplit("#", 1)
            name = name.strip()

        line = line.strip()
        if "@" not in line:
            return None

        password, hostport = line.split("@", 1)
        password = password.strip()
        host = hostport.strip()
        port = 0

        if ":" in host:
            host_val, port_str = host.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 0
        else:
            host_val = host

        # Disambiguate from SSH user@host:port format.
        # Trojan passwords are typically generated random strings (> 8 chars),
        # while SSH usernames are short common words.
        if (
            port in (22, 2222)
            or password.lower() in self._COMMON_SSH_USERS
            or (len(password) < 6 and password.isalnum())
        ):
            return None

        result = {
            "type": "trojan",
            "name": name.strip(),
            "host": host_val,
            "port": port,
            "uuid": None,
            "password": password,
            "username": None,
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
            "tls": "tls",
            "sni": None,
            "path": "",
            "host_header": None,
            "encryption": "none",
            "flow": "",
            "type_field": "none",
            "raw": line,
            "error": None,
        }

        result = self.normalize(result)
        if not result["host"] or not result["port"]:
            result["error"] = "Missing host or port"
        if not result["password"]:
            result["error"] = "Missing password"

        return result
