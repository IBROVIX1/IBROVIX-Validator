"""SSH account config parser.

Supports:
  - Standard: ssh://user@host:port
  - Dropbear style: host:port:user:password
  - Custom: host:port:user:password (colon-separated)
  - OpenVPN style: user@host:port / password@host:port
  - Encoded formats (base64)
"""

import base64
import urllib.parse
import re
from typing import Optional

from .base import BaseParser


class SSHParser(BaseParser):
    """Parse SSH account configs into normalized config dicts."""

    # Regex patterns for common SSH formats
    PATTERNS = [
        # ssh://user@host:port
        re.compile(r"^ssh://(?:(?P<user>[^:@]+)(?::(?P<pass>[^@]*))?@)?(?P<host>[^:/]+)(?::(?P<port>\d+))?"),
        # user@host:port (no ssh://)
        re.compile(r"^(?P<user>[^:@]+)@(?P<host>[^:/]+):(?P<port>\d+)$"),
        # host:port:user:password (Dropbear style)
        re.compile(r"^(?P<host>[^:]+):(?P<port>\d+):(?P<user>[^:]+):(?P<pass>.*)$"),
        # host:port:user (no password)
        re.compile(r"^(?P<host>[^:]+):(?P<port>\d+):(?P<user>[^:]+)$"),
    ]

    def parse(self, raw_line: str) -> Optional[dict]:
        line = raw_line.strip()

        # Try base64-decoded
        decoded_b64 = self._try_b64(line)
        if decoded_b64:
            result = self._parse_any(decoded_b64)
            if result:
                return result

        # Try direct parsing
        result = self._parse_any(line)
        if result:
            return result

        return None

    def _try_b64(self, line: str) -> Optional[str]:
        """Try to decode as base64 and return decoded text if looks like SSH."""
        try:
            padded = line
            missing_padding = len(padded) % 4
            if missing_padding:
                padded += "=" * (4 - missing_padding)

            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace").strip()
            if "@" in decoded or ":" in decoded:
                decoded = decoded.encode("utf-8").decode("utf-8")
                return decoded
        except Exception:
            pass

        try:
            decoded = base64.b64decode(line).decode("utf-8", errors="replace").strip()
            if "@" in decoded or ":" in decoded:
                return decoded
        except Exception:
            pass

        return None

    def _parse_ssh_url(self, line: str) -> Optional[dict]:
        """Parse ssh:// URL format."""
        # ssh://user:password@host:port
        rest = line[len("ssh://"):].strip()

        name = ""
        if "#" in rest:
            rest, name_part = rest.rsplit("#", 1)
            name = urllib.parse.unquote(name_part)

        if "@" not in rest:
            return None

        userinfo, hostport = rest.split("@", 1)

        user = None
        password = None
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
            user = urllib.parse.unquote(user)
            password = urllib.parse.unquote(password)
        else:
            user = urllib.parse.unquote(userinfo)

        host = hostport.strip()
        port = 22

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
                port_str = "22"

        try:
            port = int(port_str) if port_str else 22
        except ValueError:
            port = 22

        if not host_val or not user:
            return None

        return {
            "type": "ssh",
            "name": name,
            "host": host_val,
            "port": port,
            "uuid": None,
            "password": password,
            "username": user,
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
            "tls": "none",
            "sni": host_val,  # SSH uses hostname for validation
            "path": "",
            "host_header": None,
            "encryption": "none",
            "flow": "",
            "type_field": "none",
            "raw": line,
            "error": None,
        }

    def _parse_any(self, line: str) -> Optional[dict]:
        """Try all known SSH formats."""
        if not line:
            return None

        # URL format
        if line.startswith("ssh://"):
            result = self._parse_ssh_url(line)
            if result:
                result = self.normalize(result)
                return self._clean_result(result)
            return None

        # Try each regex pattern
        for pattern in self.PATTERNS:
            m = pattern.match(line)
            if m:
                groups = m.groupdict()
                host = groups.get("host", "")
                port_str = groups.get("port", "22")
                user = groups.get("user")
                password = groups.get("pass")

                try:
                    port = int(port_str) if port_str else 22
                except ValueError:
                    port = 22

                if not host or not user:
                    continue

                result = {
                    "type": "ssh",
                    "name": "",
                    "host": host,
                    "port": port,
                    "uuid": None,
                    "password": password,
                    "username": user,
                    "aid": 0,
                    "scy": "auto",
                    "net": "tcp",
                    "tls": "none",
                    "sni": host,
                    "path": "",
                    "host_header": None,
                    "encryption": "none",
                    "flow": "",
                    "type_field": "none",
                    "raw": line,
                    "error": None,
                }
                result = self.normalize(result)
                return self._clean_result(result)

        return None

    def _clean_result(self, result: dict) -> dict:
        """Apply post-parse validation."""
        if not result["host"] or not result["port"]:
            result["error"] = "Missing host or port"
        if not result["username"]:
            result["error"] = "Missing username"
        return result
