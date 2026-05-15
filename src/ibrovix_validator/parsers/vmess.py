"""VMess protocol config parser.

Supports:
  - Standard: vmess://<base64-encoded-JSON>
  - Share链接: vmess://<base64> (various client formats)
"""

import base64
import json
import re
from typing import Optional

from .base import BaseParser


class VmessParser(BaseParser):
    """Parse VMess share links into normalized config dicts."""

    def parse(self, raw_line: str) -> Optional[dict]:
        line = raw_line.strip()
        if not line.startswith("vmess://"):
            return None

        b64_data = line[len("vmess://"):].strip()

        # Remove any trailing fragment identifiers or junk
        b64_data = b64_data.split("#")[0].split("?")[0]

        try:
            # Add padding if missing
            padded = b64_data
            missing_padding = len(padded) % 4
            if missing_padding:
                padded += "=" * (4 - missing_padding)

            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except (ValueError, Exception):
            try:
                decoded = base64.b64decode(b64_data).decode("utf-8", errors="replace")
            except (ValueError, Exception):
                return None

        # Parse JSON
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError:
            # Some clients use non-standard formats — try URL-decoded first
            import urllib.parse
            try:
                decoded = urllib.parse.unquote(b64_data)
                data = json.loads(decoded) if decoded.startswith("{") else None
                if data is None:
                    return None
            except Exception:
                return None

        if not isinstance(data, dict):
            return None

        # Normalize fields — different clients use different key names
        host = data.get("add") or data.get("host") or data.get("address") or data.get("addr", "")
        port_str = data.get("port", "0")

        if isinstance(port_str, str):
            # Handle port like "443" or "443,8443" (take first)
            port_str = port_str.split(",")[0].strip()

        try:
            port = int(port_str)
        except (ValueError, TypeError):
            port = 0

        # Extract name/remark
        name = data.get("ps") or data.get("remark") or data.get("name", "")

        result = {
            "type": "vmess",
            "name": name,
            "host": host,
            "port": port,
            "uuid": data.get("id"),
            "aid": self._to_int(data.get("aid", "0")),
            "scy": data.get("scy") or data.get("security", "auto"),
            "net": data.get("net") or data.get("network", "tcp"),
            "tls": data.get("tls") or data.get("security_type", "none"),
            "sni": data.get("sni") or data.get("servername", None),
            "path": data.get("path", ""),
            "host_header": data.get("host"),
            "encryption": data.get("encryption", "none"),
            "flow": data.get("flow", ""),
            "type_field": data.get("type", "none"),  # header type (none/http)
            "raw": raw_line,
            "error": None,
        }

        result = self.normalize(result)

        # Basic validation
        if not result["host"] or not result["port"]:
            result["error"] = "Missing host or port"
        if not result["uuid"]:
            result["error"] = "Missing UUID (id)"

        return result

    @staticmethod
    def _to_int(val) -> int:
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0
