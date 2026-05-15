"""VLESS protocol config parser.

Supports:
  - Standard: vless://<uuid>@<host>:<port>?params#name
"""

import urllib.parse
from typing import Optional

from .base import BaseParser


class VlessParser(BaseParser):
    """Parse VLESS share links into normalized config dicts."""

    def parse(self, raw_line: str) -> Optional[dict]:
        line = raw_line.strip()
        if not line.startswith("vless://"):
            return None

        # Strip protocol prefix
        rest = line[len("vless://"):].strip()

        # Split fragment (name)
        name = ""
        if "#" in rest:
            rest, name_part = rest.rsplit("#", 1)
            name = urllib.parse.unquote(name_part)

        # Split query parameters
        query = {}
        if "?" in rest:
            rest, query_str = rest.split("?", 1)
            query = dict(urllib.parse.parse_qsl(query_str))

        # Parse authority: uuid@host:port
        if "@" not in rest:
            return None

        userinfo, hostport = rest.split("@", 1)
        uuid = userinfo.strip()

        # Parse host and port
        host = hostport.strip()
        port = 0

        # IPv6 handling: [::1]:port
        if host.startswith("["):
            bracket_end = host.find("]")
            if bracket_end == -1:
                return None
            host_val = host[1:bracket_end]
            port_str = host[bracket_end+2:]  # skip "]:"
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

        # V2Ray uses "peer" as the TLS SNI field in the future, but currently "sni"
        sni = query.get("sni") or query.get("peer") or None

        result = {
            "type": "vless",
            "name": name,
            "host": host_val,
            "port": port,
            "uuid": uuid,
            "password": None,
            "username": None,
            "aid": 0,
            "scy": query.get("security", "auto"),
            "net": query.get("type", "tcp"),
            "tls": query.get("security", "none"),
            "sni": sni,
            "path": query.get("path", "") or query.get("serviceName", ""),
            "host_header": query.get("host"),
            "encryption": query.get("encryption", "none"),
            "flow": query.get("flow", ""),
            "type_field": query.get("headerType", "none"),
            "allowInsecure": query.get("allowInsecure", ""),
            "fp": query.get("fp", ""),                # fingerprint (reality)
            "pbk": query.get("pbk", ""),              # public key (reality)
            "sid": query.get("sid", ""),              # shortId (reality)
            "raw": raw_line,
            "error": None,
        }

        result = self.normalize(result)

        if not result["host"] or not result["port"]:
            result["error"] = "Missing host or port"
        if not result["uuid"]:
            result["error"] = "Missing UUID"

        return result
