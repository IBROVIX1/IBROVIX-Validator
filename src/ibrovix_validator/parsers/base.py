"""Base parser interface for all protocol parsers."""

from abc import ABC, abstractmethod
from typing import Optional


class BaseParser(ABC):
    """Abstract base class for all config line parsers."""

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[dict]:
        """Parse a raw config line into a normalized config dictionary.
        
        Returns None if the line cannot be parsed by this parser.
        
        Normalized output fields (protocol-dependent):
            type: str          — protocol name
            name: str          — display name or label
            host: str          — server address (IP or domain)
            port: int          — server port
            uuid: str | None   — VMess/VLESS UUID
            password: str | None — Trojan password / SSH password
            username: str | None — SSH username
            aid: int | None    — VMess alterId
            scy: str | None    — VMess security method
            net: str | None    — transport (tcp/ws/grpc/quic)
            tls: str | None    — TLS type (tls/reality/none)
            sni: str | None    — Server Name Indicator
            path: str | None   — WebSocket path
            host_header: str | None — HTTP Host header
            encryption: str | None — VMess/VLESS encryption
            flow: str | None   — VLESS flow control
            raw: str           — original config line untouched
        """
        ...

    def normalize(self, data: dict) -> dict:
        """Apply final normalization to parsed data."""
        result = dict(data)
        result.setdefault("name", "")
        result.setdefault("host", "")
        result.setdefault("port", 0)
        result.setdefault("uuid", None)
        result.setdefault("password", None)
        result.setdefault("username", None)
        result.setdefault("aid", 0)
        result.setdefault("scy", "auto")
        result.setdefault("net", "tcp")
        result.setdefault("tls", "none")
        result.setdefault("sni", None)
        result.setdefault("path", "")
        result.setdefault("host_header", None)
        result.setdefault("encryption", "none")
        result.setdefault("flow", "")
        result.setdefault("error", None)
        return result
