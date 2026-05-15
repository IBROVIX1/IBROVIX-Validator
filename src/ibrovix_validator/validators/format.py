"""Config format validator — checks structural integrity of parsed configs."""

import re
from typing import Optional

from .base import BaseValidator


class FormatValidator(BaseValidator):
    """Validate that a parsed config has all required fields properly formatted."""

    UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE
    )
    IP_PATTERN = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    DOMAIN_PATTERN = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    async def validate(self, config: dict) -> dict:
        """Validate config structure. Returns config with 'format_valid' and 'format_errors' added."""
        result = dict(config)
        errors = []

        # Check required fields
        if not config.get("host"):
            errors.append("Missing server host/address")
        else:
            host = config["host"]
            if not (self.IP_PATTERN.match(host) or self.DOMAIN_PATTERN.match(host)):
                # Allow raw IP or domain even if not perfect
                if not host.replace(".", "").replace("-", "").replace(":", "").isalnum():
                    errors.append(f"Suspicious host format: {host}")

        if not config.get("port"):
            errors.append("Missing or invalid port")
        elif not (0 < config["port"] < 65536):
            errors.append(f"Port out of range: {config['port']}")

        # Protocol-specific validation
        ptype = config.get("type", "")

        if ptype in ("vmess", "vless"):
            uuid = config.get("uuid")
            if not uuid:
                errors.append("Missing UUID")
            elif not self.UUID_PATTERN.match(uuid):
                errors.append(f"Invalid UUID format: {uuid}")

        if ptype == "trojan":
            if not config.get("password"):
                errors.append("Missing Trojan password")

        if ptype == "ssh":
            if not config.get("username"):
                errors.append("Missing SSH username")

        # Validate transport protocol
        valid_transports = {"tcp", "ws", "grpc", "quic", "kcp", "http", "h2"}
        net = config.get("net", "")
        if net and net not in valid_transports:
            errors.append(f"Unknown transport: {net}")

        # Validate TLS
        valid_tls = {"tls", "none", "reality", "xtls"}
        tls = config.get("tls", "")
        if tls and tls not in valid_tls and tls != "":
            errors.append(f"Unknown TLS mode: {tls}")

        result["format_valid"] = len(errors) == 0
        result["format_errors"] = errors
        return result
