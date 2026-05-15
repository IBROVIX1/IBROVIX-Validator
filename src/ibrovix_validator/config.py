"""Default configuration constants for IBROVIX-Validator."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ValidatorConfig:
    """Global validator configuration."""

    # Connection timeouts
    tcp_timeout: float = 5.0       # TCP connect timeout (seconds)
    tls_timeout: float = 8.0       # TLS handshake timeout (seconds)
    handshake_timeout: float = 10.0  # Full protocol handshake timeout (seconds)

    # Concurrency
    max_workers: int = 50          # Max concurrent validation tasks

    # Handshake test settings
    tls_probe: bool = True         # Perform TLS handshake test
    sni_check: bool = True         # Verify SNI/host compatibility
    trojan_probe: bool = True      # Send Trojan protocol header
    ssh_banner: bool = True        # Read SSH banner
    vmess_auth_probe: bool = True  # Send VMess auth probe

    # Filter defaults
    max_latency: Optional[float] = None  # Max acceptable latency (ms)
    alive_only: bool = False             # Show only alive servers
    protocols: list[str] = field(default_factory=lambda: ["vmess", "vless", "trojan", "ssh"])

    # Output
    output_format: str = "table"   # table | json | plain
    color_output: bool = True
    show_all_fields: bool = False


# Common V2Ray ports for quick heuristic validation
COMMON_V2RAY_PORTS = {443, 80, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8880, 8443}

# IP geolocation API (free tier)
IP_GEOLOCATION_API = "http://ip-api.com/json/{}"
