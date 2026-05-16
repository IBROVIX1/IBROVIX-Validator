"""Parser module for proxy protocol configs."""

from .vmess import VmessParser
from .vless import VlessParser
from .trojan import TrojanParser
from .ssh import SSHParser
from .ss import ShadowsocksParser

# Registry: map protocol type string -> parser instance
_registry: dict[str, object] = {}

def register_parser(protocol: str, parser: object) -> None:
    _registry[protocol] = parser

def get_parser(protocol: str) -> object:
    return _registry.get(protocol)

def get_all_parsers() -> dict[str, object]:
    return dict(_registry)

def parse_line(line: str) -> dict | None:
    """Try every registered parser on a single line of input.
    Returns the first successful parse result or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for proto, parser in _registry.items():
        result = parser.parse(line)
        if result is not None:
            return result
    return None

def detect_protocol(line: str) -> str | None:
    """Detect which protocol a config line belongs to without full parsing."""
    line = line.strip()
    if line.startswith("vmess://"):
        return "vmess"
    if line.startswith("vless://"):
        return "vless"
    if line.startswith("trojan://"):
        return "trojan"
    if line.startswith("ss://"):
        return "ss"
    if line.startswith("ssh://") or "@" in line or ":" in line.replace("ssh://", ""):
        # Could be SSH — let the parser handle it
        return "ssh"
    return None

# Import and register parsers
_vmess = VmessParser()
_vless = VlessParser()
_trojan = TrojanParser()
_ssh = SSHParser()
_ss = ShadowsocksParser()

register_parser("vmess", _vmess)
register_parser("vless", _vless)
register_parser("trojan", _trojan)
register_parser("ssh", _ssh)
register_parser("ss", _ss)
