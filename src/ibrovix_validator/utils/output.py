"""Output formatting and display utilities."""

import json
import sys
from typing import Optional


# ANSI color codes
class Colorizer:
    """Simple ANSI terminal color helper."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.RESET}"

    @classmethod
    def green(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.RESET}"

    @classmethod
    def yellow(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.RESET}"

    @classmethod
    def blue(cls, text: str) -> str:
        return f"{cls.BLUE}{text}{cls.RESET}"

    @classmethod
    def cyan(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.RESET}"

    @classmethod
    def magenta(cls, text: str) -> str:
        return f"{cls.MAGENTA}{text}{cls.RESET}"

    @classmethod
    def gray(cls, text: str) -> str:
        return f"{cls.GRAY}{text}{cls.RESET}"

    @classmethod
    def bold(cls, text: str) -> str:
        return f"{cls.BOLD}{text}{cls.RESET}"

    @classmethod
    def status_tag(cls, alive: Optional[bool]) -> str:
        if alive is True:
            return f"{cls.BG_GREEN}{cls.BOLD} ALIVE {cls.RESET}"
        elif alive is False:
            return f"{cls.BG_RED}{cls.BOLD} DEAD  {cls.RESET}"
        else:
            return f"{cls.BG_YELLOW}{cls.BOLD} UNKNOWN {cls.RESET}"

    @classmethod
    def protocol_tag(cls, proto: str) -> str:
        colors = {
            "vmess": cls.MAGENTA,
            "vless": cls.BLUE,
            "trojan": cls.RED,
            "ssh": cls.GREEN,
        }
        color = colors.get(proto, cls.WHITE)
        return f"{color}{cls.BOLD}{proto.upper():<7}{cls.RESET}"

    @classmethod
    def latency_str(cls, ms: Optional[float]) -> str:
        if ms is None:
            return cls.gray("--- ms")
        if ms < 100:
            return cls.green(f"{ms:<5.1f} ms")
        elif ms < 300:
            return cls.yellow(f"{ms:<5.1f} ms")
        else:
            return cls.red(f"{ms:<5.1f} ms")


class OutputFormatter:
    """Format proxy config lists for various output types."""

    def __init__(self, use_color: bool = True):
        self.color = use_color

    def format_table(self, configs: list[dict]) -> str:
        """Render configs as a pretty table."""
        if not configs:
            return "No configs to display."

        # Column widths
        lines = []
        header = f"{'#':>3}  {'Protocol':<9} {'Name':<24} {'Host':<22} {'Port':<5} {'Status':<8} {'Latency':<8} {'Transport':<6} {'TLS':<6} {'SNI':<20} Notes"
        sep = "─" * 140

        if self.color:
            lines.append(self._colorize(Colorizer.cyan(sep)))
            lines.append(self._colorize(Colorizer.bold(header)))
            lines.append(self._colorize(Colorizer.cyan(sep)))
        else:
            lines.append(sep)
            lines.append(header)
            lines.append(sep)

        for i, cfg in enumerate(configs, 1):
            proto = cfg.get("type", "?")
            name = (cfg.get("name", "") or "")[:23]
            host = cfg.get("host", "")[:21]
            port = cfg.get("port", 0)
            alive = cfg.get("alive")
            latency = cfg.get("latency_ms")
            net = cfg.get("net", "?")
            tls = cfg.get("tls", "?")
            sni = (cfg.get("sni") or "")[:19]
            err = cfg.get("error") or cfg.get("handshake_error") or ""

            if self.color:
                status = Colorizer.status_tag(alive)
                lat_str = Colorizer.latency_str(latency)
                proto_tag = Colorizer.protocol_tag(proto)
                row = (
                    f"{i:>3}  {proto_tag} {name:<24} {host:<22} {port:<5} "
                    f"{status} {lat_str} {net:<6} {tls:<6} {sni:<20} {err[:40]}"
                )
            else:
                status = "ALIVE" if alive is True else "DEAD" if alive is False else "?"
                lat_str = f"{latency:.1f}ms" if latency is not None else "---"
                row = (
                    f"{i:>3}  {proto:<9} {name:<24} {host:<22} {port:<5} "
                    f"{status:<8} {lat_str:<8} {net:<6} {tls:<6} {sni:<20} {err[:40]}"
                )
            lines.append(row)

        if self.color:
            lines.append(self._colorize(Colorizer.cyan(sep)))
        else:
            lines.append(sep)

        return "\n".join(lines)

    def format_json(self, configs: list[dict], pretty: bool = True) -> str:
        """Render configs as JSON."""
        indent = 2 if pretty else None
        return json.dumps(configs, indent=indent, default=str, ensure_ascii=False)

    def format_plain(self, configs: list[dict]) -> str:
        """Render configs as flat text lines (for piping/export)."""
        lines = []
        for cfg in configs:
            proto = cfg.get("type", "?")
            name = cfg.get("name", "") or ""
            host = cfg.get("host", "")
            port = cfg.get("port", 0)
            alive = cfg.get("alive")
            latency = cfg.get("latency_ms")
            lat_str = f"{latency:.1f}ms" if latency is not None else "---"
            status = "OK" if alive else "DEAD"

            if name:
                lines.append(f"[{proto.upper()}] {name} — {host}:{port} [{status}] {lat_str}")
            else:
                lines.append(f"[{proto.upper()}] {host}:{port} [{status}] {lat_str}")
        return "\n".join(lines)

    def format_stats(self, stats: dict) -> str:
        """Render statistics summary."""
        lines = []
        if self.color:
            lines.append(self._colorize(Colorizer.bold("\n═══ IBROVIX-Validator Statistics ═══")))

        lines.append(f"  Total configs:     {stats['total']}")
        lines.append(f"  Alive:             {stats['alive']}")
        lines.append(f"  Dead:              {stats['dead']}")
        lines.append(f"  Untested:          {stats['untested']}")

        if stats.get("avg_latency_ms"):
            lines.append(f"  Avg latency:       {stats['avg_latency_ms']:.1f} ms")
            lines.append(f"  Min latency:       {stats['min_latency_ms']:.1f} ms")
            lines.append(f"  Max latency:       {stats['max_latency_ms']:.1f} ms")

        lines.append("  By protocol:")
        for proto, count in sorted(stats.get("by_type", {}).items()):
            lines.append(f"    {proto:<8}: {count}")

        return "\n".join(lines)

    def _colorize(self, text: str) -> str:
        return text if self.color else text

