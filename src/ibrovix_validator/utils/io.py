"""Input/output utilities for reading and writing proxy configs."""

import asyncio
import sys
from pathlib import Path
from typing import Optional


class ConfigReader:
    """Read proxy config lines from files, stdin, or strings."""

    @staticmethod
    def from_file(filepath: str) -> list[str]:
        """Read lines from a file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")
        return path.read_text(encoding="utf-8", errors="replace").splitlines()

    @staticmethod
    def from_stdin() -> list[str]:
        """Read lines from standard input."""
        if sys.stdin.isatty():
            return []
        return [line.rstrip("\n\r") for line in sys.stdin]

    @staticmethod
    def from_text(text: str) -> list[str]:
        """Split a multi-line string into config lines."""
        return text.strip().splitlines()

    @staticmethod
    def from_multiple(paths: list[str]) -> list[str]:
        """Read from multiple files and return combined lines."""
        lines = []
        for path in paths:
            lines.extend(ConfigReader.from_file(path))
        return lines


class ConfigWriter:
    """Write proxy configs to files or stdout."""

    @staticmethod
    def to_file(filepath: str, lines: list[str]) -> None:
        """Write lines to a file."""
        Path(filepath).write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def to_stdout(lines: list[str]) -> None:
        """Write lines to stdout."""
        for line in lines:
            print(line)

    @staticmethod
    def export_valid(configs: list[dict]) -> list[str]:
        """Export valid configs back to their original format (raw lines)."""
        lines = []
        seen = set()
        for cfg in configs:
            raw = cfg.get("raw", "")
            if raw and raw not in seen:
                lines.append(raw)
                seen.add(raw)
        return lines
