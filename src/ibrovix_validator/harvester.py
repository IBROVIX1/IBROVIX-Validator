"""Automated Live Proxy Harvester — fetches V2Ray/Shadowsocks configs from
public raw repositories and subscription links asynchronously, then feeds them
into the existing validation pipeline.

Protocols supported: VMess, VLESS, Trojan, Shadowsocks (SS)
Protocols excluded: SSH (to keep high-performance for V2Ray ecosystem)

Features:
  - Async HTTP fetching with httpx
  - Base64 subscription decoding (standard and URL-safe)
  - Plain text config file parsing
  - Deduplication by raw config line content
  - Built-in default sources (well-known public GitHub repos)
  - Custom user-provided URLs
  - Progress reporting
  - Configurable concurrency and timeouts
"""

import asyncio
import base64
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

import httpx

from .parsers import parse_line, detect_protocol


# ---------------------------------------------------------------------------
# Default public sources: well-known GitHub repos and subscription aggregators
# that regularly publish free V2Ray/Shadowsocks proxy configurations.
#
# These are raw.githubusercontent.com URLs pointing to known config files.
# Users can override or extend these via CLI flags or environment variables.
# ---------------------------------------------------------------------------
DEFAULT_SOURCES: list[str] = [
    # freefq/free — well-known V2Ray config aggregator (high update frequency)
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    # mahdibland aggregators — V2Ray + Shadowsocks (daily updates)
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_auto.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_auto_base64.txt",
    # Pawdroid Free-servers — multi-protocol (frequent updates)
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    # ermaozi get_subscribe — active V2Ray config collector
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    # ssrsub — multi-protocol configurations
    "https://raw.githubusercontent.com/ssrsub/ssr/master/v2ray",
    # Leon406 SubCrawler — large config aggregator (daily updates)
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/base64.txt",
    # vpei Free-Node-Merge — merged from multiple channels
    "https://raw.githubusercontent.com/vpei/Free-Node-Merge/main/out/v2ray_sub",
    # aiboboxx v2ray-free — active fork with frequent updates
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2ray",
    # mianzzp free-proxy — updated regularly
    "https://raw.githubusercontent.com/mianzzp/free-proxy/main/v2ray",
    # fainsh/FreeNodes — high update frequency
    "https://raw.githubusercontent.com/fainsh/FreeNodes/main/v2ray",
    # v2ray-links — popular config source
    "https://raw.githubusercontent.com/v2ray-links/v2ray-links/master/v2ray",
    # xrayfree — Xray/V2Ray config aggregator
    "https://raw.githubusercontent.com/xrayfree/free-ssr-ss-v2ray-vpn-clash/main/v2ray",
    # clashnode — multi-format proxy source
    "https://raw.githubusercontent.com/clashnode/ClashNode/main/v2ray",
    # Xray-configs — community-maintained config repo
    "https://raw.githubusercontent.com/Xray-configs/Xray-configs/main/v2ray.txt",
]

# Environment variable override for custom sources
ENV_SOURCES_VAR = "IBROVIX_SOURCES"


@dataclass
class HarvestResult:
    """Results from a harvesting operation."""

    total_sources: int = 0
    successful_sources: int = 0
    failed_sources: list[tuple[str, str]] = field(default_factory=list)
    total_raw_lines: int = 0
    total_parsed: int = 0
    unique_configs: list[dict] = field(default_factory=list)
    duplicates_removed: int = 0
    by_protocol: dict[str, int] = field(default_factory=dict)

    @property
    def total_unique(self) -> int:
        return len(self.unique_configs)


class ConfigHarvester:
    """Async harvester for proxy configs from public sources.

    Fetches, decodes, deduplicates, and parses proxy config lines from
    subscription URLs and raw config repositories.

    Usage:
        harvester = ConfigHarvester()
        result = await harvester.harvest(sources=["https://..."])
        for config in result.unique_configs:
            print(config)
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_concurrent: int = 10,
        max_retries: int = 2,
        progress: bool = True,
        exclude_ssh: bool = True,
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.progress = progress
        self.exclude_ssh = exclude_ssh
        self._seen_raw: set[str] = set()

    def get_default_sources(self) -> list[str]:
        """Return the default sources, optionally overridden by env var."""
        import os
        env_sources = os.environ.get(ENV_SOURCES_VAR)
        if env_sources:
            return [s.strip() for s in env_sources.split(",") if s.strip()]
        return list(DEFAULT_SOURCES)

    async def harvest(
        self,
        sources: Optional[list[str]] = None,
        use_defaults: bool = False,
        protocols: Optional[list[str]] = None,
    ) -> HarvestResult:
        """Fetch configs from the given sources and parse them.

        Args:
            sources: Custom source URLs to fetch from.
            use_defaults: Also include built-in default sources.
            protocols: Only keep configs matching these protocol types.
                       If None, all protocols are kept (except SSH by default).

        Returns:
            HarvestResult with unique parsed configs.
        """
        all_sources: list[str] = []
        if sources:
            all_sources.extend(sources)
        if use_defaults:
            all_sources.extend(self.get_default_sources())

        # Deduplicate sources
        all_sources = list(dict.fromkeys(all_sources))

        if not all_sources:
            return HarvestResult()

        result = HarvestResult(total_sources=len(all_sources))

        # Fetch all sources concurrently
        sem = asyncio.Semaphore(self.max_concurrent)
        tracker = {"succeeded": 0, "failed": []}

        async def _fetch_one(url: str) -> tuple[list[str], bool, str]:
            async with sem:
                lines, ok = await self._fetch_with_retry(url)
                return lines, ok, url

        tasks = [_fetch_one(url) for url in all_sources]
        fetched_lines: list[str] = []

        # Process results as they complete for progress reporting
        for coro in asyncio.as_completed(tasks):
            try:
                lines, ok, url = await coro
                if ok:
                    tracker["succeeded"] += 1
                else:
                    tracker["failed"].append((url, "fetch failed"))
                fetched_lines.extend(lines)
            except Exception as e:
                # Should not happen since errors are handled inside _fetch_with_retry
                pass

        result.successful_sources = tracker["succeeded"]
        result.failed_sources = tracker["failed"]

        if not fetched_lines:
            return result

        result.total_raw_lines = len(fetched_lines)

        # Deduplicate raw config lines
        self._seen_raw.clear()

        unique_lines: list[str] = []
        actual_duplicates = 0
        for line in fetched_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped in self._seen_raw:
                actual_duplicates += 1
                continue
            self._seen_raw.add(stripped)
            unique_lines.append(stripped)
        result.duplicates_removed = actual_duplicates

        # Parse each unique line into a config dict
        parsed_configs = []
        for line in unique_lines:
            cfg = parse_line(line)
            if cfg is not None:
                proto = cfg.get("type", "")
                # Exclude SSH if configured
                if self.exclude_ssh and proto == "ssh":
                    continue
                # Filter by requested protocols
                if protocols and proto not in protocols:
                    continue
                parsed_configs.append(cfg)
                result.by_protocol[proto] = result.by_protocol.get(proto, 0) + 1

        result.total_parsed = len(parsed_configs)
        result.unique_configs = parsed_configs

        return result

    async def _fetch_with_retry(self, url: str) -> tuple[list[str], bool]:
        """Fetch a single URL with retry logic. Returns (lines, success).

        Returns:
            Tuple of (list of raw config lines, whether the fetch succeeded).
        """
        last_error = ""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/plain, */*",
        }

        for attempt in range(1 + self.max_retries):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    limits=httpx.Limits(max_connections=self.max_concurrent),
                ) as client:
                    response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    content = response.text
                    # Try to decode as base64 first
                    decoded_lines = self._decode_content(content)
                    if self.progress:
                        print(
                            f"  [OK] {url} — {len(decoded_lines)} lines",
                            file=sys.stderr,
                        )
                    return decoded_lines, True
                elif response.status_code == 404:
                    if self.progress:
                        print(f"  [404] {url} — not found", file=sys.stderr)
                    return [], False
                else:
                    last_error = f"HTTP {response.status_code}"
                    if attempt < self.max_retries:
                        await asyncio.sleep(1 * (attempt + 1))
                        continue
                    if self.progress:
                        print(
                            f"  [FAIL] {url} — {last_error}",
                            file=sys.stderr,
                        )
                    return [], False

            except httpx.TimeoutException:
                last_error = "timeout"
                if attempt < self.max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
            except httpx.ConnectError:
                last_error = "connection failed"
                if attempt < self.max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
            except Exception as e:
                last_error = str(e)[:80]
                if attempt < self.max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue

        if self.progress:
            print(f"  [FAIL] {url} — {last_error}", file=sys.stderr)
        return [], False

    def _decode_content(self, content: str) -> list[str]:
        """Decode content from a source URL into individual config lines.

        Handles:
          - Plain text: one config per line
          - Base64-encoded: full body or per-line
          - Base64 with newlines (multi-line)
          - Mixed: base64 blocks mixed with plain text
        """
        content = content.strip()
        if not content:
            return []

        lines: list[str] = []

        # Strategy 1: Try to decode the entire content as base64
        b64_lines = self._try_decode_as_base64(content)
        if b64_lines is not None:
            return b64_lines

        # Strategy 2: Content might be a mix of base64 and plain text lines
        # Process line by line
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check if this individual line is base64
            b64_line = self._try_decode_as_base64(line)
            if b64_line is not None:
                lines.extend(b64_line)
            else:
                lines.append(line)

        return lines

    def _try_decode_as_base64(self, text: str) -> Optional[list[str]]:
        """Try to decode text as base64. Returns list of lines or None if not valid base64.

        Handles:
          - Standard base64 with padding
          - URL-safe base64
          - Unpadded base64
          - Multi-line base64 blocks
        """
        if not text:
            return None

        # Clean the text — remove whitespace that might be in base64
        cleaned = text.strip()

        # Remove newlines and spaces for base64 detection
        flat = re.sub(r"\s+", "", cleaned)

        # Quick check: base64 strings typically have even length and
        # contain only base64 chars
        if len(flat) < 4:
            return None

        # Base64 detection: should mostly contain A-Z, a-z, 0-9, +, /, =
        # URL-safe: uses - instead of +, _ instead of /
        b64_chars = sum(1 for c in flat if c.isalnum() or c in "+/=_-")
        if b64_chars < len(flat) * 0.85:
            return None

        # Try URL-safe first, then standard
        for variant in ["urlsafe", "standard"]:
            try:
                padded = flat
                missing_padding = len(padded) % 4
                if missing_padding:
                    padding_needed = 4 - missing_padding
                    # Don't add padding if it would make it obviously wrong
                    if padding_needed == 3:
                        continue
                    padded += "=" * padding_needed

                if variant == "urlsafe":
                    decoded_bytes = base64.urlsafe_b64decode(padded)
                else:
                    decoded_bytes = base64.b64decode(padded)

                decoded = decoded_bytes.decode("utf-8", errors="replace")

                # Validate: decoded content should have printable chars
                # and look like config data (contains : or @ or /)
                if not decoded.strip():
                    continue

                # Check if it looks like proxy config data
                has_proxy_chars = any(c in decoded for c in ["://", "@", ":", "."])
                if not has_proxy_chars and len(decoded) > 20:
                    # Could be a base64 of base64 (double encoded)
                    nested = self._try_decode_as_base64(decoded.strip())
                    if nested is not None:
                        return nested
                    continue

                # Split into lines and filter
                decoded_lines = [
                    l.strip()
                    for l in decoded.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]

                # Further decode any nested base64 lines
                final_lines = []
                for dl in decoded_lines:
                    nested = self._try_decode_as_base64(dl)
                    if nested is not None:
                        final_lines.extend(nested)
                    else:
                        final_lines.append(dl)

                if final_lines:
                    return final_lines
                elif decoded.strip():
                    return [decoded.strip()]

            except (ValueError, Exception):
                continue

        return None

    @staticmethod
    def format_result_summary(result: HarvestResult) -> str:
        """Format a human-readable summary of harvest results."""
        lines = []
        lines.append(f"  Sources:      {result.successful_sources}/{result.total_sources} succeeded")
        if result.failed_sources:
            lines.append(f"  Failed:       {len(result.failed_sources)} source(s)")
        lines.append(f"  Raw lines:    {result.total_raw_lines} total")
        lines.append(f"  Duplicates:   {result.duplicates_removed} removed")
        lines.append(f"  Parsed:       {result.total_parsed} configs")
        if result.by_protocol:
            parts = ", ".join(f"{k}: {v}" for k, v in sorted(result.by_protocol.items()))
            lines.append(f"  By protocol:  {parts}")
        return "\n".join(lines)
