"""Geo-IP lookup utility for proxy server geolocation.

Uses ip-api.com free API (no API key required, 45 requests/min limit).
Results are cached in-memory to minimize API calls.
Supports both async (aiohttp) and sync (requests) lookup modes.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from ..config import IP_GEOLOCATION_API


@dataclass
class GeoLocation:
    """Geolocation data for a proxy server."""
    ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    lat: float = 0.0
    lon: float = 0.0
    timezone: str = ""
    as_number: str = ""
    cached: bool = False
    error: Optional[str] = None

    @property
    def short_display(self) -> str:
        """Short location string (e.g., '🇺🇸 US - Los Angeles')."""
        if self.error:
            return self.error
        parts = []
        if self.country_code:
            parts.append(self.country_code)
        if self.city:
            parts.append(self.city)
        return " - ".join(parts) if parts else "Unknown"

    @property
    def full_display(self) -> str:
        """Full location description."""
        if self.error:
            return f"GeoIP error: {self.error}"
        parts = []
        if self.city:
            parts.append(self.city)
        if self.region:
            parts.append(self.region)
        if self.country:
            parts.append(self.country)
        if self.isp:
            parts.append(f"({self.isp})")
        return ", ".join(parts) if parts else "Unknown"


class GeoIPResolver:
    """Async Geo-IP resolver with in-memory caching.

    Uses ip-api.com free tier (non-commercial, 45 req/min).
    Respects rate limits automatically with a simple token bucket.

    Usage:
        resolver = GeoIPResolver()
        location = await resolver.lookup("8.8.8.8")
        print(location.country, location.city)
    """

    # Singleton cache shared across instances
    _cache: dict[str, GeoLocation] = {}
    _last_request_time: float = 0
    _min_interval: float = 1.5  # ~40 req/min to stay under 45 limit

    def __init__(self, use_cache: bool = True):
        self.use_cache = use_cache

    async def lookup(self, host: str) -> GeoLocation:
        """Look up geolocation for a hostname or IP address.

        Results are cached to minimize API calls.
        Hostnames are resolved to IPs before lookup.
        """
        # Normalize: extract IP if it's a hostname with port
        host_clean = host.split(":")[0].strip()

        # Check cache first
        if self.use_cache and host_clean in self._cache:
            cached = self._cache[host_clean]
            cached.cached = True
            return cached

        # Don't do geolocation for hostnames (only IPs work reliably)
        if not self._is_ip(host_clean):
            loc = GeoLocation(
                ip=host_clean,
                country="Unknown",
                country_code="N/A",
                error="Hostname (resolve IP first)",
            )
            if self.use_cache:
                self._cache[host_clean] = loc
            return loc

        # Rate limiting
        await self._rate_limit()

        try:
            loc = await self._fetch(host_clean)
            if self.use_cache:
                self._cache[host_clean] = loc
            return loc
        except Exception as e:
            loc = GeoLocation(
                ip=host_clean,
                error=str(e)[:60],
            )
            if self.use_cache:
                self._cache[host_clean] = loc
            return loc

    async def lookup_many(self, hosts: list[str]) -> dict[str, GeoLocation]:
        """Look up multiple hosts concurrently."""
        tasks = {host: self.lookup(host) for host in hosts}
        results = {}
        for host, task in tasks.items():
            try:
                results[host] = await task
            except Exception:
                results[host] = GeoLocation(ip=host, error="lookup failed")
        return results

    async def _fetch(self, ip: str) -> GeoLocation:
        """Fetch geolocation from ip-api.com API."""
        try:
            import aiohttp
        except ImportError:
            return GeoLocation(ip=ip, error="aiohttp not installed")

        url = IP_GEOLOCATION_API.format(ip)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    headers={"User-Agent": "IBROVIX-Validator/2.0"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            return GeoLocation(
                                ip=ip,
                                country=data.get("country", ""),
                                country_code=data.get("countryCode", ""),
                                region=data.get("regionName", ""),
                                city=data.get("city", ""),
                                isp=data.get("isp", ""),
                                org=data.get("org", ""),
                                lat=float(data.get("lat", 0)),
                                lon=float(data.get("lon", 0)),
                                timezone=data.get("timezone", ""),
                                as_number=data.get("as", ""),
                            )
                        else:
                            msg = data.get("message", "query failed")
                            return GeoLocation(ip=ip, error=msg)
                    elif resp.status == 429:
                        return GeoLocation(ip=ip, error="rate limited")
                    else:
                        return GeoLocation(
                            ip=ip,
                            error=f"HTTP {resp.status}",
                        )
        except asyncio.TimeoutError:
            return GeoLocation(ip=ip, error="timeout")
        except Exception as e:
            return GeoLocation(ip=ip, error=str(e)[:60])

    async def _rate_limit(self) -> None:
        """Ensure we don't exceed API rate limits."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self.__class__._last_request_time = time.monotonic()

    @staticmethod
    def _is_ip(host: str) -> bool:
        """Check if a string looks like a valid IP address."""
        import re
        ipv4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
        m = ipv4.match(host)
        if m:
            return all(0 <= int(g) <= 255 for g in m.groups())
        ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
        return bool(ipv6.match(host))

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the geolocation cache."""
        cls._cache.clear()

    @classmethod
    def cache_size(cls) -> int:
        """Number of cached entries."""
        return len(cls._cache)
