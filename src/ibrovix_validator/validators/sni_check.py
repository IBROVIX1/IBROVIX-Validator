"""SNI/Host compatibility validator with deep injection mapping.

Detects misconfigurations where:
  - SNI doesn't match the server certificate
  - Host header doesn't match SNI
  - ServerName/peer field is missing when required
  - "injected bug" mismatches where SNI is set wrong

Deep SNI Injection Mapping:
  When the configured SNI fails, tries alternative SNI candidates to find
  a working combination. This is common with CDN-fronted proxies where
  the backend accepts a specific SNI that differs from the config.
"""

import ssl
import asyncio
import time
from typing import Optional

from .base import BaseValidator
from ..config import ValidatorConfig


class SNIChecker(BaseValidator):
    """Verify SNI/Host header compatibility with the actual server.

    Features:
      - Standard SNI compatibility check
      - Deep SNI injection mapping: tries alternative SNI candidates
      - Working SNI caching: remembers host → working SNI mappings
      - Injected bug detection
      - Wildcard certificate support
    """

    # Persistent cache: host:port -> working_sni
    _SNI_MAPPING_CACHE: dict[str, str] = {}

    # Common SNI candidates to try for injection mapping
    _COMMON_SNI_CANDIDATES = [
        "cloudflare.com",
        "speed.cloudflare.com",
        "www.google.com",
        "google.com",
        "www.youtube.com",
        "youtube.com",
        "microsoft.com",
        "www.microsoft.com",
        "apple.com",
        "www.apple.com",
        "github.com",
        "www.github.com",
    ]

    def __init__(self, config: Optional[ValidatorConfig] = None):
        self.config = config or ValidatorConfig()

    async def validate(self, config: dict) -> dict:
        """Check SNI/host compatibility for a config.

        Returns config with additional fields:
          - sni: str | None — the SNI used
          - sni_compatible: bool — whether SNI matches server cert
          - sni_issues: list[str] — any SNI-related issues found
          - host_mismatch: bool — if host header != SNI
          - injection_mappings: list[dict] — alternative working SNIs found
        """
        result = dict(config)
        issues = []
        host = config.get("host", "")
        port = config.get("port", 0)
        sni = config.get("sni") or config.get("host_header") or host
        tls_mode = config.get("tls", "none")

        result["sni"] = sni
        result["sni_compatible"] = True
        result["host_mismatch"] = False
        result["injection_mappings"] = []

        if tls_mode not in ("tls", "reality", "xtls"):
            result["sni_needed"] = False
            return result

        result["sni_needed"] = True

        if not sni:
            issues.append("TLS enabled but no SNI configured")
            result["sni_compatible"] = False
            result["sni_issues"] = issues
            return result

        # Check if host_header (HTTP Host) differs from SNI
        host_header = config.get("host_header")
        if host_header and host_header != sni:
            result["host_mismatch"] = True
            issues.append(
                f"Host header ('{host_header}') differs from SNI ('{sni}') — "
                "may cause routing issues"
            )

        # Try TLS connection with the configured SNI
        primary_ok = await self._try_tls_with_sni(host, port, sni, result, issues)

        if not primary_ok:
            # Deep SNI injection mapping: try cached mapping first
            cache_key = f"{host}:{port}"
            cached_sni = self._SNI_MAPPING_CACHE.get(cache_key)

            if cached_sni and cached_sni != sni:
                cached_ok = await self._try_tls_with_sni(
                    host, port, cached_sni, result, issues, is_cached=True
                )
                if cached_ok:
                    result["sni"] = cached_sni
                    result["injection_mappings"].append({
                        "original_sni": sni,
                        "injected_sni": cached_sni,
                        "source": "cache",
                        "working": True,
                    })
                else:
                    # Cached mapping no longer valid — clear it
                    self._SNI_MAPPING_CACHE.pop(cache_key, None)

                    # Try the full injection scan
                    await self._injection_scan(host, port, sni, result, issues)

            else:
                # No cache entry — run full injection scan
                await self._injection_scan(host, port, sni, result, issues)

            # Try with host as SNI (detect "injected bug")
            if not result.get("sni_compatible") and sni != host:
                try:
                    ctx_no_sni = ssl.create_default_context()
                    ctx_no_sni.check_hostname = False
                    ctx_no_sni.verify_mode = ssl.CERT_NONE

                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx_no_sni, server_hostname=host),
                        timeout=self.config.tls_timeout
                    )
                    issues.append(
                        f"SNI '{sni}' failed but server accepts hostname '{host}' as SNI — "
                        "possible SNI injection bug in config"
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                except Exception:
                    pass

        result["sni_issues"] = issues
        return result

    async def _try_tls_with_sni(
        self, host: str, port: int, sni: str,
        result: dict, issues: list[str],
        is_cached: bool = False,
    ) -> bool:
        """Try TLS connection with a specific SNI. Returns True if successful."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
                timeout=self.config.tls_timeout
            )

            # Verify the certificate CN/SAN matches our SNI
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                try:
                    cert = ssl_obj.getpeercert()
                    if cert:
                        sans = [san[1] for san in cert.get("subjectAltName", [])]
                        if sans and sni not in sans:
                            wildcard_match = any(
                                self._wildcard_match(sni, san) for san in sans
                            )
                            if not wildcard_match:
                                if is_cached:
                                    issues.append(
                                        f"Cached SNI '{sni}' no longer valid for this server"
                                    )
                                else:
                                    issues.append(
                                        f"SNI '{sni}' not found in server certificate SANs: {sans[:5]}"
                                    )
                                result["sni_compatible"] = False
                                writer.close()
                                try:
                                    await writer.wait_closed()
                                except Exception:
                                    pass
                                return False
                except Exception:
                    pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True

        except ssl.CertificateError as e:
            if not is_cached:
                issues.append(f"SNI '{sni}' rejected by server: {e}")
            result["sni_compatible"] = False
            return False
        except ssl.SSLError as e:
            if not is_cached:
                issues.append(f"SSL error with SNI '{sni}': {e}")
            result["sni_compatible"] = False
            return False
        except Exception as e:
            if not is_cached:
                issues.append(f"Error checking SNI '{sni}': {e}")
            return False

    async def _injection_scan(
        self, host: str, port: int, original_sni: str,
        result: dict, issues: list[str],
    ) -> None:
        """Try alternative SNI candidates to find a working injection mapping.

        Tests the server with common CDN/cloud SNI values and caches any
        working mapping found.
        """
        cache_key = f"{host}:{port}"
        candidates = self._generate_sni_candidates(host, original_sni)

        seen = set()
        for candidate in candidates:
            if candidate == original_sni or candidate in seen:
                continue
            seen.add(candidate)

            test_result = {}
            test_issues = []
            ok = await self._try_tls_with_sni(
                host, port, candidate,
                test_result, test_issues,
                is_cached=False,
            )

            if ok:
                # Found working injection mapping!
                self._SNI_MAPPING_CACHE[cache_key] = candidate
                result["injection_mappings"].append({
                    "original_sni": original_sni,
                    "injected_sni": candidate,
                    "source": "injection_scan",
                    "working": True,
                })
                issues.append(
                    f"Found working SNI injection: '{candidate}' (was '{original_sni}')"
                )
                # Update result
                result["sni"] = candidate
                result["sni_compatible"] = True
                return  # Use first working candidate

        # No working candidate found
        result["sni_compatible"] = False

    def _generate_sni_candidates(self, host: str, configured_sni: str) -> list[str]:
        """Generate alternative SNI candidates for injection testing.

        Strategy:
          1. The host itself (try without SNI)
          2. Common CDN/cloud SNIs
          3. Domain-derived candidates (remove/subdomains)
          4. Cached working SNIs for similar hosts
        """
        seen = set()
        candidates = []

        def _add(candidate: str) -> None:
            if candidate != configured_sni and candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

        # 1. The host itself
        _add(host)

        # 2. Extract domain from host and try variations
        domain = self._extract_domain(host)
        _add(domain)
        _add(f"www.{domain}")

        # 3. Common SNI candidates
        for common in self._COMMON_SNI_CANDIDATES:
            _add(common)

        # 4. Cached mappings for similar hosts (same domain)
        for key, cached_sni in self._SNI_MAPPING_CACHE.items():
            cached_host = key.split(":")[0]
            if cached_host != host and self._extract_domain(cached_host) == domain:
                _add(cached_sni)

        return candidates

    @staticmethod
    def _extract_domain(host: str) -> str:
        """Extract the main domain from a hostname.

        E.g., 'sub.example.com' -> 'example.com'
        """
        parts = host.split(".")
        if len(parts) >= 3:
            # Could be subdomain — try to extract main domain
            # Handle special cases like .co.uk
            if len(parts) >= 4 and parts[-2] in ("co", "com", "org", "net", "gov") and len(parts[-1]) <= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return host

    async def find_injection_mapping(
        self, configs: list[dict]
    ) -> list[dict]:
        """Run deep SNI injection mapping across multiple configs.

        This is a bulk operation that tries to find working SNI values
        for configs whose primary SNI is not compatible.

        Returns configs with injection mapping results populated.
        """
        results = []
        for cfg in configs:
            result = await self.validate(cfg)
            results.append(result)
        return results

    @classmethod
    def get_cached_mappings(cls) -> dict[str, str]:
        """Get all cached SNI mappings (host:port -> working_sni)."""
        return dict(cls._SNI_MAPPING_CACHE)

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the SNI mapping cache."""
        cls._SNI_MAPPING_CACHE.clear()

    @staticmethod
    def _wildcard_match(hostname: str, pattern: str) -> bool:
        """Check if hostname matches a wildcard pattern like *.example.com.

        *.example.com matches sub.example.com (one level of subdomain)
        but NOT deep.sub.example.com (two levels).
        """
        if not pattern.startswith("*."):
            return False
        domain_part = pattern[2:]
        # Must end with ".domain_part" (with leading dot to prevent partial matches)
        # and have exactly one more label than the domain_part
        return hostname.endswith("." + domain_part) and hostname.count(".") == domain_part.count(".") + 1
