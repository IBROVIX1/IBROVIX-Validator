"""SNI/Host compatibility validator.

Detects misconfigurations where:
  - SNI doesn't match the server certificate
  - Host header doesn't match SNI
  - ServerName/peer field is missing when required
  - "injected bug" mismatches where SNI is set wrong
"""

import ssl
import asyncio
import time
from typing import Optional

from .base import BaseValidator
from ..config import ValidatorConfig


class SNIChecker(BaseValidator):
    """Verify SNI/Host header compatibility with the actual server."""

    def __init__(self, config: Optional[ValidatorConfig] = None):
        self.config = config or ValidatorConfig()

    async def validate(self, config: dict) -> dict:
        """Check SNI/host compatibility for a config.
        
        Returns config with additional fields:
          - sni: str | None — the SNI used
          - sni_compatible: bool — whether SNI matches server cert
          - sni_issues: list[str] — any SNI-related issues found
          - host_mismatch: bool — if host header != SNI
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
                        # Check subjectAltName for our SNI
                        sans = [san[1] for san in cert.get("subjectAltName", [])]
                        if sans and sni not in sans:
                            # Check wildcard
                            wildcard_match = any(
                                self._wildcard_match(sni, san) for san in sans
                            )
                            if not wildcard_match:
                                issues.append(
                                    f"SNI '{sni}' not found in server certificate SANs: {sans[:5]}"
                                )
                                result["sni_compatible"] = False
                except Exception:
                    pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except ssl.CertificateError as e:
            issues.append(f"SNI '{sni}' rejected by server: {e}")
            result["sni_compatible"] = False
        except ssl.SSLError as e:
            issues.append(f"SSL error with SNI '{sni}': {e}")
            result["sni_compatible"] = False
        except Exception as e:
            issues.append(f"Error checking SNI '{sni}': {e}")

        # Try without SNI (or with host as SNI) to detect "injected bug"
        # where the config SNI doesn't match but the server works with host
        if not result["sni_compatible"] and sni != host:
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

    @staticmethod
    def _wildcard_match(hostname: str, pattern: str) -> bool:
        """Check if hostname matches a wildcard pattern like *.example.com."""
        if not pattern.startswith("*."):
            return False
        domain_part = pattern[2:]  # remove "*."
        return hostname.endswith(domain_part) and hostname.count(".") == domain_part.count(".")
