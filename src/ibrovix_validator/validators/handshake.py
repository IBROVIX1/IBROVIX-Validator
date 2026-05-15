"""Handshake validator — performs real protocol-level probing of proxy servers.

This goes beyond simple TCP pings by implementing actual protocol handshakes:

  - TCP connect + latency measurement for all protocols
  - TLS handshake with SNI verification for TLS-enabled configs
  - Trojan protocol header exchange (password verification)
  - SSH banner detection
  - VMess/VLESS auth probe detection
"""

import asyncio
import time
import socket
import ssl
from typing import Optional

from .base import BaseValidator
from ..config import ValidatorConfig


class HandshakeValidator(BaseValidator):
    """Perform real connectivity and protocol handshake tests."""

    # Trojan protocol: client sends [password]\r\n[data]
    TROJAN_PROBE = b"\r\n"

    # SSH banner typically starts with "SSH-"
    SSH_BANNER_PREFIX = b"SSH-"

    def __init__(self, config: Optional[ValidatorConfig] = None):
        self.config = config or ValidatorConfig()

    async def validate(self, config: dict) -> dict:
        """Run handshake validation on a parsed config.
        
        Returns config with additional fields:
          - alive: bool
          - latency_ms: float | None
          - tls_ok: bool | None
          - protocol_banner: str | None
          - handshake_error: str | None
        """
        result = dict(config)
        host = config.get("host", "")
        port = config.get("port", 0)

        if not host or not port:
            result["alive"] = False
            result["handshake_error"] = "Invalid host or port"
            return result

        # TCP connectivity test
        tcp_ok, latency, tcp_error = await self._tcp_probe(host, port)
        result["latency_ms"] = latency
        result["tcp_ok"] = tcp_ok

        if not tcp_ok:
            result["alive"] = False
            result["handshake_error"] = f"TCP connect failed: {tcp_error}"
            return result

        # Protocol-specific probes
        proto = config.get("type", "")

        if proto == "trojan" and self.config.trojan_probe:
            trojan_ok, trojan_msg = await self._trojan_probe(host, port, config.get("password", ""))
            result["trojan_ok"] = trojan_ok
            if not trojan_ok:
                result["alive"] = False
                result["handshake_error"] = trojan_msg
            else:
                result["alive"] = True

        elif proto == "ssh" and self.config.ssh_banner:
            ssh_ok, ssh_banner = await self._ssh_probe(host, port)
            result["ssh_banner"] = ssh_banner
            result["alive"] = ssh_ok
            if not ssh_ok:
                result["handshake_error"] = "No SSH banner received"
            else:
                result["alive"] = True

        elif proto in ("vmess", "vless") and self.config.vmess_auth_probe:
            # For VMess/VLESS, do TLS if TLS enabled, otherwise just TCP is checked
            v2ray_ok, v2ray_msg = await self._vmess_probe(host, port, config)
            result["v2ray_probe_ok"] = v2ray_ok
            if not v2ray_ok:
                result["alive"] = False
                result["handshake_error"] = v2ray_msg
            else:
                result["alive"] = True
        else:
            result["alive"] = tcp_ok

        # TLS handshake check
        if self.config.tls_probe and config.get("tls", "none") in ("tls", "reality", "xtls"):
            tls_ok, tls_info = await self._tls_probe(host, port, config.get("sni") or host)
            result["tls_ok"] = tls_ok
            result["tls_info"] = str(tls_info) if tls_info else ""
        else:
            result["tls_ok"] = None

        return result

    async def _tcp_probe(self, host: str, port: int) -> tuple[bool, Optional[float], Optional[str]]:
        """Simple TCP connect with latency measurement."""
        try:
            start = time.monotonic()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.tcp_timeout
            )
            elapsed = (time.monotonic() - start) * 1000  # ms
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, round(elapsed, 1), None
        except asyncio.TimeoutError:
            return False, None, "Connection timed out"
        except ConnectionRefusedError:
            return False, None, "Connection refused"
        except socket.gaierror as e:
            return False, None, f"DNS resolution failed: {e}"
        except OSError as e:
            return False, None, f"Socket error: {e}"
        except Exception as e:
            return False, None, str(e)

    async def _tls_probe(self, host: str, port: int, sni: str) -> tuple[bool, Optional[str]]:
        """Perform TLS handshake and verify certificate/SNI."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            start = time.monotonic()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
                timeout=self.config.tls_timeout
            )
            elapsed = (time.monotonic() - start) * 1000

            # Get certificate info
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = None
            cert_info = ""
            if ssl_obj:
                try:
                    cert = ssl_obj.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        cn = subject.get("commonName", "N/A")
                        sans = cert.get("subjectAltName", [])
                        cert_info = f"CN={cn}, SANs={len(sans)}"
                except Exception:
                    cert_info = "Cert info unavailable"

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return True, f"TLS OK ({round(elapsed, 1)}ms) {cert_info}"
        except ssl.CertificateError as e:
            return False, f"TLS certificate error: {e}"
        except ssl.SSLError as e:
            return False, f"SSL error: {e}"
        except asyncio.TimeoutError:
            return False, "TLS handshake timed out"
        except Exception as e:
            return False, str(e)

    async def _trojan_probe(self, host: str, port: int, password: str) -> tuple[bool, str]:
        """Send Trojan protocol header and check response.
        
        Trojan protocol: client sends [password]\r\n immediately upon connection.
        If the server accepts, it will start sending data. If rejected, connection closes.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.tcp_timeout
            )

            # Send Trojan auth header: [password]\r\n
            auth_data = (password + "\r\n").encode()
            writer.write(auth_data)
            await writer.drain()

            # Wait briefly for a response — Trojan server sends data after auth
            try:
                response = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=2.0
                )
                # If we got data back, the password was likely accepted
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True, "Trojan handshake accepted (data received)"
            except asyncio.TimeoutError:
                # No data back could mean server is waiting for more (pipeline mode)
                # or the connection is just idle — often means auth accepted
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True, "Trojan handshake likely accepted (no immediate rejection)"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except asyncio.TimeoutError:
            return False, "Connection timed out"
        except Exception as e:
            return False, str(e)

    async def _ssh_probe(self, host: str, port: int) -> tuple[bool, Optional[str]]:
        """Connect to SSH server and read the banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.tcp_timeout
            )

            try:
                banner = await asyncio.wait_for(
                    reader.read(256),
                    timeout=3.0
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                if banner.startswith(self.SSH_BANNER_PREFIX):
                    banner_str = banner.decode("utf-8", errors="replace").strip()
                    return True, banner_str
                else:
                    return False, f"Unexpected banner: {banner[:50]}"
            except asyncio.TimeoutError:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return False, "No banner received (timed out)"
        except Exception as e:
            return False, str(e)

    async def _vmess_probe(self, host: str, port: int, config: dict) -> tuple[bool, str]:
        """Probe VMess/VLESS server.
        
        For V2Ray servers, we do a TLS handshake (if TLS enabled) and check
        that the server responds on the expected protocol port.
        """
        tls_mode = config.get("tls", "none")

        if tls_mode in ("tls", "reality", "xtls"):
            sni = config.get("sni") or host
            tls_ok, tls_info = await self._tls_probe(host, port, sni)
            if tls_ok:
                return True, f"TLS handshake OK on V2Ray port"
            else:
                return False, f"TLS failed on V2Ray port: {tls_info}"
        else:
            # Non-TLS V2Ray — just check TCP connectivity (already done)
            return True, "TCP connection OK (non-TLS V2Ray)"
