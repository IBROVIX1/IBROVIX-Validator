"""Tests for IBROVIX-Validator harvester module and Shadowsocks parser."""

import sys
import os
import json
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from ibrovix_validator.parsers import parse_line, detect_protocol
from ibrovix_validator.harvester import ConfigHarvester, HarvestResult


# =============================================================================
# Shadowsocks (SS) Parser Tests
# =============================================================================

class TestShadowsocksParser:
    """Test parsing Shadowsocks ss:// URIs."""

    def test_ss_standard(self):
        """Standard ss://BASE64(method:password)@host:port format."""
        # ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:443
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:password123").decode().rstrip("=")
        raw = f"ss://{userinfo}@example.com:443#MyServer"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ss"
        assert result["host"] == "example.com"
        assert result["port"] == 443
        assert result["method"] == "aes-256-gcm"
        assert result["password"] == "password123"
        assert result["name"] == "MyServer"

    def test_ss_padded_b64(self):
        """SS URI with standard padded base64."""
        userinfo = base64.b64encode(b"chacha20-ietf-poly1305:secretkey").decode()
        raw = f"ss://{userinfo}@server.test.com:8443#Test"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ss"
        assert result["host"] == "server.test.com"
        assert result["port"] == 8443
        assert result["method"] == "chacha20-ietf-poly1305"
        assert result["password"] == "secretkey"

    def test_ss_sip002_with_plugin(self):
        """SIP002 format with plugin parameter."""
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:testpass").decode().rstrip("=")
        raw = f"ss://{userinfo}@vpn.example.com:443/?plugin=v2ray-plugin%3Bpath%3D%2Fws#VPN"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ss"
        assert result["host"] == "vpn.example.com"
        assert result["port"] == 443
        assert result["plugin"] != ""
        assert "v2ray-plugin" in result["plugin"]

    def test_ss_no_fragment(self):
        """SS URI without #fragment."""
        userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:mypass").decode().rstrip("=")
        raw = f"ss://{userinfo}@server.io:2053"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ss"
        assert result["host"] == "server.io"
        assert result["port"] == 2053
        assert result["name"] == ""

    def test_ss_ipv6_host(self):
        """SS URI with IPv6 address."""
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:pass123").decode().rstrip("=")
        raw = f"ss://{userinfo}@[::1]:443#IPv6Test"
        result = parse_line(raw)
        assert result is not None
        assert result["host"] == "::1"
        assert result["port"] == 443

    def test_ss_nested_b64(self):
        """SS URI where the entire thing is base64-encoded."""
        inner = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:443"
        encoded = base64.b64encode(inner.encode()).decode()
        raw = f"ss://{encoded}"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ss"
        assert result["host"] == "example.com"

    def test_ss_invalid_cipher(self):
        """SS URI with unknown encryption method."""
        userinfo = base64.urlsafe_b64encode(b"unknown-cipher:pass").decode().rstrip("=")
        raw = f"ss://{userinfo}@example.com:443"
        result = parse_line(raw)
        assert result is not None
        assert result.get("error") is not None
        assert "unknown" in result["error"].lower()

    def test_ss_missing_host(self):
        """SS URI with missing host."""
        raw = "ss://YWVzLTI1Ni1nY206cGFzcw==@:0"
        result = parse_line(raw)
        assert result is not None
        assert result.get("error") is not None

    def test_detect_ss_protocol(self):
        """detect_protocol should identify ss:// links."""
        assert detect_protocol("ss://abc123") == "ss"

    def test_ss_not_ssh(self):
        """SS URI should not be confused with SSH."""
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:password").decode().rstrip("=")
        raw = f"ss://{userinfo}@root@host.com:22"  # @ in password portion
        result = parse_line(raw)
        # Should still parse as SS, not SSH
        assert result is not None
        assert result["type"] == "ss"


# =============================================================================
# Harvester Tests
# =============================================================================

class TestConfigHarvester:
    """Test the ConfigHarvester class."""

    def test_default_sources_list(self):
        """Default sources should be a non-empty list of URLs."""
        harvester = ConfigHarvester()
        sources = harvester.get_default_sources()
        assert len(sources) > 0
        assert all(s.startswith("http") for s in sources)

    def test_decode_plain_text(self):
        """Decode plain text config lines."""
        harvester = ConfigHarvester()
        content = (
            "vmess://eyJhZGQiOiAiZXhhbXBsZS5jb20iLCAicG9ydCI6IDQ0MywgImlkIjogIjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCIsICJwcyI6ICJUZXN0In0=\n"
            "trojan://password@example.com:443\n"
            "# this is a comment\n"
            "\n"
        )
        lines = harvester._decode_content(content)
        assert len(lines) == 2
        assert any("vmess://" in l for l in lines)
        assert any("trojan://" in l for l in lines)

    def test_decode_base64_body(self):
        """Decode content that is entirely base64 encoded."""
        harvester = ConfigHarvester()
        original = "vmess://eyJhZGQiOiAiZXhhbXBsZS5jb20ifQ==\ntrojan://pass@host.com:443"
        encoded = base64.b64encode(original.encode()).decode()
        lines = harvester._decode_content(encoded)
        assert len(lines) == 2
        assert any("vmess://" in l for l in lines)

    def test_decode_single_b64_line(self):
        """Decode a single line that is base64."""
        harvester = ConfigHarvester()
        line = base64.b64encode(b"vmess://eyJhZGQiOiAidGVzdC5jb20ifQ==").decode()
        lines = harvester._decode_content(line)
        assert len(lines) > 0
        assert any("vmess://" in l for l in lines)

    def test_decode_non_b64_content(self):
        """Regular plain text should pass through unchanged."""
        harvester = ConfigHarvester()
        content = "vmess://someconfig\ntrojan://otherconfig\nss://thirdconfig"
        lines = harvester._decode_content(content)
        assert len(lines) == 3

    def test_decode_empty_content(self):
        """Empty content should return empty list."""
        harvester = ConfigHarvester()
        assert harvester._decode_content("") == []
        assert harvester._decode_content("   ") == []

    def test_decode_nested_b64(self):
        """Double base64-encoded content should be decoded twice."""
        harvester = ConfigHarvester()
        inner = "vmess://eyJhZGQiOiAiZXhhbXBsZS5jb20ifQ=="
        outer = base64.b64encode(inner.encode()).decode()
        lines = harvester._decode_content(outer)
        assert len(lines) >= 1
        assert any("vmess://" in l for l in lines)

    def test_exclude_ssh_by_default(self):
        """Harvester should exclude SSH configs by default."""
        harvester = ConfigHarvester()
        # SSH should not be in the by_protocol list when harvested
        # We can check the protocol filter by simulating
        assert harvester.exclude_ssh is True

    def test_urlsafe_b64_decode(self):
        """Test URL-safe base64 decoding with SIP002 format."""
        harvester = ConfigHarvester()
        # URL-safe base64 uses - instead of + and _ instead of /
        urlsafe_b64 = base64.urlsafe_b64encode(b"vmess://test").decode().rstrip("=")
        lines = harvester._decode_content(urlsafe_b64)
        assert len(lines) >= 1

    def test_harvest_result_dataclass(self):
        """HarvestResult should initialize with default values."""
        result = HarvestResult()
        assert result.total_sources == 0
        assert result.successful_sources == 0
        assert result.failed_sources == []
        assert result.total_raw_lines == 0
        assert result.total_parsed == 0
        assert result.unique_configs == []
        assert result.duplicates_removed == 0
        assert result.by_protocol == {}
        assert result.total_unique == 0  # property


# =============================================================================
# Harvester + Parser Integration Tests
# =============================================================================

class TestHarvesterParserIntegration:
    """Test end-to-end harvester + parser integration."""

    def test_parsed_configs_have_expected_fields(self):
        """Configs returned by harvester should have standard fields."""
        # We'll simulate the harvest flow by creating configs manually
        # that match what the harvester would produce
        configs = []
        for line in self._make_test_lines():
            cfg = parse_line(line)
            if cfg is not None:
                configs.append(cfg)

        assert len(configs) > 0
        for cfg in configs:
            assert "type" in cfg
            assert "host" in cfg
            assert "port" in cfg
            assert "raw" in cfg
            assert cfg["type"] in ("vmess", "vless", "trojan", "ss")

    def test_protocol_distribution(self):
        """Parsed configs should include multiple protocols."""
        configs = []
        for line in self._make_test_lines():
            cfg = parse_line(line)
            if cfg is not None:
                configs.append(cfg)

        types = set(c["type"] for c in configs)
        assert len(types) >= 3  # Should have at least 3 protocols

    def test_ssh_excluded_by_default(self):
        """SSH configs should not appear in harvester output."""
        lines = self._make_test_lines()
        # Check that none of the test lines are SSH
        for line in lines:
            if parse_line(line):
                assert parse_line(line)["type"] != "ssh"

    @staticmethod
    def _make_test_lines() -> list[str]:
        """Generate test config lines mimicking harvested data."""
        vmess_raw = base64.b64encode(json.dumps({
            "v": "2", "ps": "TestVMess",
            "add": "vmess.server.com", "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "aid": "0", "scy": "auto", "net": "ws",
            "tls": "tls", "sni": "vmess.server.com",
            "path": "/ws",
        }).encode()).decode()
        vless_raw = "vless://550e8400-e29b-41d4-a716-446655440000@vless.server.com:443?encryption=none&security=tls&type=ws#VlessTest"
        trojan_raw = "trojan://mypassword@trojan.server.com:443?sni=trojan.server.com#TrojanTest"

        ss_userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:sspassword").decode().rstrip("=")
        ss_raw = f"ss://{ss_userinfo}@ss.server.com:8443#SSTest"

        return [
            f"vmess://{vmess_raw}",
            vless_raw,
            trojan_raw,
            ss_raw,
        ]
