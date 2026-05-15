"""Tests for IBROVIX-Validator protocol parsers."""

import sys
import os
import json
import base64

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from ibrovix_validator.parsers import parse_line, detect_protocol
from ibrovix_validator.parsers.vmess import VmessParser
from ibrovix_validator.parsers.vless import VlessParser
from ibrovix_validator.parsers.trojan import TrojanParser
from ibrovix_validator.parsers.ssh import SSHParser
from ibrovix_validator.validators.format import FormatValidator
from ibrovix_validator.filters.engine import FilterEngine
from ibrovix_validator.utils.io import ConfigReader, ConfigWriter


# =============================================================================
# VMess Parser Tests
# =============================================================================

def _make_vmess_base64(data: dict) -> str:
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    return f"vmess://{encoded}"


class TestVmessParser:
    def test_standard_vmess(self):
        raw = _make_vmess_base64({
            "v": "2", "ps": "Test Server", "add": "example.com",
            "port": "443", "id": "550e8400-e29b-41d4-a716-446655440000",
            "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": "example.com", "path": "/ws", "tls": "tls", "sni": "example.com"
        })
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "vmess"
        assert result["host"] == "example.com"
        assert result["port"] == 443
        assert result["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["net"] == "ws"
        assert result["tls"] == "tls"
        assert result["path"] == "/ws"

    def test_vmess_missing_host(self):
        raw = _make_vmess_base64({
            "v": "2", "ps": "Broken", "add": "",
            "port": "443", "id": "550e8400-e29b-41d4-a716-446655440000"
        })
        result = parse_line(raw)
        assert result is not None
        assert result["error"] is not None

    def test_vmess_invalid_base64(self):
        result = parse_line("vmess://not-valid-base64!!!")
        assert result is None

    def test_vmess_non_json_base64(self):
        # Valid base64 but not JSON
        result = parse_line("vmess://dGhpc2lzbm90anNvbg==")
        assert result is None


# =============================================================================
# VLESS Parser Tests
# =============================================================================

class TestVlessParser:
    def test_standard_vless(self):
        raw = (
            "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443"
            "?encryption=none&security=tls&type=ws&host=example.com&path=/ws#TestServer"
        )
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "vless"
        assert result["host"] == "example.com"
        assert result["port"] == 443
        assert result["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["tls"] == "tls"
        assert result["net"] == "ws"

    def test_vless_no_fragment(self):
        raw = (
            "vless://550e8400-e29b-41d4-a716-446655440000@server.test.com:2053"
            "?encryption=none&security=none&type=tcp"
        )
        result = parse_line(raw)
        assert result is not None
        assert result["host"] == "server.test.com"
        assert result["port"] == 2053

    def test_vless_ipv6(self):
        raw = (
            "vless://550e8400-e29b-41d4-a716-446655440000@[::1]:443"
            "?encryption=none&security=tls&sni=example.com"
        )
        result = parse_line(raw)
        assert result is not None
        assert result["host"] == "::1"
        assert result["port"] == 443
        assert result["sni"] == "example.com"

    def test_vless_missing_uuid(self):
        raw = "vless://@example.com:443"
        result = parse_line(raw)
        assert result is None or result.get("uuid") == ""


# =============================================================================
# Trojan Parser Tests
# =============================================================================

class TestTrojanParser:
    def test_standard_trojan(self):
        raw = "trojan://mypassword@example.com:443?security=tls&sni=example.com#MyTrojan"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "trojan"
        assert result["host"] == "example.com"
        assert result["port"] == 443
        assert result["password"] == "mypassword"
        assert result["sni"] == "example.com"
        assert result["name"] == "MyTrojan"

    def test_trojan_base64_encoded(self):
        raw_url = "trojan://pass123@server.test.com:8443?security=tls#Test"
        encoded = base64.b64encode(raw_url.encode()).decode()
        result = parse_line(encoded)
        assert result is not None
        assert result["type"] == "trojan"
        assert result["host"] == "server.test.com"
        assert result["port"] == 8443

    def test_trojan_legacy_format(self):
        raw = "mypassword@example.com:443 #MyServer"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "trojan"
        assert result["host"] == "example.com"
        assert result["port"] == 443
        assert result["password"] == "mypassword"

    def test_trojan_missing_password(self):
        raw = "trojan://@example.com:443"
        result = parse_line(raw)
        assert result is not None
        assert result.get("error") is not None or not result.get("password")


# =============================================================================
# SSH Parser Tests
# =============================================================================

class TestSSHParser:
    def test_ssh_url_format(self):
        raw = "ssh://user@example.com:22"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ssh"
        assert result["host"] == "example.com"
        assert result["port"] == 22
        assert result["username"] == "user"

    def test_ssh_url_with_password(self):
        raw = "ssh://user:mypass@example.com:2222"
        result = parse_line(raw)
        assert result is not None
        assert result["username"] == "user"
        assert result["password"] == "mypass"
        assert result["port"] == 2222

    def test_ssh_dropbear_format(self):
        raw = "example.com:22:root:secret123"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ssh"
        assert result["host"] == "example.com"
        assert result["port"] == 22
        assert result["username"] == "root"
        assert result["password"] == "secret123"

    def test_ssh_user_at_host(self):
        raw = "user@example.com:22"
        result = parse_line(raw)
        assert result is not None
        assert result["type"] == "ssh"
        assert result["username"] == "user"
        assert result["host"] == "example.com"
        assert result["port"] == 22

    def test_ssh_base64_encoded(self):
        raw_url = "ssh://admin@vpn.example.com:443"
        encoded = base64.b64encode(raw_url.encode()).decode()
        result = parse_line(encoded)
        assert result is not None
        assert result["type"] == "ssh"
        assert result["host"] == "vpn.example.com"


# =============================================================================
# Parse detection tests
# =============================================================================

class TestDetection:
    def test_detect_vmess(self):
        assert detect_protocol("vmess://abc123") == "vmess"

    def test_detect_vless(self):
        assert detect_protocol("vless://uuid@host:443") == "vless"

    def test_detect_trojan(self):
        assert detect_protocol("trojan://pass@host:443") == "trojan"

    def test_detect_trojan_b64(self):
        data = base64.b64encode(b"trojan://pass@host:443").decode()
        result = parse_line(data)
        assert result is not None
        assert result["type"] == "trojan"

    def test_ignore_comments(self):
        assert parse_line("# this is a comment") is None
        assert parse_line("") is None
        assert parse_line("   ") is None


# =============================================================================
# Format Validator Tests
# =============================================================================

class TestFormatValidator:
    @pytest.mark.asyncio
    async def test_valid_vmess(self):
        validator = FormatValidator()
        config = {
            "type": "vmess", "host": "example.com", "port": 443,
            "uuid": "550e8400-e29b-41d4-a716-446655440000", "net": "ws", "tls": "tls"
        }
        result = await validator.validate(config)
        assert result["format_valid"] is True

    @pytest.mark.asyncio
    async def test_invalid_uuid(self):
        validator = FormatValidator()
        config = {
            "type": "vmess", "host": "example.com", "port": 443,
            "uuid": "not-a-uuid"
        }
        result = await validator.validate(config)
        assert result["format_valid"] is False

    @pytest.mark.asyncio
    async def test_invalid_port(self):
        validator = FormatValidator()
        config = {
            "type": "vmess", "host": "example.com", "port": 99999,
            "uuid": "550e8400-e29b-41d4-a716-446655440000"
        }
        result = await validator.validate(config)
        assert result["format_valid"] is False


# =============================================================================
# Filter Engine Tests
# =============================================================================

class TestFilterEngine:
    def test_filter_by_protocol(self):
        configs = [
            {"type": "vmess", "name": "A"},
            {"type": "vless", "name": "B"},
            {"type": "trojan", "name": "C"},
        ]
        engine = FilterEngine(configs)
        filtered = engine.by_protocol("vmess", "trojan").apply()
        assert len(filtered) == 2
        assert all(c["type"] in ("vmess", "trojan") for c in filtered)

    def test_filter_alive(self):
        configs = [
            {"alive": True, "latency_ms": 50},
            {"alive": False, "latency_ms": None},
            {"alive": True, "latency_ms": 120},
        ]
        engine = FilterEngine(configs)
        filtered = engine.alive(True).apply()
        assert len(filtered) == 2

    def test_filter_latency(self):
        configs = [
            {"latency_ms": 50},
            {"latency_ms": 200},
            {"latency_ms": 500},
        ]
        engine = FilterEngine(configs)
        filtered = engine.max_latency(200).apply()
        assert len(filtered) == 2

    def test_filter_chain(self):
        configs = [
            {"type": "vmess", "alive": True, "latency_ms": 50, "net": "ws"},
            {"type": "vless", "alive": True, "latency_ms": 200, "net": "tcp"},
            {"type": "trojan", "alive": False, "latency_ms": None, "net": "tcp"},
        ]
        engine = FilterEngine(configs)
        filtered = engine.by_protocol("vmess", "vless").alive(True).max_latency(100).apply()
        assert len(filtered) == 1
        assert filtered[0]["type"] == "vmess"

    def test_stats(self):
        configs = [
            {"type": "vmess", "alive": True, "latency_ms": 50},
            {"type": "vless", "alive": False, "latency_ms": None},
            {"type": "trojan", "alive": True, "latency_ms": 100},
        ]
        engine = FilterEngine(configs)
        stats = engine.stats()
        assert stats["total"] == 3
        assert stats["alive"] == 2
        assert stats["dead"] == 1
        assert stats["by_type"]["vmess"] == 1
        assert stats["avg_latency_ms"] == 75.0
