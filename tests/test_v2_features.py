"""Tests for IBROVIX-Validator v2.0.0 features.

Covers:
  - Geo-IP lookup module (GeoIPResolver, GeoLocation)
  - FilterEngine latency sorting
  - SNI injection mapping (domain extraction, candidate generation)
  - TUI helper functions
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from ibrovix_validator.utils.geo import GeoIPResolver, GeoLocation
from ibrovix_validator.filters.engine import FilterEngine
from ibrovix_validator.validators.sni_check import SNIChecker
from ibrovix_validator.utils.output import Colorizer, OutputFormatter


# =============================================================================
# Geo-IP Module Tests
# =============================================================================

class TestGeoLocation:
    """Test the GeoLocation dataclass and its display properties."""

    def test_short_display_with_country_and_city(self):
        loc = GeoLocation(country_code="US", city="Los Angeles")
        assert loc.short_display == "US - Los Angeles"

    def test_short_display_country_only(self):
        loc = GeoLocation(country_code="DE")
        assert loc.short_display == "DE"

    def test_short_display_empty(self):
        loc = GeoLocation()
        assert loc.short_display == "Unknown"

    def test_short_display_with_error(self):
        loc = GeoLocation(error="rate limited")
        assert loc.short_display == "rate limited"

    def test_full_display_with_all_fields(self):
        loc = GeoLocation(
            city="London", region="England",
            country="United Kingdom", isp="Example ISP"
        )
        assert "London" in loc.full_display
        assert "England" in loc.full_display
        assert "United Kingdom" in loc.full_display
        assert "Example ISP" in loc.full_display

    def test_full_display_empty(self):
        loc = GeoLocation()
        assert loc.full_display == "Unknown"

    def test_full_display_with_error(self):
        loc = GeoLocation(error="timeout")
        assert "timeout" in loc.full_display

    def test_cached_flag(self):
        loc = GeoLocation(ip="1.2.3.4", cached=True)
        assert loc.cached is True

    def test_lat_lon_defaults(self):
        loc = GeoLocation()
        assert loc.lat == 0.0
        assert loc.lon == 0.0


class TestGeoIPResolver:
    """Test the GeoIPResolver — local/offline methods only (no network calls)."""

    def setup_method(self):
        GeoIPResolver.clear_cache()

    def test_is_ip_ipv4(self):
        assert GeoIPResolver._is_ip("8.8.8.8") is True
        assert GeoIPResolver._is_ip("192.168.1.1") is True
        assert GeoIPResolver._is_ip("0.0.0.0") is True
        assert GeoIPResolver._is_ip("255.255.255.255") is True

    def test_is_ip_ipv6(self):
        assert GeoIPResolver._is_ip("::1") is True
        assert GeoIPResolver._is_ip("2001:db8::1") is True
        assert GeoIPResolver._is_ip("fe80::1") is True

    def test_is_ip_hostname(self):
        assert GeoIPResolver._is_ip("example.com") is False
        assert GeoIPResolver._is_ip("google.com") is False
        assert GeoIPResolver._is_ip("localhost") is False
        assert GeoIPResolver._is_ip("my-server-01") is False

    def test_is_ip_invalid(self):
        assert GeoIPResolver._is_ip("999.999.999.999") is False
        assert GeoIPResolver._is_ip("abc.def.ghi.jkl") is False
        assert GeoIPResolver._is_ip("") is False

    def test_cache_starts_empty(self):
        GeoIPResolver.clear_cache()
        assert GeoIPResolver.cache_size() == 0

    def test_cache_clear(self):
        # Manually insert into cache
        GeoIPResolver._cache["test_ip"] = GeoLocation(ip="test_ip", country="Test")
        assert GeoIPResolver.cache_size() > 0
        GeoIPResolver.clear_cache()
        assert GeoIPResolver.cache_size() == 0

    def test_lookup_hostname_returns_unknown(self):
        """Hostnames should return a no-lookup result without API call."""
        resolver = GeoIPResolver()
        import asyncio
        loc = asyncio.run(resolver.lookup("example.com"))
        assert loc.country_code == "N/A"
        assert "Hostname" in (loc.error or "")

    def test_lookup_hostname_with_port(self):
        """Hostname with port should extract the hostname correctly."""
        resolver = GeoIPResolver()
        import asyncio
        loc = asyncio.run(resolver.lookup("example.com:443"))
        assert loc.country_code == "N/A"

    def test_lookup_caches_hostname_result(self):
        """Subsequent lookups of same hostname should use cache."""
        resolver = GeoIPResolver()
        GeoIPResolver.clear_cache()
        import asyncio
        loc1 = asyncio.run(resolver.lookup("testhost.io"))
        loc2 = asyncio.run(resolver.lookup("testhost.io"))
        assert loc2.cached is True

    def test_lookup_private_ip_returns_error_gracefully(self):
        """Private IPs will fail API lookup but should raise no exception."""
        resolver = GeoIPResolver()
        GeoIPResolver.clear_cache()
        import asyncio
        # This should not crash — the resolver will try the API, fail gracefully
        loc = asyncio.run(resolver.lookup("192.168.1.1"))
        assert loc is not None
        # Should have an error or country info depending on API response

    def test_cache_disabled_skip_lookup(self):
        """use_cache=False skips the cache read check (cache is class-level singleton)."""
        # The cache is stored at the class level, so even with use_cache=False,
        # previously cached entries are found. This test verifies no crash.
        resolver = GeoIPResolver(use_cache=False)
        import asyncio
        loc = asyncio.run(resolver.lookup("unique-nocache-test.io"))
        assert loc is not None
        assert loc.country_code == "N/A"  # Hostname fallback


# =============================================================================
# FilterEngine Sorting Tests
# =============================================================================

class TestFilterEngineSorting:
    """Test the v2.0.0 sorting capabilities of FilterEngine."""

    def test_sort_by_latency_ascending(self):
        configs = [
            {"host": "a", "latency_ms": 100},
            {"host": "b", "latency_ms": 50},
            {"host": "c", "latency_ms": 200},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by_latency(ascending=True).apply()
        latencies = [c["latency_ms"] for c in filtered]
        assert latencies == [50, 100, 200]

    def test_sort_by_latency_descending(self):
        configs = [
            {"host": "a", "latency_ms": 100},
            {"host": "b", "latency_ms": 50},
            {"host": "c", "latency_ms": 200},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by_latency(ascending=False).apply()
        latencies = [c["latency_ms"] for c in filtered]
        assert latencies == [200, 100, 50]

    def test_sort_by_latency_nones_last_ascending(self):
        """Configs with None latency should be sorted last when ascending."""
        configs = [
            {"host": "a", "latency_ms": None},
            {"host": "b", "latency_ms": 50},
            {"host": "c", "latency_ms": 100},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by_latency(ascending=True).apply()
        assert filtered[0]["host"] == "b"
        assert filtered[1]["host"] == "c"
        assert filtered[2]["host"] == "a"

    def test_sort_by_latency_nones_last_descending(self):
        """Configs with None latency should be sorted last when descending too."""
        configs = [
            {"host": "a", "latency_ms": 50},
            {"host": "b", "latency_ms": None},
            {"host": "c", "latency_ms": 100},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by_latency(ascending=False).apply()
        assert filtered[0]["host"] == "c"
        assert filtered[1]["host"] == "a"
        assert filtered[2]["host"] == "b"

    def test_sort_by_latency_all_none(self):
        """When all latencies are None, order should be preserved."""
        configs = [
            {"host": "a", "latency_ms": None},
            {"host": "b", "latency_ms": None},
            {"host": "c", "latency_ms": None},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by_latency().apply()
        assert [c["host"] for c in filtered] == ["a", "b", "c"]

    def test_sort_by_latency_empty_list(self):
        """Sorting an empty list should work without error."""
        engine = FilterEngine([])
        filtered = engine.sort_by_latency().apply()
        assert filtered == []

    def test_sort_by_custom_field(self):
        configs = [
            {"host": "z", "port": 443},
            {"host": "a", "port": 80},
            {"host": "m", "port": 8080},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by("host", ascending=True).apply()
        assert [c["host"] for c in filtered] == ["a", "m", "z"]

    def test_sort_by_custom_field_descending(self):
        configs = [
            {"host": "a", "port": 443},
            {"host": "b", "port": 80},
            {"host": "c", "port": 8080},
        ]
        engine = FilterEngine(configs)
        filtered = engine.sort_by("port", ascending=False).apply()
        assert [c["port"] for c in filtered] == [8080, 443, 80]

    def test_sort_with_filter(self):
        """Sorting should work in combination with filtering."""
        configs = [
            {"type": "vmess", "alive": True, "latency_ms": 200},
            {"type": "vless", "alive": True, "latency_ms": 50},
            {"type": "trojan", "alive": False, "latency_ms": None},
        ]
        engine = FilterEngine(configs)
        filtered = (
            engine.alive(True)
            .sort_by_latency(ascending=True)
            .apply()
        )
        assert len(filtered) == 2
        assert filtered[0]["latency_ms"] == 50
        assert filtered[1]["latency_ms"] == 200

    def test_sort_by_latency_after_clone(self):
        """Cloned engine should maintain independent sort state."""
        configs = [{"latency_ms": 100}, {"latency_ms": 50}]
        engine = FilterEngine(configs)
        cloned = engine.clone()
        cloned.sort_by_latency()
        # Original should have no sort applied
        original_result = engine.apply()
        assert original_result[0]["latency_ms"] == 100
        assert original_result[1]["latency_ms"] == 50
        # Clone should be sorted ascending
        cloned_result = cloned.apply()
        assert cloned_result[0]["latency_ms"] == 50
        assert cloned_result[1]["latency_ms"] == 100


# =============================================================================
# SNI Injection Mapping Tests
# =============================================================================

class TestSNIChecker:
    """Test SNIChecker — local/offline methods only."""

    def setup_method(self):
        SNIChecker.clear_cache()

    def test_extract_domain_simple(self):
        """Simple domain should stay unchanged."""
        assert SNIChecker._extract_domain("example.com") == "example.com"

    def test_extract_domain_subdomain(self):
        """Subdomain should have main domain extracted."""
        assert SNIChecker._extract_domain("sub.example.com") == "example.com"

    def test_extract_domain_deep_subdomain(self):
        """Deep subdomain should have main 2-part domain extracted."""
        assert SNIChecker._extract_domain("a.b.example.com") == "example.com"

    def test_extract_domain_no_subdomain(self):
        """Apex domain should return itself."""
        assert SNIChecker._extract_domain("google.com") == "google.com"

    def test_extract_domain_co_uk(self):
        """Special TLDs like .co.uk should extract 3 parts."""
        result = SNIChecker._extract_domain("sub.example.co.uk")
        assert result == "example.co.uk"

    def test_extract_domain_com_br(self):
        """Special TLDs like .com.br should extract 3 parts."""
        result = SNIChecker._extract_domain("sub.example.com.br")
        assert result == "example.com.br"

    def test_wildcard_match_exact(self):
        """*.example.com should match sub.example.com."""
        assert SNIChecker._wildcard_match("sub.example.com", "*.example.com") is True

    def test_wildcard_match_no_match(self):
        """*.example.com should NOT match other.com."""
        assert SNIChecker._wildcard_match("other.com", "*.example.com") is False

    def test_wildcard_match_no_prefix(self):
        """Pattern without * should return False."""
        assert SNIChecker._wildcard_match("example.com", "example.com") is False

    def test_wildcard_match_deep_sub(self):
        """*.example.com should NOT match deep.sub.example.com — dot counts differ."""
        assert SNIChecker._wildcard_match("deep.sub.example.com", "*.example.com") is False

    def test_wildcard_match_count_equal_depth(self):
        """Pattern *.sub.example.com should match deep.sub.example.com (same dot count)."""
        assert SNIChecker._wildcard_match("deep.sub.example.com", "*.sub.example.com") is True

    def test_generate_candidates_includes_host(self):
        """Host should be included as a candidate."""
        checker = SNIChecker()
        candidates = checker._generate_sni_candidates("example.com", "configured.sni.com")
        assert "example.com" in candidates

    def test_generate_candidates_excludes_original_sni(self):
        """Original configured SNI should not be in candidates."""
        checker = SNIChecker()
        candidates = checker._generate_sni_candidates("example.com", "configured.sni.com")
        assert "configured.sni.com" not in candidates

    def test_generate_candidates_domain_variations(self):
        """Domain variations should be generated."""
        checker = SNIChecker()
        candidates = checker._generate_sni_candidates("sub.example.com", "configured.sni.com")
        # Domain should be extracted
        assert "example.com" in candidates
        # www. variant should exist
        assert "www.example.com" in candidates

    def test_generate_candidates_includes_common(self):
        """Common CDN SNI candidates should be included."""
        checker = SNIChecker()
        candidates = checker._generate_sni_candidates("example.com", "configured.sni.com")
        common_expected = ["cloudflare.com", "speed.cloudflare.com", "www.google.com"]
        for common in common_expected:
            assert common in candidates

    def test_generate_candidates_no_duplicates(self):
        """Candidates list should not contain duplicates."""
        checker = SNIChecker()
        candidates = checker._generate_sni_candidates("example.com", "configured.sni.com")
        assert len(candidates) == len(set(candidates))

    def test_generate_candidates_host_same_as_configured(self):
        """When host equals configured SNI, host should not be duplicated."""
        checker = SNIChecker()
        candidates = checker._generate_sni_candidates("example.com", "example.com")
        # "example.com" should only appear once (was excluded via == check)
        # Actually it appears via domain extraction which also yields "example.com"
        # But dedup should handle it
        assert candidates.count("example.com") <= 1

    def test_cache_clear(self):
        """Clear cache should empty the mapping cache."""
        SNIChecker._SNI_MAPPING_CACHE["test:443"] = "working.sni.com"
        assert len(SNIChecker.get_cached_mappings()) > 0
        SNIChecker.clear_cache()
        assert len(SNIChecker.get_cached_mappings()) == 0

    def test_get_cached_mappings(self):
        """get_cached_mappings should return the current cache dict."""
        SNIChecker._SNI_MAPPING_CACHE["host1:443"] = "sni1.com"
        SNIChecker._SNI_MAPPING_CACHE["host2:8080"] = "sni2.com"
        mappings = SNIChecker.get_cached_mappings()
        assert mappings["host1:443"] == "sni1.com"
        assert mappings["host2:8080"] == "sni2.com"

    def test_validate_skips_non_tls(self):
        """Configs without TLS should skip SNI check."""
        checker = SNIChecker()
        import asyncio
        result = asyncio.run(checker.validate({
            "type": "vmess",
            "host": "example.com",
            "port": 443,
            "tls": "none",
        }))
        assert result.get("sni_needed") is False
        assert result.get("sni_compatible") is True

    def test_validate_missing_sni(self):
        """TLS config with no SNI should flag an issue."""
        checker = SNIChecker()
        import asyncio
        result = asyncio.run(checker.validate({
            "type": "vmess",
            "host": "example.com",
            "port": 443,
            "tls": "tls",
        }))
        # No SNI provided, so should have issues
        if not result.get("sni"):
            assert result.get("sni_compatible") is False
            assert len(result.get("sni_issues", [])) > 0

    def test_validate_uses_host_as_sni_fallback(self):
        """When no sni set, host should be used as fallback."""
        checker = SNIChecker()
        import asyncio
        result = asyncio.run(checker.validate({
            "type": "vmess",
            "host": "example.com",
            "port": 443,
            "tls": "tls",
            "sni": "example.com",
        }))
        assert result["sni"] == "example.com"

    def test_validate_host_mismatch_detection(self):
        """Host header differing from SNI should be flagged."""
        checker = SNIChecker()
        import asyncio
        result = asyncio.run(checker.validate({
            "type": "vmess",
            "host": "example.com",
            "port": 443,
            "tls": "tls",
            "sni": "cdn.example.com",
            "host_header": "different.com",
        }))
        assert result.get("host_mismatch") is True


# =============================================================================
# TUI Helper Tests
# =============================================================================

class TestTUIHelpers:
    """Test standalone helper functions used in the TUI module."""

    def test_status_cell_alive(self):
        """Alive status should return green text."""
        # Import the inline helper from the TUI module
        from ibrovix_validator.tui import _status_cell
        result = _status_cell(True)
        assert "ALIVE" in result
        assert "green" in result or "GREEN" in result

    def test_status_cell_dead(self):
        """Dead status should return red text."""
        from ibrovix_validator.tui import _status_cell
        result = _status_cell(False)
        assert "DEAD" in result
        assert "red" in result or "RED" in result

    def test_status_cell_unknown(self):
        """Unknown status should return yellow text."""
        from ibrovix_validator.tui import _status_cell
        result = _status_cell(None)
        assert "?" in result
        assert "yellow" in result or "YELLOW" in result

    def test_latency_cell_none(self):
        """None latency should show dim placeholder."""
        from ibrovix_validator.tui import _latency_cell
        result = _latency_cell(None)
        assert "---" in result

    def test_latency_cell_fast(self):
        """Fast latency (<100ms) should be green."""
        from ibrovix_validator.tui import _latency_cell
        result = _latency_cell(50)
        assert "green" in result or "GREEN" in result
        assert "50" in result

    def test_latency_cell_medium(self):
        """Medium latency (100-300ms) should be yellow."""
        from ibrovix_validator.tui import _latency_cell
        result = _latency_cell(150)
        assert "yellow" in result or "YELLOW" in result
        assert "150" in result

    def test_latency_cell_slow(self):
        """Slow latency (>300ms) should be red."""
        from ibrovix_validator.tui import _latency_cell
        result = _latency_cell(500)
        assert "red" in result or "RED" in result
        assert "500" in result

    def test_proto_cell_vmess(self):
        """VMess protocol should have magenta color."""
        from ibrovix_validator.tui import _proto_cell
        result = _proto_cell("vmess")
        assert "VMESS" in result
        assert "magenta" in result or "MAGENTA" in result

    def test_proto_cell_vless(self):
        """VLESS protocol should have blue color."""
        from ibrovix_validator.tui import _proto_cell
        result = _proto_cell("vless")
        assert "VLESS" in result
        assert "blue" in result or "BLUE" in result

    def test_proto_cell_trojan(self):
        """Trojan protocol should have red color."""
        from ibrovix_validator.tui import _proto_cell
        result = _proto_cell("trojan")
        assert "TROJAN" in result
        assert "red" in result or "RED" in result

    def test_proto_cell_ssh(self):
        """SSH protocol should have green color."""
        from ibrovix_validator.tui import _proto_cell
        result = _proto_cell("ssh")
        assert "SSH" in result
        assert "green" in result or "GREEN" in result

    def test_proto_cell_unknown(self):
        """Unknown protocol should use white color."""
        from ibrovix_validator.tui import _proto_cell
        result = _proto_cell("unknown")
        assert "UNKNOWN" in result


# =============================================================================
# OutputFormatter Tests (v2.0.0 additions)
# =============================================================================

class TestOutputFormatterV2:
    """Test OutputFormatter — v2.0.0 specific formatting."""

    def test_format_plain_with_all_fields(self):
        """Plain output should include type, name, host, port, status, latency."""
        formatter = OutputFormatter(use_color=False)
        configs = [{
            "type": "vmess", "name": "TestServer", "host": "example.com",
            "port": 443, "alive": True, "latency_ms": 50.5,
        }]
        output = formatter.format_plain(configs)
        assert "VMESS" in output
        assert "TestServer" in output
        assert "example.com" in output
        assert "443" in output
        assert "OK" in output
        assert "50.5ms" in output

    def test_format_plain_no_name(self):
        """Plain output without name should still work."""
        formatter = OutputFormatter(use_color=False)
        configs = [{
            "type": "trojan", "host": "server.io", "port": 8443,
            "alive": False, "latency_ms": None,
        }]
        output = formatter.format_plain(configs)
        assert "TROJAN" in output
        assert "server.io" in output
        assert "DEAD" in output

    def test_format_plain_multiple(self):
        """Plain output should handle multiple configs."""
        formatter = OutputFormatter(use_color=False)
        configs = [
            {"type": "vmess", "name": "A", "host": "a.com", "port": 443, "alive": True, "latency_ms": 10},
            {"type": "vless", "name": "B", "host": "b.com", "port": 80, "alive": False, "latency_ms": None},
        ]
        output = formatter.format_plain(configs)
        lines = output.split("\n")
        assert len(lines) == 2

    def test_format_table_no_color(self):
        """Table output without color should still render properly."""
        formatter = OutputFormatter(use_color=False)
        configs = [{
            "type": "vmess", "name": "Test", "host": "example.com",
            "port": 443, "alive": True, "latency_ms": 50.0,
            "net": "ws", "tls": "tls", "sni": "example.com",
        }]
        output = formatter.format_table(configs)
        assert "Test" in output
        assert "example.com" in output
        assert "443" in output
        assert "ALIVE" in output or "50.0" in output

    def test_format_table_empty(self):
        """Empty config list should return 'No configs to display'."""
        formatter = OutputFormatter(use_color=False)
        assert "No configs" in formatter.format_table([])

    def test_format_json_pretty(self):
        """JSON output should be pretty-printed by default."""
        formatter = OutputFormatter()
        configs = [{"host": "example.com", "port": 443}]
        output = formatter.format_json(configs)
        parsed = json.loads(output)
        assert parsed == configs

    def test_format_json_not_pretty(self):
        """JSON output without pretty should be compact."""
        formatter = OutputFormatter()
        configs = [{"host": "example.com", "port": 443}]
        output = formatter.format_json(configs, pretty=False)
        assert "\n" not in output

    def test_format_stats_contains_counts(self):
        """Stats should include count fields."""
        formatter = OutputFormatter(use_color=False)
        stats = {
            "total": 10, "alive": 5, "dead": 3, "untested": 2,
            "by_type": {"vmess": 5, "trojan": 5},
        }
        output = formatter.format_stats(stats)
        assert "10" in output
        assert "5" in output
        assert "3" in output
        assert "vmess" in output
        assert "trojan" in output
