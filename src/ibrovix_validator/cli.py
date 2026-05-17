"""IBROVIX-Validator CLI — command-line interface for proxy validation."""

import argparse
import asyncio
import sys
import os
from typing import Optional

from . import __version__
from .config import ValidatorConfig
from .parsers import parse_line
from .validators import FormatValidator, HandshakeValidator, SNIChecker
from .filters import FilterEngine
from .utils.io import ConfigReader, ConfigWriter
from .utils.output import OutputFormatter, Colorizer
from .harvester import ConfigHarvester, HarvestResult


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ibrovix-validator",
        description="IBROVIX-Validator — High-performance proxy validation & filtering tool",
        epilog="Supports VMess, VLESS, Trojan, and SSH protocols.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"IBROVIX-Validator v{__version__}",
    )

    # Input source
    parser.add_argument(
        "input",
        nargs="?",
        help="Input file with proxy configs (reads from stdin if omitted)",
    )

    # Harvester options
    parser.add_argument(
        "--harvest",
        action="store_true",
        help="Enable live proxy harvesting mode — fetch configs from public sources",
    )
    parser.add_argument(
        "--source",
        "-s",
        action="append",
        dest="sources",
        default=[],
        metavar="URL",
        help="Custom subscription/raw config URL(s) to harvest from (can be used multiple times)",
    )
    parser.add_argument(
        "--default-sources",
        action="store_true",
        help="Include built-in default public sources (freefq, surfboardv2ray, etc.)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable harvester progress output",
    )

    # Actions
    parser.add_argument(
        "-m", "--mode",
        choices=["parse", "check", "probe", "filter"],
        default="check",
        help="""Operation mode:
  parse   — Parse configs and show structure
  check   — Parse + format validation (default)
  probe   — Parse + validate + connectivity handshake test
  filter  — Parse + validate + filter results
""",
    )

    # Filter options
    parser.add_argument(
        "--protocol",
        nargs="+",
        choices=["vmess", "vless", "trojan", "ssh"],
        help="Filter by protocol type(s)",
    )
    parser.add_argument(
        "--alive",
        action="store_true",
        help="Show only alive servers (requires --mode probe or check)",
    )
    parser.add_argument(
        "--dead",
        action="store_true",
        help="Show only dead servers",
    )
    parser.add_argument(
        "--max-latency",
        type=float,
        metavar="MS",
        help="Maximum acceptable latency in milliseconds",
    )
    parser.add_argument(
        "--min-latency",
        type=float,
        metavar="MS",
        help="Minimum latency in milliseconds",
    )
    parser.add_argument(
        "--transport",
        nargs="+",
        choices=["tcp", "ws", "grpc", "quic", "kcp", "http"],
        help="Filter by transport type(s)",
    )
    parser.add_argument(
        "--tls",
        choices=["tls", "none", "reality"],
        help="Filter by TLS mode",
    )
    parser.add_argument(
        "--search",
        type=str,
        metavar="TERM",
        help="Search configs by name or host containing this term",
    )
    parser.add_argument(
        "--valid-format",
        action="store_true",
        help="Show only format-valid configs",
    )
    parser.add_argument(
        "--with-errors",
        action="store_true",
        help="Show only configs with errors",
    )

    # Interactive TUI / Menu
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch interactive Terminal User Interface (Textual)",
    )
    parser.add_argument(
        "--menu",
        action="store_true",
        help="Launch interactive Rich terminal menu (harvest, validate, SNI match)",
    )

    # Output options
    parser.add_argument(
        "-o", "--output",
        choices=["table", "json", "plain"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show statistics summary",
    )
    parser.add_argument(
        "--export",
        type=str,
        metavar="FILE",
        help="Export valid/alive configs to a file",
    )

    # Performance options
    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Max concurrent validation workers (default: 50)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="TCP connection timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--tls-timeout",
        type=float,
        default=8.0,
        help="TLS handshake timeout in seconds (default: 8.0)",
    )

    # Probe options
    parser.add_argument(
        "--no-tls-probe",
        action="store_true",
        help="Skip TLS handshake probe",
    )
    parser.add_argument(
        "--no-sni-check",
        action="store_true",
        help="Skip SNI/Host compatibility check",
    )
    parser.add_argument(
        "--no-trojan-probe",
        action="store_true",
        help="Skip Trojan protocol probe",
    )
    parser.add_argument(
        "--no-ssh-banner",
        action="store_true",
        help="Skip SSH banner detection",
    )

    return parser


def run_cli(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Build config
    cfg = ValidatorConfig(
        tcp_timeout=args.timeout,
        tls_timeout=args.tls_timeout,
        max_workers=args.workers,
        output_format=args.output,
        color_output=not args.no_color,
        tls_probe=not args.no_tls_probe,
        sni_check=not args.no_sni_check,
        trojan_probe=not args.no_trojan_probe,
        ssh_banner=not args.no_ssh_banner,
    )

    formatter = OutputFormatter(use_color=not args.no_color)

    # Read input — either from harvester or file/stdin
    parsed: list[dict] = []
    harvest_result: Optional[HarvestResult] = None

    def _run_harvester(sources: Optional[list[str]], use_defaults: bool) -> Optional[HarvestResult]:
        """Run the harvester and print results. Returns harvest_result or None on failure."""
        print("🌐 IBROVIX Harvester — fetching live proxy configs...", file=sys.stderr)
        print(f"  Sources: {'custom URLs' if sources else 'none'}{' + defaults' if use_defaults else ''}", file=sys.stderr)

        h = ConfigHarvester(
            timeout=cfg.tcp_timeout * 3,
            max_concurrent=min(args.workers, 20),
            progress=not args.no_progress,
        )

        hr = asyncio.run(
            h.harvest(
                sources=sources,
                use_defaults=use_defaults,
            )
        )

        if hr.total_unique == 0:
            print("\nWarning: No configs were harvested.", file=sys.stderr)
            return None

        print(f"\n{h.format_result_summary(hr)}", file=sys.stderr)
        print(file=sys.stderr)
        return hr

    # Determine input source priority:
    #   1. Explicit --harvest / --source / --default-sources flags
    #   2. Input file argument
    #   3. Data piped via stdin (non-TTY)
    #   4. Auto-harvest with defaults (if nothing else is available)
    #
    input_from_stdin = not sys.stdin.isatty()

    if args.harvest or args.sources or args.default_sources:
        # --- Explicit harvester mode ---
        hr = _run_harvester(
            sources=args.sources if args.sources else None,
            use_defaults=args.default_sources or not args.sources,
        )
        if hr is None:
            if args.stats:
                print(formatter.format_stats({"total": 0, "by_type": {}, "alive": 0, "dead": 0, "untested": 0}))
            return 0
        harvest_result = hr
        parsed = hr.unique_configs

    elif args.input:
        # --- File input mode ---
        try:
            lines = ConfigReader.from_file(args.input)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

        for line in lines:
            result = parse_line(line)
            if result is not None:
                parsed.append(result)

        if not parsed:
            print("Warning: No valid configs found in input.", file=sys.stderr)
            if args.stats:
                print(formatter.format_stats({"total": 0, "by_type": {}, "alive": 0, "dead": 0, "untested": 0}))
            return 0

    elif input_from_stdin:
        # --- Stdin input mode ---
        lines = ConfigReader.from_stdin()
        if not lines:
            print("Warning: Empty input from stdin.", file=sys.stderr)
            return 0

        for line in lines:
            result = parse_line(line)
            if result is not None:
                parsed.append(result)

        if not parsed:
            print("Warning: No valid configs found in input.", file=sys.stderr)
            if args.stats:
                print(formatter.format_stats({"total": 0, "by_type": {}, "alive": 0, "dead": 0, "untested": 0}))
            return 0

    else:
        # --- No input provided — auto-harvest with defaults ---
        print("📡 No input file provided — automatically harvesting live configs...", file=sys.stderr)
        print("ℹ️  To disable auto-harvest, specify an input file or pipe data via stdin.", file=sys.stderr)
        hr = _run_harvester(sources=None, use_defaults=True)
        if hr is None:
            print("\nNo configs could be harvested from any source.", file=sys.stderr)
            if args.stats:
                print(formatter.format_stats({"total": 0, "by_type": {}, "alive": 0, "dead": 0, "untested": 0}))
            return 0
        harvest_result = hr
        parsed = hr.unique_configs

    if not parsed:
        print("Warning: No valid configs found.", file=sys.stderr)
        if args.stats:
            print(formatter.format_stats({"total": 0, "by_type": {}, "alive": 0, "dead": 0, "untested": 0}))
        return 0

    # Launch interactive Rich menu if requested
    if args.menu:
        print("Launching Interactive Menu...", file=sys.stderr)
        try:
            from .menu import run_menu
            run_menu()
        except ImportError as e:
            print(f"Error: Menu requires 'rich' package. Install with: pip install rich\n{e}", file=sys.stderr)
            return 1
        return 0

    # Launch interactive TUI if requested
    if args.tui:
        print(f"Launching Interactive TUI with {len(parsed)} configs...", file=sys.stderr)
        try:
            from .tui import run_tui
            run_tui(parsed)
        except ImportError as e:
            print(f"Error: TUI requires 'textual' package. Install with: pip install textual\n{e}", file=sys.stderr)
            return 1
        return 0

    # Mode: parse only
    if args.mode == "parse":
        if args.stats:
            engine = FilterEngine(parsed)
            print(formatter.format_stats(engine.stats()))
        if args.output == "json":
            print(formatter.format_json(parsed))
        else:
            for cfg in parsed:
                print(f"  [{cfg.get('type','?'):>6}] {cfg.get('name','?'):<24} {cfg.get('host','?'):<20}:{cfg.get('port',0)}")
        return 0

    # Format validation
    print("Validating config formats...", file=sys.stderr)
    format_validator = FormatValidator()
    validated = asyncio.run(_run_validators(format_validator, parsed, cfg))

    # Mode: check (format validation only)
    if args.mode == "check":
        valid_count = sum(1 for c in validated if c.get("format_valid"))
        print(f"  {valid_count}/{len(validated)} configs have valid format\n", file=sys.stderr)

        if args.valid_format or args.alive:
            validated = [c for c in validated if c.get("format_valid")]

        if args.with_errors:
            validated = [c for c in validated if c.get("format_errors")]

    # Mode: probe (full connectivity test)
    if args.mode == "probe":
        print("Probing servers...", file=sys.stderr)
        handshake = HandshakeValidator(cfg)

        if cfg.sni_check:
            sni_checker = SNIChecker(cfg)
            validated = asyncio.run(_run_validators_parallel(handshake, sni_checker, validated, cfg))
        else:
            validated = asyncio.run(_run_validators(handshake, validated, cfg))

        alive_count = sum(1 for c in validated if c.get("alive"))
        print(f"  {alive_count}/{len(validated)} servers alive\n", file=sys.stderr)

    # Mode: filter
    if args.mode == "filter":
        if not args.protocol and not args.alive and not args.dead and not args.max_latency and not args.search and not args.transport and not args.tls and not args.valid_format and not args.with_errors:
            print("Warning: No filters specified. Use --help to see available filters.", file=sys.stderr)
        else:
            print("Filtering configs...", file=sys.stderr)

    # Apply filters
    engine = FilterEngine(validated)

    if args.protocol:
        engine.by_protocol(*args.protocol)
    if args.alive:
        engine.alive(True)
    if args.dead:
        engine.alive(False)
    if args.max_latency is not None:
        engine.max_latency(args.max_latency)
    if args.min_latency is not None:
        engine.min_latency(args.min_latency)
    if args.transport:
        engine.by_transport(*args.transport)
    if args.tls:
        engine.by_tls(args.tls)
    if args.search:
        engine.name_contains(args.search)
        engine.by_host(args.search)
    if args.valid_format:
        engine.valid_format(True)
    if args.with_errors:
        engine.with_error()

    filtered = engine.apply()

    # Output
    if args.stats:
        stats = engine.stats()
        stats["filtered_count"] = len(filtered)
        print(formatter.format_stats(stats))

    if args.output == "json":
        print(formatter.format_json(filtered))
    elif args.output == "plain":
        print(formatter.format_plain(filtered))
    else:
        print(formatter.format_table(filtered))

    # Export
    if args.export:
        exported = ConfigWriter.export_valid(filtered)
        ConfigWriter.to_file(args.export, exported)
        print(f"\nExported {len(exported)} configs to {args.export}", file=sys.stderr)

    return 0


async def _run_validators(validator, configs: list[dict], cfg: ValidatorConfig) -> list[dict]:
    """Run a validator across all configs concurrently."""
    sem = asyncio.Semaphore(cfg.max_workers)

    async def _validate_one(config: dict) -> dict:
        async with sem:
            try:
                return await validator.validate(config)
            except Exception as e:
                config["error"] = str(e)
                return config

    tasks = [_validate_one(c) for c in configs]
    return await asyncio.gather(*tasks)


async def _run_validators_parallel(
    v1, v2, configs: list[dict], cfg: ValidatorConfig
) -> list[dict]:
    """Run two validators across all configs concurrently."""
    sem = asyncio.Semaphore(cfg.max_workers)

    async def _validate_both(config: dict) -> dict:
        async with sem:
            try:
                c1 = await v1.validate(config)
                c2 = await v2.validate(c1)
                return c2
            except Exception as e:
                config["error"] = str(e)
                return config

    tasks = [_validate_both(c) for c in configs]
    return await asyncio.gather(*tasks)


def main():
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
