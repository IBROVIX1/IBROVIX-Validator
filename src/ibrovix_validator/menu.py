"""IBROVIX-Validator Interactive Menu — rich terminal menu with live progress.

Provides a beautiful interactive text menu with:
  - Stylized banner showing "IBROVIX-Validator v2.0.0"
  - Live progress bars during processing
  - Live counters showing real-time results
  - 5 menu options for different validation workflows
  - hosts.txt → SNI matching → host_server.txt pipeline

Menu Options:
  [1] Harvest & Validate ALL Protocols (VMess, VLESS, Trojan, Shadowsocks)
  [2] Harvest & Validate V2Ray Protocols ONLY (VMess & VLESS)
  [3] Advanced SNI/Host Matching (Cross-match with custom SNIs from hosts.txt)
  [4] System Settings & Source Update
  [5] Exit
"""

import asyncio
import ssl
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn, TaskProgressColumn,
)
from rich import box
from rich.prompt import Prompt, Confirm

from . import __version__
from .config import ValidatorConfig
from .parsers import parse_line
from .validators import FormatValidator, HandshakeValidator, SNIChecker
from .filters import FilterEngine
from .utils.io import ConfigReader, ConfigWriter
from .utils.output import OutputFormatter
from .harvester import ConfigHarvester, HarvestResult

console = Console()

# ── Banner ────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                     IBROVIX-Validator                        ║
║              High-Performance Proxy Validation               ║
║                   ✦  v{}  ✦                        ║
╚══════════════════════════════════════════════════════════════╝
"""


def _print_banner():
    """Display the stylized banner."""
    console.print(BANNER.format(__version__), style="bold cyan", justify="center")
    console.print()


# ── Rich-based live progress wrapper ──────────────────────────────────────

class LiveProgress:
    """Context manager for Rich-based live progress displays."""

    def __init__(self, description: str = "Processing..."):
        self.description = description
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        self.task = None

    def __enter__(self):
        self.progress.start()
        self.task = self.progress.add_task(self.description, total=None)
        return self

    def __exit__(self, *args):
        self.progress.stop()

    def update(self, completed: int = None, total: int = None, description: str = None):
        """Update progress bar state."""
        if description:
            self.progress.update(self.task, description=description)
        if total is not None:
            self.progress.update(self.task, total=total)
        if completed is not None:
            self.progress.update(self.task, completed=completed)


# ── Core pipeline functions ──────────────────────────────────────────────

async def _run_harvest_pipeline(
    protocols: Optional[list[str]] = None,
    use_defaults: bool = True,
    sources: Optional[list[str]] = None,
) -> tuple[list[dict], Optional[HarvestResult]]:
    """Harvest, validate, probe, and return configs with live progress."""
    console.print("\n[bold cyan]📡 Harvest Phase[/] — Fetching live proxy configs...")

    harvester = ConfigHarvester(progress=True, timeout=15.0, max_concurrent=10)
    hr = await harvester.harvest(
        sources=sources,
        use_defaults=use_defaults,
        protocols=protocols,
    )

    if hr.total_unique == 0:
        console.print("[bold red]✗ No configs harvested from any source.[/]")
        return [], hr

    console.print(f"[green]✓ {hr.total_unique} unique configs harvested[/]")
    console.print(f"  Protocols: {', '.join(f'{k}: {v}' for k, v in hr.by_protocol.items())}")

    configs = hr.unique_configs

    # Format validation
    console.print("\n[bold cyan]🔍 Validation Phase[/] — Checking config formats...")
    fmt_validator = FormatValidator()
    sem = asyncio.Semaphore(50)

    async def _validate_one(cfg):
        async with sem:
            return await fmt_validator.validate(cfg)

    validated = await asyncio.gather(*[_validate_one(c) for c in configs])
    valid_count = sum(1 for c in validated if c.get("format_valid"))
    console.print(f"[green]✓ {valid_count}/{len(validated)} configs have valid format[/]")

    # Handshake probe
    console.print(f"\n[bold cyan]⚡ Probe Phase[/] — Testing server connectivity...")
    cfg = ValidatorConfig(max_workers=50)
    handshake = HandshakeValidator(cfg)

    async def _probe_one(cfg_dict):
        async with sem:
            return await handshake.validate(cfg_dict)

    with LiveProgress("Probing servers...") as lp:
        lp.progress.update(lp.task, total=len(validated))
        probed = []
        batch_size = max(1, len(validated) // 20)
        for i, c in enumerate(validated):
            probed.append(await _probe_one(c))
            if (i + 1) % batch_size == 0 or i == len(validated) - 1:
                alive_so_far = sum(1 for p in probed if p.get("alive"))
                lp.update(completed=i + 1, description=f"Probing... {i+1}/{len(validated)} ({alive_so_far} alive)")

    alive_count = sum(1 for c in probed if c.get("alive"))
    console.print(f"[green]✓ {alive_count}/{len(probed)} servers alive[/]")

    # Sort by latency
    engine = FilterEngine(probed)
    engine.sort_by_latency(ascending=True)
    sorted_configs = engine.apply()

    return sorted_configs, hr


async def _run_sni_matching_pipeline(configs: list[dict]) -> None:
    """Advanced SNI/Host Matching — read hosts.txt, inject SNIs, test, output host_server.txt.

    For each alive server, reads custom SNIs from hosts.txt and tries them,
    performing real TLS handshakes. Outputs working combinations to host_server.txt.
    """
    hosts_file = Path("hosts.txt")
    if not hosts_file.exists():
        console.print("[bold red]✗ hosts.txt not found in current directory.[/]")
        console.print("  Create a file named 'hosts.txt' with one domain/IP per line.")
        return

    custom_hosts = [
        line.strip() for line in hosts_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not custom_hosts:
        console.print("[bold red]✗ hosts.txt is empty (no custom hosts to inject).[/]")
        return

    console.print(f"\n[bold cyan]📋 Loaded {len(custom_hosts)} host(s) from hosts.txt:[/]")
    for h in custom_hosts:
        console.print(f"    • {h}")
    console.print()

    # Filter to only alive TLS configs
    alive_tls = [
        c for c in configs
        if c.get("alive") and c.get("tls", "none") in ("tls", "reality", "xtls")
    ]

    if not alive_tls:
        console.print("[bold yellow]⚠ No alive TLS configs to test against.[/]")
        return

    console.print(f"[cyan]Testing {len(alive_tls)} alive TLS servers against {len(custom_hosts)} custom hosts...[/]\n")

    working_combos = []
    total_tests = len(alive_tls) * len(custom_hosts)

    with LiveProgress("SNI injection mapping...") as lp:
        lp.progress.update(lp.task, total=total_tests)
        test_count = 0

        for cfg in alive_tls:
            host = cfg.get("host", "")
            port = cfg.get("port", 0)
            original_sni = cfg.get("sni") or host

            for custom_host in custom_hosts:
                test_count += 1
                lp.update(
                    completed=test_count,
                    description=f"Testing {custom_host} → {host}:{port} ({test_count}/{total_tests})",
                )

                # Clone config with injected custom host
                test_cfg = dict(cfg)
                test_cfg["sni"] = custom_host
                test_cfg["host_header"] = custom_host
                test_cfg["host"] = custom_host

                # Perform TLS handshake with the injected SNI
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED

                try:
                    start = time.monotonic()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx, server_hostname=custom_host),
                        timeout=8.0,
                    )
                    elapsed = (time.monotonic() - start) * 1000

                    # Verify certificate
                    ssl_obj = writer.get_extra_info("ssl_object")
                    cert_ok = False
                    if ssl_obj:
                        try:
                            cert = ssl_obj.getpeercert()
                            if cert:
                                sans = [san[1] for san in cert.get("subjectAltName", [])]
                                cert_ok = custom_host in sans or any(
                                    SNIChecker._wildcard_match(custom_host, san) for san in sans
                                )
                        except Exception:
                            pass

                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    if cert_ok or elapsed < 3000:  # If TLS handshake completed, it's promising
                        working_combos.append({
                            "original_config": cfg.get("raw", ""),
                            "original_host": host,
                            "original_port": port,
                            "original_sni": original_sni,
                            "injected_host": custom_host,
                            "latency_ms": round(elapsed, 1),
                            "tls_verified": cert_ok,
                        })

                except Exception:
                    pass

    # Write results to host_server.txt
    output_lines = []
    output_lines.append("# IBROVIX-Validator SNI Injection Results")
    output_lines.append(f"# Generated: {datetime.now().isoformat()}")
    output_lines.append(f"# Tested: {len(alive_tls)} servers × {len(custom_hosts)} hosts = {total_tests} combinations")
    output_lines.append(f"# Working: {len(working_combos)} combinations")
    output_lines.append("")

    if working_combos:
        output_lines.append("# Working SNI Injection Combinations")
        output_lines.append("# Format: original_config | injected_host | latency_ms | tls_verified")
        output_lines.append("")
        for wc in sorted(working_combos, key=lambda x: x["latency_ms"]):
            raw = wc.get("original_config", "")
            output_lines.append(f"{raw} | sni={wc['injected_host']} | {wc['latency_ms']}ms | tls={wc['tls_verified']}")
            output_lines.append(f"  → Functional: {wc['injected_host']}:{wc['original_port']} (SNI: {wc['injected_host']})")
            output_lines.append("")

    output_lines.append("")
    output_lines.append("# Summary")
    output_lines.append(f"Total servers tested: {len(alive_tls)}")
    output_lines.append(f"Custom hosts injected: {len(custom_hosts)}")
    output_lines.append(f"Working combinations found: {len(working_combos)}")

    Path("host_server.txt").write_text("\n".join(output_lines), encoding="utf-8")

    console.print(f"\n[bold green]✓ Results written to host_server.txt[/]")
    console.print(f"  Total combinations tested: [bold]{total_tests}[/]")
    console.print(f"  Working combinations: [bold green]{len(working_combos)}[/]")

    if working_combos:
        console.print("\n[bold]Top working injections (lowest latency):[/]")
        for wc in working_combos[:5]:
            console.print(
                f"  [green]•[/] {wc['original_host']}:{wc['original_port']} "
                f"→ [bold]{wc['injected_host']}[/] "
                f"({wc['latency_ms']}ms, TLS: {'✓' if wc['tls_verified'] else '?'})"
            )


# ── Menu Options ─────────────────────────────────────────────────────────

async def _option_1():
    """Harvest & Validate ALL Protocols (VMess, VLESS, Trojan, Shadowsocks)."""
    console.clear()
    _print_banner()
    console.print("[bold green][[1]][/] Harvest & Validate ALL Protocols\n")

    configs, hr = await _run_harvest_pipeline(use_defaults=True)
    if not configs:
        return

    # Geo-IP tagging
    console.print(f"\n[bold cyan]🌍 Geo-IP Phase[/] — Resolving locations for alive servers...")
    alive = [c for c in configs if c.get("alive")]
    await _tag_geo_ip(alive)

    # Display results
    _display_results(configs)


async def _option_2():
    """Harvest & Validate V2Ray Protocols ONLY (VMess & VLESS)."""
    console.clear()
    _print_banner()
    console.print("[bold blue][[2]][/] Harvest & Validate V2Ray Protocols ONLY (VMess & VLESS)\n")

    configs, hr = await _run_harvest_pipeline(
        protocols=["vmess", "vless"],
        use_defaults=True,
    )
    if not configs:
        return

    # Geo-IP tagging
    console.print(f"\n[bold cyan]🌍 Geo-IP Phase[/] — Resolving locations for alive servers...")
    alive = [c for c in configs if c.get("alive")]
    await _tag_geo_ip(alive)

    _display_results(configs)


async def _option_3():
    """Advanced SNI/Host Matching — hosts.txt → injection → host_server.txt."""
    console.clear()
    _print_banner()
    console.print("[bold yellow][[3]][/] Advanced SNI/Host Matching\n")

    # First, we need alive configs. Ask user how to get them.
    choice = Prompt.ask(
        "How would you like to provide configs?",
        choices=["harvest", "file"],
        default="harvest",
    )

    configs = []
    if choice == "harvest":
        harvest_configs, _ = await _run_harvest_pipeline(use_defaults=True)
        configs = harvest_configs
    else:
        filepath = Prompt.ask("Enter config file path", default="configs.txt")
        try:
            lines = ConfigReader.from_file(filepath)
            for line in lines:
                cfg = parse_line(line)
                if cfg is not None:
                    configs.append(cfg)
        except FileNotFoundError:
            console.print(f"[bold red]✗ File not found: {filepath}[/]")
            return

    if not configs:
        console.print("[bold red]✗ No configs available.[/]")
        return

    alive = [c for c in configs if c.get("alive")]
    if not alive:
        console.print("[bold yellow]⚠ No alive configs found. Running handshake probe first...[/]")
        cfg = ValidatorConfig(max_workers=50)
        handshake = HandshakeValidator(cfg)
        sem = asyncio.Semaphore(50)

        async def _probe(c):
            async with sem:
                return await handshake.validate(c)

        probed = await asyncio.gather(*[_probe(c) for c in configs])
        alive = [c for c in probed if c.get("alive")]
        configs = probed
        console.print(f"[green]✓ {len(alive)}/{len(configs)} alive[/]")

    # Run SNI matching pipeline
    await _run_sni_matching_pipeline(configs)


async def _option_4():
    """System Settings & Source Update."""
    console.clear()
    _print_banner()
    console.print("[bold magenta][[4]][/] System Settings & Source Update\n")

    from .harvester import DEFAULT_SOURCES

    sources_path = Path("sources.txt")

    while True:
        console.print(Panel(
            "[bold]Current Configuration[/]\n"
            f"  Default sources: [cyan]{len(DEFAULT_SOURCES)}[/] built-in URLs\n"
            f"  Sources file: [{'green' if sources_path.exists() else 'yellow'}]{sources_path.name if sources_path.exists() else 'not found'}[/]\n"
            f"  Version: [bold]{__version__}[/]",
            title="Settings",
            box=box.ROUNDED,
        ))

        console.print()
        console.print("  [1] View default source URLs")
        console.print("  [2] Save default sources to sources.txt (to edit)")
        console.print("  [3] View custom sources.txt")
        console.print("  [4] Clear cache (SNI mappings, Geo-IP)")
        console.print("  [5] Back to main menu")
        console.print()

        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"], default="5")

        if choice == "1":
            console.print("\n[bold]Default Harvest Sources:[/]")
            for i, url in enumerate(DEFAULT_SOURCES, 1):
                console.print(f"  {i:2d}. [dim]{url}[/]")
            console.print()

        elif choice == "2":
            content = "\n".join(DEFAULT_SOURCES)
            sources_path.write_text(content, encoding="utf-8")
            console.print(f"[green]✓ Saved {len(DEFAULT_SOURCES)} sources to {sources_path}[/]\n")

        elif choice == "3":
            if sources_path.exists():
                console.print(f"\n[bold]Contents of {sources_path}:[/]")
                for line in sources_path.read_text().splitlines():
                    if line.strip():
                        console.print(f"  • [dim]{line.strip()}[/]")
                console.print()
            else:
                console.print(f"[yellow]⚠ sources.txt not found. Use option [2] to create it.[/]\n")

        elif choice == "4":
            from .validators.sni_check import SNIChecker
            from .utils.geo import GeoIPResolver
            SNIChecker.clear_cache()
            GeoIPResolver.clear_cache()
            console.print("[green]✓ SNI mapping cache cleared[/]")
            console.print("[green]✓ Geo-IP cache cleared[/]\n")

        else:
            break


async def _option_5():
    """Exit — gracefully terminate the session."""
    console.print("\n[bold cyan]Thank you for using IBROVIX-Validator![/]")
    console.print("[dim]Exiting...[/]")


# ── Geo-IP Tagging ──────────────────────────────────────────────────────

async def _tag_geo_ip(configs: list[dict]) -> None:
    """Tag configs with Geo-IP information asynchronously."""
    from .utils.geo import GeoIPResolver
    resolver = GeoIPResolver()

    alive = [c for c in configs if c.get("alive")]
    if not alive:
        console.print("[dim]No alive servers to geo-tag.[/]")
        return

    with LiveProgress("Resolving Geo-IP...") as lp:
        lp.progress.update(lp.task, total=len(alive))
        for i, cfg in enumerate(alive):
            host = cfg.get("host", "")
            if host:
                loc = await resolver.lookup(host)
                cfg["geo"] = {
                    "country_code": loc.country_code,
                    "country": loc.country,
                    "city": loc.city,
                    "isp": loc.isp,
                    "lat": loc.lat,
                    "lon": loc.lon,
                }
                cfg["geo_display"] = loc.short_display
            lp.update(completed=i + 1)

    geo_count = sum(1 for c in alive if c.get("geo_display") and c["geo_display"] != "Unknown")
    console.print(f"[green]✓ Geo-tagged {geo_count}/{len(alive)} servers[/]")


# ── Results Display ─────────────────────────────────────────────────────

def _display_results(configs: list[dict]) -> None:
    """Display results in a Rich table with live counters."""
    total = len(configs)
    alive = [c for c in configs if c.get("alive")]
    dead = [c for c in configs if not c.get("alive")]

    # Stats panel
    stats = Panel(
        f"[bold green]Alive: {len(alive)}[/]   "
        f"[bold red]Dead: {len(dead)}[/]   "
        f"[bold]Total: {total}[/]   "
        f"[bold]Avg Latency: {sum(c.get('latency_ms', 0) or 0 for c in alive) / max(len(alive), 1):.0f}ms[/]",
        title="Results Summary",
        box=box.ROUNDED,
    )
    console.print(stats)

    # Protocol breakdown
    by_proto = {}
    for c in configs:
        proto = c.get("type", "?")
        by_proto.setdefault(proto, {"total": 0, "alive": 0})
        by_proto[proto]["total"] += 1
        if c.get("alive"):
            by_proto[proto]["alive"] += 1

    proto_table = Table(title="Protocol Breakdown", box=box.SIMPLE, title_style="bold")
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Total", justify="right")
    proto_table.add_column("Alive", justify="right")
    proto_table.add_column("Dead", justify="right")

    for proto, counts in sorted(by_proto.items()):
        proto_table.add_row(
            proto.upper(),
            str(counts["total"]),
            f"[green]{counts['alive']}[/]",
            f"[red]{counts['total'] - counts['alive']}[/]",
        )

    # Geo-IP table
    geo_alive = [c for c in alive if c.get("geo_display")]
    if geo_alive:
        geo_table = Table(title="Geo-IP Locations (Alive Servers)", box=box.SIMPLE, title_style="bold")
        geo_table.add_column("Host", style="cyan")
        geo_table.add_column("Location", style="green")
        geo_table.add_column("ISP", style="yellow")
        geo_table.add_column("Latency", justify="right")

        for c in sorted(geo_alive, key=lambda x: x.get("latency_ms", 9999) or 9999)[:15]:
            geo = c.get("geo", {})
            geo_table.add_row(
                c.get("host", ""),
                geo.get("country_code", "?"),
                geo.get("isp", "Unknown")[:18],
                f"{c.get('latency_ms', 0):.0f}ms" if c.get("latency_ms") else "---",
            )

    # Latency leaderboard
    latency_sorted = sorted(alive, key=lambda c: c.get("latency_ms", 9999) or 9999)
    if latency_sorted:
        lat_table = Table(title="Top 10 Fastest Servers", box=box.SIMPLE, title_style="bold")
        lat_table.add_column("#", justify="right", style="dim")
        lat_table.add_column("Protocol", style="cyan")
        lat_table.add_column("Host")
        lat_table.add_column("Location", style="green")
        lat_table.add_column("Latency", justify="right")

        for i, c in enumerate(latency_sorted[:10], 1):
            geo_str = c.get("geo_display", "")
            lat_table.add_row(
                str(i),
                c.get("type", "").upper(),
                c.get("host", ""),
                geo_str,
                f"[green]{c.get('latency_ms', 0):.1f}ms[/]" if c.get("latency_ms") else "[dim]---[/]",
            )

    # Display all tables
    console.print()
    console.print(proto_table)
    if geo_alive:
        console.print()
        console.print(geo_table)
    if latency_sorted:
        console.print()
        console.print(lat_table)

    # Export prompt
    console.print()
    if Confirm.ask("Export valid configs to file?", default=False):
        export_name = Prompt.ask("Output filename", default="valid_export.txt")
        exported = ConfigWriter.export_valid(alive)
        ConfigWriter.to_file(export_name, exported)
        console.print(f"[green]✓ Exported {len(exported)} configs to {export_name}[/]")


# ── Main Menu Loop ──────────────────────────────────────────────────────

def run_menu():
    """Launch the interactive Rich-based menu system."""
    console.clear()
    _print_banner()

    options = {
        "1": ("Harvest & Validate ALL Protocols", _option_1),
        "2": ("Harvest & Validate V2Ray Protocols ONLY", _option_2),
        "3": ("Advanced SNI/Host Matching", _option_3),
        "4": ("System Settings & Source Update", _option_4),
        "5": ("Exit", _option_5),
    }

    # Single event loop for the entire menu lifetime
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        while True:
            console.print(Panel(
                "\n".join(
                    f"  [{'bold cyan' if i == '5' else 'white'}][[{'green' if i == '1' else 'blue' if i == '2' else 'yellow' if i == '3' else 'magenta' if i == '4' else 'red'}]{i}[/{'bold cyan' if i == '5' else 'white'}]] {desc}"
                    for i, (desc, _) in options.items()
                ),
                title="[bold]Main Menu[/]",
                subtitle="Select an option [1-5]",
                box=box.ROUNDED,
                border_style="cyan",
            ))

            choice = Prompt.ask("", choices=list(options.keys()), default="5").strip()

            if choice == "5":
                loop.run_until_complete(_option_5())
                break

            try:
                if choice in options:
                    _, func = options[choice]
                    loop.run_until_complete(func())
            except KeyboardInterrupt:
                console.print("\n[yellow]⚠ Interrupted. Returning to menu...[/]")
            except Exception as e:
                console.print(f"\n[bold red]✗ Error: {e}[/]")
                if Confirm.ask("Show full traceback?", default=False):
                    import traceback
                    console.print(traceback.format_exc())

            console.print()
            # Automatically return to main menu after each action
            # User can pick [5] Exit to leave at any time
            console.clear()
            _print_banner()
    finally:
        loop.close()

    console.print("[bold cyan]Goodbye![/]")


if __name__ == "__main__":
    run_menu()
