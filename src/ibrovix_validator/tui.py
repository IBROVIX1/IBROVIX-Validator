"""IBROVIX-Validator Interactive TUI — terminal user interface for proxy validation.

Built with Textual framework for rich, interactive terminal experience.

Features:
  - Real-time config table with keyboard navigation
  - Live filtering and search
  - Latency-based sorting (ascending/descending)
  - Geo-IP location display
  - SNI injection mapping viewer
  - Statistics panel
  - Config export
  - Color-coded status indicators

Keyboard shortcuts:
  ↑/↓        — Navigate rows
  PgUp/PgDn  — Page up/down
  Home/End   — First/last row
  /          — Focus search bar
  f          — Toggle filter mode
  s          — Toggle sort order (by latency)
  g          — Toggle geo-IP display
  e          — Export visible configs
  r          — Refresh / re-sort
  h / ?      — Show help
  q / Esc    — Quit
"""

import asyncio
import sys
from typing import Optional, ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    DataTable, Header, Footer, Input, Static,
    Button,
)
from textual.reactive import reactive
from textual.widget import Widget
from rich.text import Text
from rich.table import Table as RichTable
from rich.panel import Panel
from rich.layout import Layout
from rich.columns import Columns

from . import __version__
from .utils.geo import GeoIPResolver, GeoLocation
from .filters.engine import FilterEngine


# ── Rich renderables for TUI ────────────────────────────────────────────────

def _status_cell(alive: Optional[bool]) -> str:
    """Rich-formatted status cell."""
    if alive is True:
        return "[bold green]● ALIVE[/]"
    elif alive is False:
        return "[bold red]● DEAD[/]"
    return "[bold yellow]● ?[/]"

def _latency_cell(ms: Optional[float]) -> str:
    """Rich-formatted latency cell."""
    if ms is None:
        return "[dim]--- ms[/]"
    if ms < 100:
        return f"[bold green]{ms:.1f} ms[/]"
    elif ms < 300:
        return f"[bold yellow]{ms:.1f} ms[/]"
    return f"[bold red]{ms:.1f} ms[/]"

def _proto_cell(proto: str) -> str:
    """Rich-formatted protocol cell."""
    colors = {
        "vmess": "magenta",
        "vless": "blue",
        "trojan": "red",
        "ssh": "green",
        "ss": "cyan",
    }
    color = colors.get(proto, "white")
    return f"[bold {color}]{proto.upper():<7}[/]"


# ── Help Screen ────────────────────────────────────────────────────────────

class HelpScreen(ModalScreen):
    """Keyboard shortcuts help overlay."""

    BINDINGS = [
        Binding("escape, h, q", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold yellow]IBROVIX-Validator TUI — Keyboard Shortcuts[/]", id="help-title"),
            Static(""),
            Static("[bold]Navigation[/]"),
            Static("  ↑ / ↓         — Move up/down one row"),
            Static("  PgUp / PgDn   — Page up/down"),
            Static("  Home / End    — Jump to first/last row"),
            Static(""),
            Static("[bold]Actions[/]"),
            Static("  /             — Focus search/filter bar"),
            Static("  f             — Toggle filter mode"),
            Static("  s             — Toggle sort by latency"),
            Static("  g             — Toggle geo-IP column"),
            Static("  e             — Export visible configs to file"),
            Static("  r             — Refresh / re-sort"),
            Static("  h / ?         — Show this help screen"),
            Static("  q / Esc       — Quit"),
            Static(""),
            Static("[dim]Press any key to close[/]"),
            id="help-container",
        )

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-container {
        width: 50;
        height: auto;
        padding: 1 2;
        border: thick $primary;
        background: $surface;
    }
    #help-title {
        text-align: center;
    }
    """


# ── Export Screen ──────────────────────────────────────────────────────────

class ExportScreen(ModalScreen):
    """Export configs to file."""

    def __init__(self, configs: list[dict], output_format: str = "table"):
        super().__init__()
        self.configs = configs
        self.output_format = output_format

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold yellow]Export Configs[/]", id="export-title"),
            Input(placeholder="Output filename (e.g., export.txt)", id="export-input"),
            Horizontal(
                Button("Export", variant="primary", id="export-btn"),
                Button("Cancel", variant="default", id="cancel-btn"),
            ),
            id="export-container",
        )

    DEFAULT_CSS = """
    ExportScreen {
        align: center middle;
    }
    #export-container {
        width: 50;
        height: auto;
        padding: 1 2;
        border: thick $primary;
        background: $surface;
    }
    #export-title {
        text-align: center;
    }
    Horizontal {
        align: center middle;
        margin-top: 1;
    }
    Button {
        margin: 0 1;
    }
    """

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "export-btn":
            filename = self.query_one("#export-input", Input).value
            if filename:
                from .utils.io import ConfigWriter
                exported = ConfigWriter.export_valid(self.configs)
                ConfigWriter.to_file(filename, exported)
                self.dismiss()
        elif event.button.id == "cancel-btn":
            self.dismiss()


# ── Main TUI App ──────────────────────────────────────────────────────────

class ValidatorTUI(App):
    """Interactive TUI for IBROVIX-Validator."""

    TITLE = f"IBROVIX-Validator v{__version__}"
    SUB_TITLE = "Interactive Proxy Validation Terminal"

    BINDINGS = [
        Binding("q, escape", "quit", "Quit"),
        Binding("slash", "focus_search", "Search"),
        Binding("f", "toggle_filter", "Filter"),
        Binding("s", "toggle_sort", "Sort"),
        Binding("g", "toggle_geo", "Geo-IP"),
        Binding("e", "export", "Export"),
        Binding("r", "refresh", "Refresh"),
        Binding("h, question_mark", "show_help", "Help"),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
        Binding("pageup", "page_up", "PgUp", show=False),
        Binding("pagedown", "page_down", "PgDn", show=False),
        Binding("home", "first_row", "Home", show=False),
        Binding("end", "last_row", "End", show=False),
    ]

    # Reactive state
    sort_ascending: reactive[bool] = reactive(True)
    show_geo: reactive[bool] = reactive(False)
    filter_active: reactive[bool] = reactive(False)
    filter_text: reactive[str] = reactive("")

    def __init__(
        self,
        configs: list[dict],
        geo_resolver: Optional[GeoIPResolver] = None,
    ):
        super().__init__()
        self.all_configs = configs
        self.filtered_configs = list(configs)
        self.geo_resolver = geo_resolver or GeoIPResolver()
        self.geo_cache: dict[str, GeoLocation] = {}
        self._current_row = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            Horizontal(
                # Search/filter bar
                Input(
                    placeholder="🔍 Filter configs (protocol:host:name)...",
                    id="search-input",
                    classes="hidden",
                ),
                id="search-bar",
            ),
            # Stats bar
            Static(id="stats-bar"),
            # Main data table
            DataTable(id="config-table"),
        )
        yield Footer()

    DEFAULT_CSS = """
    #search-bar {
        height: 3;
        margin: 0 1;
    }
    #search-input {
        width: 100%;
    }
    #search-input.hidden {
        display: none;
    }
    #stats-bar {
        height: 1;
        margin: 0 1;
        text-style: bold;
    }
    #config-table {
        height: 1fr;
        margin: 0 1;
    }
    DataTable {
        border: solid $primary;
    }
    DataTable > .datatable--header {
        text-style: bold;
        background: $primary-background;
    }
    """

    def on_mount(self) -> None:
        """Set up the table when the app starts."""
        table = self.query_one("#config-table", DataTable)
        columns = [
            "#", "Protocol", "Name", "Host", "Port",
            "Status", "Latency", "Transport", "TLS", "SNI",
        ]
        if self.show_geo:
            columns.append("Location")

        table.add_columns(*columns)
        self._populate_table()
        table.cursor_type = "row"
        table.zebra_stripes = True

        # Update stats
        self._update_stats()

    def _populate_table(self) -> None:
        """Fill the table with config data."""
        table = self.query_one("#config-table", DataTable)
        table.clear()

        if not self.filtered_configs:
            table.add_row(*([""] * len(table.columns)))
            return

        show_geo = self.show_geo

        for i, cfg in enumerate(self.filtered_configs, 1):
            proto = cfg.get("type", "?")
            name = (cfg.get("name", "") or "")[:24]
            host = cfg.get("host", "")[:22]
            port = str(cfg.get("port", 0))
            alive = cfg.get("alive")
            latency = cfg.get("latency_ms")
            net = cfg.get("net", "?")
            tls = cfg.get("tls", "?")
            sni = (cfg.get("sni") or "")[:20]

            status = _status_cell(alive)
            lat_str = _latency_cell(latency)
            proto_str = _proto_cell(proto)

            row = [
                str(i), proto_str, name, host, port,
                status, lat_str, net, tls, sni,
            ]

            if show_geo:
                geo_str = self._get_geo_str(host)
                row.append(geo_str)

            table.add_row(*row, key=str(i))

    def _get_geo_str(self, host: str) -> str:
        """Get geo-location string for a host, from cache or async."""
        ip = host.split(":")[0]
        cached = self.geo_cache.get(ip)
        if cached:
            return cached.short_display
        # Schedule async lookup
        asyncio.ensure_future(self._resolve_geo(ip))
        return "[dim]...[/]"

    async def _resolve_geo(self, ip: str) -> None:
        """Resolve geo-IP asynchronously and update table."""
        loc = await self.geo_resolver.lookup(ip)
        self.geo_cache[ip] = loc
        # Refresh the display
        self._populate_table()

    def _update_stats(self) -> None:
        """Update the stats bar."""
        total = len(self.all_configs)
        shown = len(self.filtered_configs)
        alive = sum(1 for c in self.filtered_configs if c.get("alive") is True)
        dead = sum(1 for c in self.filtered_configs if c.get("alive") is False)

        stats = (
            f"[bold]Total: {total}[/]  "
            f"[bold]Shown: {shown}[/]  "
            f"[bold green]Alive: {alive}[/]  "
            f"[bold red]Dead: {dead}[/]  "
            f"[bold]Sort: {'↑' if self.sort_ascending else '↓'} latency[/]"
        )
        if self.filter_active and self.filter_text:
            stats += f"  [bold yellow]Filter: '{self.filter_text}'[/]"

        self.query_one("#stats-bar", Static).update(stats)

    def _apply_filter_and_sort(self) -> None:
        """Re-filter and re-sort configs based on current state."""
        configs = list(self.all_configs)

        # Apply text filter
        if self.filter_active and self.filter_text:
            ft = self.filter_text.lower()
            engine = FilterEngine(configs)
            engine.by_protocol("vmess", "vless", "trojan", "ssh", "ss")
            # Simple text search
            configs = [
                c for c in configs
                if ft in (c.get("name", "") or "").lower()
                or ft in (c.get("host", "") or "").lower()
                or ft in (c.get("type", "") or "").lower()
            ]

        # Apply latency sort
        engine = FilterEngine(configs)
        engine.sort_by_latency(ascending=self.sort_ascending)
        self.filtered_configs = engine.apply()

        self._populate_table()
        self._update_stats()

    # ── Action Handlers ──────────────────────────────────────────────────

    def action_focus_search(self) -> None:
        """Focus the search/filter input."""
        search_input = self.query_one("#search-input", Input)
        search_input.remove_class("hidden")
        search_input.focus()

    def action_toggle_filter(self) -> None:
        """Toggle filter mode."""
        self.filter_active = not self.filter_active
        if not self.filter_active:
            self.filter_text = ""
            self.query_one("#search-input", Input).value = ""
        self._apply_filter_and_sort()

    def action_toggle_sort(self) -> None:
        """Toggle sort direction."""
        self.sort_ascending = not self.sort_ascending
        self._apply_filter_and_sort()

    def action_toggle_geo(self) -> None:
        """Toggle geo-IP column."""
        self.show_geo = not self.show_geo
        self._populate_table()

    def action_export(self) -> None:
        """Open export dialog."""
        self.push_screen(ExportScreen(self.filtered_configs))

    def action_refresh(self) -> None:
        """Refresh the display."""
        self._apply_filter_and_sort()

    def action_show_help(self) -> None:
        """Show help overlay."""
        self.push_screen(HelpScreen())

    def action_cursor_up(self) -> None:
        """Move cursor up."""
        table = self.query_one("#config-table", DataTable)
        if table.cursor_row is not None and table.cursor_row > 0:
            table.action_cursor_up()

    def action_cursor_down(self) -> None:
        """Move cursor down."""
        table = self.query_one("#config-table", DataTable)
        if table.cursor_row is not None:
            table.action_cursor_down()

    def action_page_up(self) -> None:
        """Page up."""
        table = self.query_one("#config-table", DataTable)
        for _ in range(10):
            if table.cursor_row is not None and table.cursor_row > 0:
                table.action_cursor_up()

    def action_page_down(self) -> None:
        """Page down."""
        table = self.query_one("#config-table", DataTable)
        for _ in range(10):
            table.action_cursor_down()

    def action_first_row(self) -> None:
        """Jump to first row."""
        table = self.query_one("#config-table", DataTable)
        table.cursor_row = 0 if table.row_count > 0 else None

    def action_last_row(self) -> None:
        """Jump to last row."""
        table = self.query_one("#config-table", DataTable)
        table.cursor_row = max(0, table.row_count - 1) if table.row_count > 0 else None

    # ── Event Handlers ──────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle search input submission."""
        if event.input.id == "search-input":
            self.filter_active = True
            self.filter_text = event.input.value
            self._apply_filter_and_sort()
            event.input.add_class("hidden")

    def on_blur(self) -> None:
        """Handle focus loss on search input."""
        try:
            search_input = self.query_one("#search-input", Input)
            if not search_input.value:
                search_input.add_class("hidden")
        except Exception:
            pass


# ── TUI Runner ────────────────────────────────────────────────────────────

def run_tui(configs: list[dict]) -> None:
    """Run the interactive TUI with the given configs.

    Args:
        configs: List of parsed proxy config dicts.
    """
    app = ValidatorTUI(configs=configs)
    app.run()


def run_tui_async(configs: list[dict]) -> None:
    """Run the TUI asynchronously."""
    app = ValidatorTUI(configs=configs)
    app.run()
