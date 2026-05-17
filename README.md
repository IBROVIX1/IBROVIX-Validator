# 🚀 IBROVIX-Validator v2.0.0

**High-performance proxy validation, filtering, and interactive terminal UI tool for V2Ray (VMess/VLESS), Trojan, Shadowsocks, and SSH protocols.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)](https://github.com/IBROVIX1/ibrovix-validator)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## ✨ What's New in v2.0.0

| Feature | Description |
|---------|-------------|
| **🖥️ Interactive TUI** | Full terminal UI with keyboard navigation, real-time filtering, latency sorting, and export |
| **🌍 Geo-IP Lookup** | Automatic geolocation resolution for proxy servers (country, city, ISP) |
| **🔍 Deep SNI Injection Mapping** | Tries alternative SNI values when configured one fails — finds working CDN injections |
| **📊 Latency Sorting** | Sort results by latency (ascending/descending) with strict accuracy |
| **🎨 Textual UI Framework** | Rich, responsive terminal interface with search, stats, and color-coded status |

---

## 📋 Features

- **Multi-Protocol Support**: Parse VMess, VLESS, Trojan, Shadowsocks (SS), and SSH accounts
- **Interactive TUI**: Browse, filter, sort, and export configs in a rich terminal interface (`--tui`)
- **Format Validation**: Verify config structure integrity with detailed error reporting
- **Connectivity Probing**: Real TCP/TLS handshake tests with precise latency measurement
- **Trojan Protocol Test**: Send actual Trojan auth header and verify response
- **SSH Banner Detection**: Read and validate SSH server banners
- **Deep SNI/Host Injection**: Detect misconfigured SNI fields, try alternative injections, cache working mappings
- **Geo-IP Resolution**: Automatic location lookup (country, city, ISP) for proxy servers
- **Live Config Harvesting**: Fetch proxy configs from 15+ public sources automatically
- **Powerful Filtering**: Filter by protocol, status, latency, transport, TLS mode, name, host, and more
- **Flexible Output**: Table, JSON, plain text, or interactive TUI — with optional color
- **Async Concurrency**: High-performance async I/O with configurable worker limits
- **Export Valid Configs**: Save validated/alive/filtered configs to files

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/IBROVIX1/ibrovix-validator.git
cd ibrovix-validator

# Install core dependencies
pip install -r requirements.txt

# Install the package
pip install -e .

# Optional: install TUI support (recommended)
pip install textual

# Optional: install all extras
pip install -e ".[dev,geo,harvester]"
```

---

## 🚀 Usage

### Interactive TUI (New in v2.0.0 🎯)

```bash
# Launch the interactive terminal UI
ibrovix-validator configs.txt --tui

# Harvest + TUI — fetch live configs and browse interactively
ibrovix-validator --harvest --tui

# Keyboard shortcuts inside the TUI:
#   ↑/↓       — Navigate rows
#   /         — Search/filter configs
#   s         — Toggle latency sort order
#   g         — Toggle geo-IP column
#   e         — Export visible configs
#   h / ?     — Help screen
#   q / Esc   — Quit
```

### Parse configs

```bash
# From a file
ibrovix-validator configs.txt --mode parse

# From stdin
cat configs.txt | ibrovix-validator --mode parse

# Show as JSON
ibrovix-validator configs.txt --mode parse -o json
```

### Check format validity

```bash
ibrovix-validator configs.txt --mode check
ibrovix-validator configs.txt --mode check --stats
```

### Full connectivity probe

```bash
# Probe all servers (TCP + TLS + protocol handshake)
ibrovix-validator configs.txt --mode probe

# Show only alive servers
ibrovix-validator configs.txt --mode probe --alive

# Fastest servers (latency sort)
ibrovix-validator configs.txt --mode probe --alive --max-latency 200
```

### Filtering

```bash
# Filter by protocol
ibrovix-validator configs.txt --mode filter --protocol vmess vless

# Fastest servers
ibrovix-validator configs.txt --mode probe --alive --max-latency 100 -o table

# Filter by transport type
ibrovix-validator configs.txt --mode parse --transport ws grpc

# Search by name/host
ibrovix-validator configs.txt --mode parse --search "Japan"

# Export valid configs
ibrovix-validator configs.txt --mode probe --alive --export valid-configs.txt
```

### SNI diagnostics & injection mapping (New in v2.0.0)

```bash
# Check SNI compatibility
ibrovix-validator configs.txt --mode probe --stats

# Deep SNI injection mapping is automatic — tries alternative SNIs
# when the configured one doesn't match the server certificate
```

### Live harvesting

```bash
# Auto-harvest from default sources (no input file needed)
ibrovix-validator --mode probe --alive

# Harvest from custom URLs
ibrovix-validator --source https://example.com/config.txt --mode check

# Harvest with defaults + custom sources
ibrovix-validator --harvest --source https://example.com/config.txt --default-sources --mode probe
```

---

## 📊 Input Formats

The tool automatically detects and parses the following formats:

| Protocol | Format Example |
|----------|---------------|
| **VMess** | `vmess://eyJ2IjoiMiIsInBzIjoi...` (Base64 JSON) |
| **VLESS** | `vless://uuid@host:port?encryption=none&security=tls&type=tcp#name` |
| **Trojan** | `trojan://password@host:port?security=tls&sni=example.com#name` |
| **Trojan (Base64)** | Base64-encoded trojan:// URL |
| **Shadowsocks** | `ss://BASE64(method:password)@host:port#name` |
| **SSH** | `ssh://user@host:port` or `host:port:user:password` |

---

## 🏗️ Project Structure

```
ibrovix-validator/
├── src/
│   └── ibrovix_validator/
│       ├── __init__.py       # Package info (v2.0.0)
│       ├── cli.py            # CLI entry point
│       ├── config.py         # Configuration
│       ├── tui.py            # 🆕 Interactive TUI (Textual)
│       ├── parsers/          # Protocol parsers
│       │   ├── vmess.py      # VMess parser
│       │   ├── vless.py      # VLESS parser
│       │   ├── trojan.py     # Trojan parser
│       │   ├── ssh.py        # SSH parser
│       │   └── ss.py         # Shadowsocks parser
│       ├── validators/       # Validation modules
│       │   ├── format.py     # Format validation
│       │   ├── handshake.py  # Connectivity probes
│       │   └── sni_check.py  # 🆕 Deep SNI injection mapping
│       ├── filters/          # Filter engine
│       │   └── engine.py     # 🆕 Latency sorting
│       └── utils/            # Utilities
│           ├── io.py         # File I/O
│           ├── output.py     # Display formatting
│           └── geo.py        # 🆕 Geo-IP lookup
├── tests/                    # 53+ passing tests
├── examples/                 # Example configs
├── setup.py                  # Package setup
└── requirements.txt          # Dependencies
```

---

## 🔧 Requirements

- Python 3.9+
- `aiohttp` (optional, for Geo-IP)
- `httpx` (optional, for live harvester)
- `textual` (optional, for Interactive TUI)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>IBROVIX-Validator v2.0.0</b> — <i>Ultimate System Architecture Upgrade</i><br>
  <sub>Made with ❤️ by IBROVIX</sub>
</p>
