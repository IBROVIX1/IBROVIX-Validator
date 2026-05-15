# IBROVIX-Validator

High-performance validation and filtering tool for V2Ray, SSH, and Trojan protocols.

## Features

- **Multi-Protocol Support**: Parse VMess, VLESS, Trojan (Base64/URL), and SSH accounts
- **Format Validation**: Verify config structure integrity
- **Connectivity Probing**: Real TCP/TLS handshake tests with latency measurement
- **Trojan Protocol Test**: Send actual Trojan auth header and verify response
- **SSH Banner Detection**: Read and validate SSH server banners
- **SNI/Host Compatibility**: Detect misconfigured SNI fields and "injected bug" mismatches
- **Powerful Filtering**: Filter by protocol, alive status, latency, transport, TLS mode, and more
- **Flexible Output**: Table, JSON, or plain text formats with optional color
- **Async Concurrency**: High-performance async I/O with configurable worker limits
- **Export Valid Configs**: Save validated/alive configs to files

## Installation

```bash
# Clone the repository
git clone https://github.com/IBROVIX1/ibrovix-validator.git
cd ibrovix-validator

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

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

# Filter by max latency (ms)
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

### TLS/SNI diagnostics

```bash
# Check SNI compatibility
ibrovix-validator configs.txt --mode probe --no-color --stats

# Skip probes you don't need
ibrovix-validator configs.txt --mode probe --no-tls-probe --no-ssh-banner
```

## Input Formats

The tool automatically detects and parses the following formats:

| Protocol | Format Example |
|----------|---------------|
| **VMess** | `vmess://eyJ2IjoiMiIsInBzIjoi...` (Base64 JSON) |
| **VLESS** | `vless://uuid@host:port?encryption=none&security=tls&type=tcp#name` |
| **Trojan** | `trojan://password@host:port?security=tls&sni=example.com#name` |
| **Trojan (Base64)** | Base64-encoded trojan:// URL |
| **SSH** | `ssh://user@host:port` or `host:port:user:password` |

## Project Structure

```
ibrovix-validator/
├── src/
│   └── ibrovix_validator/
│       ├── __init__.py       # Package info
│       ├── cli.py            # CLI entry point
│       ├── config.py         # Configuration
│       ├── parsers/          # Protocol parsers
│       │   ├── vmess.py      # VMess parser
│       │   ├── vless.py      # VLESS parser
│       │   ├── trojan.py     # Trojan parser
│       │   └── ssh.py        # SSH parser
│       ├── validators/       # Validation modules
│       │   ├── format.py     # Format validation
│       │   ├── handshake.py  # Connectivity probes
│       │   └── sni_check.py  # SNI/Host checks
│       ├── filters/          # Filter engine
│       │   └── engine.py     # Filter logic
│       └── utils/            # Utilities
│           ├── io.py         # File I/O
│           └── output.py     # Display formatting
├── tests/                    # Test suite
├── examples/                 # Example configs
├── setup.py                  # Package setup
└── requirements.txt          # Dependencies
```

## Requirements

- Python 3.9+
- aiohttp (optional, for future geolocation support)

## License

MIT License — see LICENSE file for details.
