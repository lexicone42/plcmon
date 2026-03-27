# plcmon

A Rust CLI tool for monitoring HomePlug AV powerline networks. Speaks the protocol directly — no dependency on vendor software.

## Features

- **Network discovery** via standard HomePlug AV CC_DISCOVER_LIST
- **Link speed monitoring** with per-link TX/RX rates and MIMO/SISO detection
- **Live TUI** with speed matrix, sparkline history, and real-time diagnostics
- **Adapter restart** to force PHY renegotiation when links get stuck in degraded states
- **JSON output** for scripting and integration
- **Cross-platform** — macOS and Linux

## Supported Chipsets

| Chipset | Discovery | Link Speeds | Restart | Protocol |
|---------|-----------|-------------|---------|----------|
| Broadcom (BCM60xxx) | Yes | Yes (Mediaxtream 0x8912) | Yes | Fully implemented |
| Qualcomm (QCA7xxx, INT6xxx) | Yes | Stubbed (VS_NW_INFO 0xA038) | No | Ready for testing |

Tested with TP-Link TL-PA9020P (AV2000 Broadcom MIMO) adapters. Should work with any HomePlug AV/AV2 device — contributions welcome for Qualcomm testing.

## Install

Requires Rust and libpcap:

```bash
# macOS — libpcap is included with the system
cargo install --path .

# Linux — install libpcap first
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel  # Fedora
cargo install --path .
```

### Non-root Setup

Raw packet capture requires elevated privileges. Run the setup command once to configure non-root access:

```bash
# macOS — creates access_bpf group + LaunchDaemon
sudo plcmon setup

# Linux — grants CAP_NET_RAW on the binary
sudo plcmon setup
```

You may need to log out and back in for group membership to take effect.

## Usage

```bash
# One-shot scan with diagnostics
plcmon scan

# JSON output (pipe to jq, log to file, etc.)
plcmon scan --json

# Live TUI monitor (scan every 30s)
plcmon monitor

# Faster scan interval
plcmon monitor -n 10

# Restart a specific adapter (forces PHY renegotiation)
plcmon restart D4:6E:0E:F6:96:BE

# Specify network interface
plcmon scan -i en1
```

### TUI Keybindings

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit |
| `r` | Immediate rescan |
| `d` | Toggle diagnostics panel |
| `Tab` / `n` | Cycle sparkline link |

## Diagnostics

plcmon detects common powerline issues:

- **SISO fallback** — adapter stuck in single-stream mode; restart usually recovers MIMO
- **Asymmetric links** — noise source near one adapter
- **Signal flapping** — MIMO/SISO oscillation indicating an unstable link
- **Cross-phase attenuation** — very low speeds from adapters on different electrical phases

## Architecture

```
src/
  protocol/
    mod.rs         — MacAddr, frame builders/parsers, EtherType constants
    standard.rs    — CC_DISCOVER_LIST, CM_NW_STATS (cross-vendor)
    broadcom.rs    — Mediaxtream vendor messages (EtherType 0x8912)
    qualcomm.rs    — QCA vendor messages (EtherType 0x88E1 + OUI)
  net.rs           — pcap capture, interface discovery, BPF permissions
  scanner.rs       — scan orchestration (discover → query stats → build results)
  tui.rs           — ratatui TUI with diagnostics and sparklines
  setup.rs         — non-root permission setup (macOS + Linux)
  types.rs         — NetworkScan, Device, Link result types
  main.rs          — CLI (clap)
```

The scanner produces `NetworkScan` structs serializable to JSON, making it straightforward to add a web UI frontend over WebSocket in the future.

## Protocol Notes

HomePlug AV uses Ethernet frames with EtherType `0x88E1`. Broadcom devices additionally use a proprietary **Mediaxtream** protocol on EtherType `0x8912` for vendor-specific management messages. Both must be handled to get full functionality across chipsets.

Key references:
- [HomePlug AV Specification](https://docbox.etsi.org/Reference/homeplug_av21/homeplug_av21_specification_final_public.pdf)
- [open-plc-utils](https://github.com/qca/open-plc-utils) — Qualcomm's open-source HomePlug toolkit
- [pla-util](https://github.com/serock/pla-util) — Broadcom Mediaxtream reverse engineering (Ada)
- [mediaxtream-dissector](https://github.com/serock/mediaxtream-dissector) — Wireshark dissector for Broadcom protocol

## License

MIT
