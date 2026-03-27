use clap::{Parser, Subcommand};
use plcmon::net::PlcCapture;
use plcmon::scanner::Scanner;
use plcmon::tui::App;
use std::sync::mpsc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "plcmon", about = "TP-Link Powerline Network Monitor")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Live TUI monitor
    Monitor {
        /// Network interface (auto-detect if omitted)
        #[arg(short, long)]
        interface: Option<String>,
        /// Scan interval in seconds
        #[arg(short = 'n', long, default_value = "30")]
        interval: u64,
    },
    /// One-shot scan, print results
    Scan {
        #[arg(short, long)]
        interface: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Restart a powerline adapter (forces PHY re-negotiation)
    Restart {
        /// MAC address of adapter to restart (use "scan" to find MACs)
        mac: String,
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Set up BPF permissions for non-root capture (macOS)
    Setup,
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Monitor {
            interface,
            interval,
        } => cmd_monitor(interface.as_deref(), interval),
        Cmd::Scan { interface, json } => cmd_scan(interface.as_deref(), json),
        Cmd::Restart { mac, interface } => cmd_restart(interface.as_deref(), &mac),
        Cmd::Setup => plcmon::setup::run_setup(),
    }
}

fn cmd_monitor(iface: Option<&str>, interval_secs: u64) {
    let cap = match PlcCapture::open(iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let iface_name = cap.iface.clone();
    eprintln!("Opening {iface_name}...");

    let (scan_tx, scan_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel::<plcmon::tui::TuiCommand>();
    let interval = Duration::from_secs(interval_secs);

    // Scanner thread
    std::thread::spawn(move || {
        let mut scanner = Scanner::new(cap);
        loop {
            match scanner.scan() {
                Ok(result) => {
                    if scan_tx.send(result).is_err() {
                        break; // TUI exited
                    }
                }
                Err(e) => eprintln!("Scan error: {e}"),
            }
            // Wait for interval, but wake early if TUI requests a rescan
            match cmd_rx.recv_timeout(interval) {
                Ok(plcmon::tui::TuiCommand::Rescan) => {} // immediate rescan
                Err(mpsc::RecvTimeoutError::Timeout) => {} // interval elapsed
                Err(mpsc::RecvTimeoutError::Disconnected) => return, // TUI exited
            }
        }
    });

    // Run TUI on main thread
    let app = App::new(scan_rx).with_cmd_tx(cmd_tx);
    if let Err(e) = app.run() {
        eprintln!("TUI error: {e}");
        std::process::exit(1);
    }
}

fn cmd_scan(iface: Option<&str>, json: bool) {
    let cap = match PlcCapture::open(iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mut scanner = Scanner::new(cap);
    match scanner.scan() {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("json serialize")
                );
            } else {
                print_scan(&result);
            }
        }
        Err(e) => {
            eprintln!("Scan error: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_restart(iface: Option<&str>, mac_str: &str) {
    let target = parse_mac_arg(mac_str);
    let cap = match PlcCapture::open(iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    println!("Sending restart to {target}...");
    let mut cap = cap;
    let seq = 0u8;
    let frame = plcmon::protocol::broadcom::build_sta_restart_req(target, cap.mac, seq);
    if let Err(e) = cap.send(&frame) {
        eprintln!("Send error: {e}");
        std::process::exit(1);
    }

    // Wait for confirmation
    let mut got_response = false;
    let _ = cap.recv_until(Duration::from_secs(5), |data| {
        if let Some((_dst, src, etype, eth_off)) = plcmon::protocol::parse_eth(data)
            && etype == plcmon::protocol::ETHERTYPE_MEDIAXTREAM
            && let Some((mmtype, _seq, _off)) = plcmon::protocol::parse_bcm_hdr(data, eth_off)
            && mmtype == plcmon::protocol::broadcom::BCM_STA_RESTART_CNF
        {
            println!("Adapter {src} acknowledged restart.");
            got_response = true;
            return false;
        }
        true
    });

    if !got_response {
        println!("No confirmation received (adapter may have restarted immediately).");
    }

    println!("Waiting 15s for adapter to come back up...");
    std::thread::sleep(Duration::from_secs(15));

    // Re-scan to show new link speeds
    println!("Re-scanning...");
    let cap2 = match PlcCapture::open(iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not reopen capture: {e}");
            return;
        }
    };
    let mut scanner = Scanner::new(cap2);
    match scanner.scan() {
        Ok(result) => print_scan(&result),
        Err(e) => eprintln!("Re-scan error: {e}"),
    }
}

fn parse_mac_arg(s: &str) -> plcmon::protocol::MacAddr {
    // Accept formats: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    let normalized = s.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        eprintln!("Invalid MAC address: {s}");
        eprintln!("Expected format: AA:BB:CC:DD:EE:FF");
        std::process::exit(1);
    }
    let mut addr = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        addr[i] = match u8::from_str_radix(p, 16) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Invalid hex in MAC address: {p}");
                std::process::exit(1);
            }
        };
    }
    plcmon::protocol::MacAddr(addr)
}

fn print_scan(scan: &plcmon::types::NetworkScan) {
    println!(
        "\nPowerline Network — {} — {}\n",
        scan.interface,
        scan.timestamp.format("%Y-%m-%d %H:%M:%S")
    );

    // Devices
    println!("  {:<18} {:<14} {:<5} Status", "MAC", "Model", "Chip");
    println!("  {:-<18} {:-<14} {:-<5} {:-<10}", "", "", "", "");
    for d in &scan.devices {
        let status = if d.is_local { "Local" } else { "Online" };
        let model = if d.model.is_empty() { "—" } else { &d.model };
        println!("  {:<18} {:<14} {:<5} {status}", d.mac, model, d.chipset);
    }

    // Speed matrix
    let macs: Vec<_> = scan.devices.iter().map(|d| d.mac).collect();
    let labels: Vec<_> = macs.iter().map(|m| m.short()).collect();
    let matrix = scan.speed_matrix();

    println!("\n  Link Speeds (Mbps):");
    print!("  {:>10}", "");
    for l in &labels {
        print!(" {l:>8}");
    }
    println!();

    for (i, from) in macs.iter().enumerate() {
        print!("  {:>10}", labels[i]);
        for to in &macs {
            if from == to {
                print!(" {:>8}", "—");
            } else if let Some(&spd) = matrix.get(&(*from, *to)) {
                print!(" {spd:>8}");
            } else {
                print!(" {:>8}", "?");
            }
        }
        println!();
    }

    // Link diagnostics
    if !scan.links.is_empty() {
        println!("\n  Link Diagnostics:");
        println!(
            "  {:<14} {:<14} {:>6} {:>6}  {:<6} {:<6} Assessment",
            "From", "To", "TX", "RX", "TxSig", "RxSig"
        );
        println!(
            "  {:-<14} {:-<14} {:->6} {:->6}  {:-<6} {:-<6} {:-<20}",
            "", "", "", "", "", "", ""
        );
        for l in &scan.links {
            let assessment = assess_link(l.tx_mbps, l.rx_mbps, &l.tx_signal);
            println!(
                "  {:<14} {:<14} {:>5}↑ {:>5}↓  {:<6} {:<6} {}",
                l.from.short(),
                l.to.short(),
                l.tx_mbps,
                l.rx_mbps,
                if l.tx_signal.is_empty() {
                    "—"
                } else {
                    &l.tx_signal
                },
                if l.rx_signal.is_empty() {
                    "—"
                } else {
                    &l.rx_signal
                },
                assessment
            );
        }
    }
    println!();
}

fn assess_link(tx: u16, rx: u16, _signal: &str) -> &'static str {
    let avg = ((tx as u32 + rx as u32) / 2) as u16;
    match avg {
        0..=20 => "!! POOR — different phase or heavy noise",
        21..=80 => "! WEAK — likely cross-phase or noisy circuit",
        81..=200 => "OK — moderate signal",
        201..=400 => "GOOD",
        _ => "EXCELLENT",
    }
}
