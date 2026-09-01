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
    /// Deep diagnostics for a specific adapter (when it's not showing up)
    Probe {
        /// MAC address of adapter to probe
        mac: String,
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Health check: scan, detect degraded links, optionally restart adapters
    Check {
        #[arg(short, long)]
        interface: Option<String>,
        /// Minimum acceptable average speed in Mbps (default: 50)
        #[arg(long, default_value = "50")]
        min_speed: u16,
        /// Automatically restart degraded adapters
        #[arg(long)]
        restart: bool,
        /// Base cooldown between restarts of the same adapter, in minutes.
        /// Doubles after each restart that fails to recover the link (max 24h).
        #[arg(long, default_value = "60")]
        cooldown_mins: u64,
        /// State file for restart backoff tracking
        #[arg(long, default_value = "/var/lib/plcmon/check-state.json")]
        state_file: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
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
        Cmd::Probe { mac, interface } => cmd_probe(interface.as_deref(), &mac),
        Cmd::Check {
            interface,
            min_speed,
            restart,
            cooldown_mins,
            state_file,
            json,
        } => cmd_check(
            interface.as_deref(),
            min_speed,
            restart,
            cooldown_mins,
            &state_file,
            json,
        ),
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

fn cmd_probe(iface: Option<&str>, mac_str: &str) {
    let target = parse_mac_arg(mac_str);

    println!("Probing {target}...\n");

    // Step 1: Normal scan to establish context
    println!("  [1/5] Network scan...");
    let cap = match PlcCapture::open(iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let iface_str = cap.iface.clone();
    let host_mac = cap.mac;
    let mut scanner = Scanner::new(cap);
    let scan_result = match scanner.scan() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Scan error: {e}");
            std::process::exit(1);
        }
    };

    let found_in_scan = scan_result.devices.iter().any(|d| d.mac == target);
    let has_link = scan_result
        .links
        .iter()
        .any(|l| l.from == target || l.to == target);
    let local_mac = scan_result
        .devices
        .iter()
        .find(|d| d.is_local)
        .map(|d| d.mac);
    let online_remotes: Vec<_> = scan_result
        .devices
        .iter()
        .filter(|d| !d.is_local && d.mac != target)
        .map(|d| d.mac)
        .collect();

    if found_in_scan {
        println!("        Found in scan (has link: {has_link})");
    } else {
        println!("        NOT found in scan");
    }
    println!(
        "        Online devices: {} (+ local)",
        scan_result.devices.len() - 1
    );

    // Step 2: BCM NW_INFO from local adapter
    drop(scanner);
    let mut cap = match PlcCapture::open(Some(&iface_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reopening capture: {e}");
            std::process::exit(1);
        }
    };

    if let Some(local) = local_mac {
        println!("\n  [2/5] BCM NW_INFO from local adapter ({})...", local.short());
        let frame = plcmon::protocol::broadcom::build_nw_info_req(local, host_mac, 1);
        let _ = cap.send(&frame);
        let mut nw_info_macs = Vec::new();
        let _ = cap.recv_until(Duration::from_secs(3), |data| {
            if let Some((_src, payload)) =
                plcmon::protocol::broadcom::parse_nw_info_cnf(data)
            {
                nw_info_macs =
                    plcmon::protocol::broadcom::extract_macs_from_payload(&payload);
                println!("        Response: {} bytes, {} MAC candidates in payload",
                    payload.len(), nw_info_macs.len());
                let target_found = nw_info_macs.iter().any(|m| *m == target);
                if target_found {
                    println!("        ** Target {target} FOUND in NW_INFO **");
                } else {
                    println!("        Target NOT in NW_INFO topology");
                }
                for m in &nw_info_macs {
                    let marker = if *m == target { " <-- TARGET" } else { "" };
                    println!("          - {m}{marker}");
                }
                return false;
            }
            true
        });
        if nw_info_macs.is_empty() {
            println!("        No NW_INFO response (may not be supported)");
        }
    }

    // Step 3: NW_INFO from each online remote
    println!("\n  [3/5] Querying other online adapters...");
    for remote in &online_remotes {
        let frame = plcmon::protocol::broadcom::build_nw_info_req(*remote, host_mac, 2);
        let _ = cap.send(&frame);
        let mut found = false;
        let _ = cap.recv_until(Duration::from_secs(2), |data| {
            if let Some((_src, payload)) =
                plcmon::protocol::broadcom::parse_nw_info_cnf(data)
            {
                let macs =
                    plcmon::protocol::broadcom::extract_macs_from_payload(&payload);
                let target_found = macs.iter().any(|m| *m == target);
                println!("        {} — {} stations, target: {}",
                    remote.short(),
                    macs.len(),
                    if target_found { "FOUND" } else { "not found" }
                );
                found = true;
                return false;
            }
            true
        });
        if !found {
            println!("        {} — no response", remote.short());
        }
    }

    // Step 4: Direct unicast probe to target
    println!("\n  [4/5] Direct probe to {target}...");
    let frame = plcmon::protocol::broadcom::build_sta_info_req(target, host_mac, 3);
    let _ = cap.send(&frame);
    let mut direct_response = false;
    let _ = cap.recv_until(Duration::from_secs(3), |data| {
        if let Some(info) = plcmon::protocol::broadcom::parse_sta_info_cnf(data) {
            println!("        ** RESPONDED ** — chip: 0x{:08X}, uptime: {}s",
                info.chip_version, info.uptime_secs);
            direct_response = true;
            return false;
        }
        if let Some((_dst, src, etype, _)) = plcmon::protocol::parse_eth(data) {
            if src == target {
                println!("        Got frame from target (etype: {:02X}{:02X})", etype[0], etype[1]);
                direct_response = true;
                return false;
            }
        }
        true
    });
    if !direct_response {
        println!("        No response — adapter unreachable");
    }

    // Step 5: Passive listen
    println!("\n  [5/5] Passive listen for frames from {target} (5s)...");
    let mut frame_count = 0u32;
    let _ = cap.recv_until(Duration::from_secs(5), |data| {
        if let Some((_dst, src, _, _)) = plcmon::protocol::parse_eth(data) {
            if src == target {
                frame_count += 1;
                if frame_count == 1 {
                    println!("        ** Receiving frames! **");
                }
            }
        }
        true // keep listening
    });
    if frame_count > 0 {
        println!("        Captured {frame_count} frames from target");
    } else {
        println!("        No frames received — adapter silent on network");
    }

    // Summary
    println!("\n  ━━━ Diagnosis ━━━");
    if direct_response || frame_count > 0 {
        println!("  Adapter is reachable but not linking properly.");
        println!("  Try: cargo run -- restart {target}");
    } else if found_in_scan {
        println!("  Adapter appears in topology but isn't responding.");
        println!("  Try power-cycling it and re-pairing.");
    } else {
        println!("  Adapter is completely unreachable.");
        println!("  Possible causes:");
        println!("    - Powerline PHY hardware failure");
        println!("    - Lost network key (re-pair: press pair on working adapter,");
        println!("      then on this adapter within 2 minutes)");
        println!("    - Electrical isolation (different circuit breaker panel,");
        println!("      GFCI outlet, or surge protector blocking signal)");
        println!("    - Adapter plugged into power strip (must be direct wall outlet)");
        println!();
        println!("  Next steps:");
        println!("    1. Verify powerline LED (middle) is lit — if not, no PLC link");
        println!("    2. Move adapter next to a working one and try again");
        println!("    3. Factory reset: hold pair button 10+ seconds until LEDs flash");
        println!("       then re-pair with the network");
    }
    println!();
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

// -- Health check ----------------------------------------------------------

/// Exit codes for the check subcommand (cron/init-script friendly)
const EXIT_HEALTHY: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_DEGRADED: i32 = 2;

#[derive(serde::Serialize)]
struct CheckResult {
    healthy: bool,
    restarted: Vec<String>,
    in_backoff: Vec<String>,
    degraded: Vec<DegradedLink>,
    scan: plcmon::types::NetworkScan,
}

#[derive(serde::Serialize)]
struct DegradedLink {
    from: String,
    to: String,
    avg_mbps: u16,
    tx_signal: String,
    reason: String,
}

/// Per-adapter restart tracking, persisted between check runs so we don't
/// restart-loop an adapter whose link never recovers (physical-layer problem).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct CheckState {
    #[serde(default)]
    adapters: std::collections::HashMap<String, AdapterState>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy)]
struct AdapterState {
    /// Unix epoch seconds of the last restart we sent
    last_restart_epoch: i64,
    /// Restarts sent without the link ever returning to healthy
    consecutive_failures: u32,
}

const MAX_COOLDOWN_MINS: u64 = 24 * 60;

fn load_check_state(path: &str) -> CheckState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_check_state(path: &str, state: &CheckState) {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match serde_json::to_string_pretty(state) {
        Ok(s) => {
            if let Err(e) = std::fs::write(path, s) {
                eprintln!("WARN: could not persist restart state to {path}: {e}");
                eprintln!("      (restart backoff will not work across runs)");
            }
        }
        Err(e) => eprintln!("WARN: could not serialize restart state: {e}"),
    }
}

/// Cooldown for an adapter: base after the first failed restart, doubling for
/// each further failure (1h, 2h, 4h, ...), capped at 24h.
fn cooldown_secs(base_mins: u64, failures: u32) -> i64 {
    let mult = 1u64 << failures.saturating_sub(1).min(10);
    let mins = (base_mins.saturating_mul(mult)).min(MAX_COOLDOWN_MINS);
    (mins * 60) as i64
}

fn ts() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn cmd_check(
    iface: Option<&str>,
    min_speed: u16,
    do_restart: bool,
    cooldown_mins: u64,
    state_file: &str,
    json: bool,
) {
    let cap = match PlcCapture::open(iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(EXIT_ERROR);
        }
    };

    let iface_name = cap.iface.clone();
    let mut scanner = Scanner::new(cap);
    let scan = match scanner.scan() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Scan error: {e}");
            std::process::exit(EXIT_ERROR);
        }
    };

    if scan.devices.is_empty() {
        if json {
            println!(r#"{{"healthy":false,"error":"no devices found","restarted":[],"degraded":[]}}"#);
        } else {
            eprintln!("No powerline devices found on {iface_name}");
        }
        std::process::exit(EXIT_ERROR);
    }

    // Find degraded links
    let mut degraded = Vec::new();
    for link in &scan.links {
        let avg = ((link.tx_mbps as u32 + link.rx_mbps as u32) / 2) as u16;
        let is_siso = matches!(
            link.tx_signal.as_str(),
            "SISO" | "SISO2" | "SisoOnly"
        );

        let reason = if avg == 0 {
            Some("no link".to_string())
        } else if avg < min_speed && is_siso {
            Some(format!("SISO fallback at {avg} Mbps (min: {min_speed})"))
        } else if avg < min_speed {
            Some(format!("{avg} Mbps below minimum {min_speed}"))
        } else if is_siso && avg < min_speed * 2 {
            // SISO with moderate speed — could recover MIMO with restart
            Some(format!("SISO mode at {avg} Mbps — MIMO restart may help"))
        } else {
            None
        };

        if let Some(reason) = reason {
            degraded.push(DegradedLink {
                from: link.from.to_string(),
                to: link.to.to_string(),
                avg_mbps: avg,
                tx_signal: link.tx_signal.clone(),
                reason,
            });
        }
    }

    let healthy = degraded.is_empty();

    // Restart degraded remote adapters if requested (with backoff)
    let mut restarted = Vec::new();
    let mut in_backoff: Vec<String> = Vec::new();
    let mut state = load_check_state(state_file);
    let now_epoch = chrono::Local::now().timestamp();

    // Any adapter that is no longer degraded gets its failure history cleared.
    {
        let degraded_macs: std::collections::HashSet<String> = degraded
            .iter()
            .flat_map(|d| [d.from.clone(), d.to.clone()])
            .collect();
        state.adapters.retain(|mac, _| degraded_macs.contains(mac));
    }

    if do_restart && !degraded.is_empty() {
        // Collect unique remote MACs to restart (skip local adapter)
        let local_macs: std::collections::HashSet<_> = scan
            .devices
            .iter()
            .filter(|d| d.is_local)
            .map(|d| d.mac)
            .collect();

        let mut restart_candidates = std::collections::HashSet::new();
        for d in &degraded {
            // Parse the "to" MAC — restart the remote end of degraded links
            if let Some(mac) = plcmon::net::parse_mac(&d.to) {
                if !local_macs.contains(&mac) {
                    restart_candidates.insert(mac);
                }
            }
            if let Some(mac) = plcmon::net::parse_mac(&d.from) {
                if !local_macs.contains(&mac) {
                    restart_candidates.insert(mac);
                }
            }
        }

        // Apply backoff: skip adapters whose previous restart didn't stick.
        // Every restart disrupts devices behind the adapter, so an adapter
        // that stays degraded earns exponentially longer cooldowns.
        let mut restart_targets = Vec::new();
        for mac in restart_candidates {
            let key = mac.to_string();
            match state.adapters.get(&key) {
                Some(st) => {
                    let cd = cooldown_secs(cooldown_mins, st.consecutive_failures);
                    let elapsed = now_epoch - st.last_restart_epoch;
                    if elapsed < cd {
                        let next_in_mins = (cd - elapsed) / 60;
                        if !json {
                            eprintln!(
                                "[{}] {key} still degraded after {} restart(s) — in backoff, next attempt in ~{next_in_mins}m",
                                ts(),
                                st.consecutive_failures
                            );
                        }
                        in_backoff.push(key);
                    } else {
                        restart_targets.push(mac);
                    }
                }
                None => restart_targets.push(mac),
            }
        }

        if !json && !restart_targets.is_empty() {
            eprintln!(
                "[{}] Found {} degraded link(s), restarting {} adapter(s)...",
                ts(),
                degraded.len(),
                restart_targets.len()
            );
        }

        // Reopen capture for sending restart frames (only if something to do)
        if !restart_targets.is_empty() {
        let mut cap2 = match PlcCapture::open(Some(&iface_name)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Could not reopen capture for restart: {e}");
                std::process::exit(EXIT_ERROR);
            }
        };

        for target in &restart_targets {
            let frame =
                plcmon::protocol::broadcom::build_sta_restart_req(*target, cap2.mac, 0);
            if let Err(e) = cap2.send(&frame) {
                if !json {
                    eprintln!("Failed to restart {target}: {e}");
                }
                continue;
            }

            // Wait briefly for ack
            let mut acked = false;
            let _ = cap2.recv_until(Duration::from_secs(3), |data| {
                if let Some((_dst, _src, etype, eth_off)) =
                    plcmon::protocol::parse_eth(data)
                    && etype == plcmon::protocol::ETHERTYPE_MEDIAXTREAM
                    && let Some((mmtype, _seq, _off)) =
                        plcmon::protocol::parse_bcm_hdr(data, eth_off)
                    && mmtype == plcmon::protocol::broadcom::BCM_STA_RESTART_CNF
                {
                    acked = true;
                    return false;
                }
                true
            });

            if !json {
                if acked {
                    eprintln!("  Restarted {target} (acknowledged)");
                } else {
                    eprintln!("  Restarted {target} (no ack — may have rebooted immediately)");
                }
            }
            restarted.push(target.to_string());

            // Record the restart so the next run applies backoff if it didn't help
            let entry = state
                .adapters
                .entry(target.to_string())
                .or_insert(AdapterState {
                    last_restart_epoch: now_epoch,
                    consecutive_failures: 0,
                });
            entry.last_restart_epoch = now_epoch;
            entry.consecutive_failures += 1;
        }
        } // if !restart_targets.is_empty()
    }

    save_check_state(state_file, &state);

    // Output
    if json {
        let result = CheckResult {
            healthy,
            restarted,
            in_backoff,
            degraded,
            scan,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("json serialize")
        );
    } else if healthy {
        println!("[{}] OK — all links above {min_speed} Mbps", ts());
        for link in &scan.links {
            let avg = ((link.tx_mbps as u32 + link.rx_mbps as u32) / 2) as u16;
            let sig = if link.tx_signal.is_empty() {
                ""
            } else {
                &link.tx_signal
            };
            println!(
                "  {} → {}  {avg} Mbps avg  {sig}",
                link.from.short(),
                link.to.short()
            );
        }
    } else {
        println!(
            "[{}] DEGRADED — {} link(s) below threshold",
            ts(),
            degraded.len()
        );
        for d in &degraded {
            println!("  {} → {}  {} Mbps  {}", d.from, d.to, d.avg_mbps, d.reason);
        }
        if !restarted.is_empty() {
            println!("Restarted: {}", restarted.join(", "));
        }
        if !in_backoff.is_empty() {
            println!(
                "In backoff (restart withheld — repeated restarts haven't helped): {}",
                in_backoff.join(", ")
            );
        }
        if do_restart && restarted.is_empty() && in_backoff.is_empty() {
            println!("No remote adapters to restart.");
        }
    }

    std::process::exit(if healthy { EXIT_HEALTHY } else { EXIT_DEGRADED });
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
