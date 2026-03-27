use crate::protocol::MacAddr;
#[cfg(target_os = "linux")]
use libc;
use pcap::{Active, Capture, Device};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("pcap: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("no suitable network interface found (need wired Ethernet)")]
    NoInterface,
    #[error("{0}")]
    PermissionDenied(String),
    #[error("interface {0} has no MAC address")]
    NoMacAddr(String),
}

pub struct PlcCapture {
    cap: Capture<Active>,
    pub iface: String,
    pub mac: MacAddr,
}

impl PlcCapture {
    /// Open a capture handle on the given interface (or auto-detect).
    pub fn open(iface: Option<&str>) -> Result<Self, NetError> {
        check_capture_permissions()?;

        let name = match iface {
            Some(n) => n.to_string(),
            None => find_ethernet_iface()?,
        };

        let mac = get_mac(&name).ok_or_else(|| NetError::NoMacAddr(name.clone()))?;

        let mut cap = Capture::from_device(name.as_str())
            .map_err(NetError::Pcap)?
            .promisc(true)
            .snaplen(4096)
            .timeout(500) // ms — affects recv granularity
            .open()
            .map_err(NetError::Pcap)?;

        cap.filter("ether proto 0x88e1 or ether proto 0x8912", true)
            .map_err(NetError::Pcap)?;

        Ok(Self {
            cap,
            iface: name,
            mac,
        })
    }

    pub fn send(&mut self, frame: &[u8]) -> Result<(), NetError> {
        self.cap.sendpacket(frame).map_err(NetError::Pcap)
    }

    /// Receive frames for up to `dur`, passing each to `f`.
    /// Stops early if `f` returns `false`.
    pub fn recv_until<F>(&mut self, dur: Duration, mut f: F) -> Result<(), NetError>
    where
        F: FnMut(&[u8]) -> bool,
    {
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline {
            match self.cap.next_packet() {
                Ok(pkt) => {
                    if !f(pkt.data) {
                        return Ok(());
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(NetError::Pcap(e)),
            }
        }
        Ok(())
    }
}

// -- Permission checks -----------------------------------------------------

fn check_capture_permissions() -> Result<(), NetError> {
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = std::fs::metadata("/dev/bpf0")
            && e.kind() == std::io::ErrorKind::PermissionDenied
        {
            return Err(NetError::PermissionDenied(
                "BPF devices not accessible — run:  sudo plcmon setup\n\
                     (creates access_bpf group so you can capture without root)"
                    .into(),
            ));
        }
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux, raw capture needs CAP_NET_RAW or root
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            // Check if we have CAP_NET_RAW (best-effort — if the check fails, let pcap try)
            let status = std::process::Command::new("getpcaps")
                .arg(std::process::id().to_string())
                .output();
            if let Ok(out) = status {
                let text = String::from_utf8_lossy(&out.stdout);
                if !text.contains("cap_net_raw") {
                    return Err(NetError::PermissionDenied(
                        "Raw capture not permitted — run:  sudo plcmon setup\n\
                         (grants cap_net_raw so you can capture without root)"
                            .into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

// -- Interface discovery ---------------------------------------------------

fn find_ethernet_iface() -> Result<String, NetError> {
    let devs = Device::list().map_err(NetError::Pcap)?;

    // macOS: prefer en* interfaces
    // Linux: prefer eth*, enp*, eno* interfaces
    let ethernet_prefixes = ["en", "eth", "enp", "eno"];

    for d in &devs {
        if ethernet_prefixes.iter().any(|p| d.name.starts_with(p)) && !d.addresses.is_empty() {
            return Ok(d.name.clone());
        }
    }
    // Fallback: any non-loopback with addresses
    for d in &devs {
        if !d.name.starts_with("lo") && !d.addresses.is_empty() {
            return Ok(d.name.clone());
        }
    }
    Err(NetError::NoInterface)
}

// -- MAC address discovery -------------------------------------------------

fn get_mac(ifname: &str) -> Option<MacAddr> {
    // Try Linux sysfs first (fast, no subprocess)
    #[cfg(target_os = "linux")]
    {
        if let Some(mac) = get_mac_sysfs(ifname) {
            return Some(mac);
        }
    }
    // Fall back to ifconfig (works on macOS and most Linux)
    get_mac_ifconfig(ifname)
}

#[cfg(target_os = "linux")]
fn get_mac_sysfs(ifname: &str) -> Option<MacAddr> {
    let path = format!("/sys/class/net/{ifname}/address");
    let text = std::fs::read_to_string(path).ok()?;
    parse_mac(text.trim())
}

fn get_mac_ifconfig(ifname: &str) -> Option<MacAddr> {
    let out = std::process::Command::new("ifconfig")
        .arg(ifname)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        // macOS: "ether aa:bb:cc:dd:ee:ff"
        if let Some(rest) = trimmed.strip_prefix("ether ") {
            return parse_mac(rest.trim());
        }
        // Linux: "ether aa:bb:cc:dd:ee:ff txqueuelen ..."
        // (also matched by the strip_prefix above)
    }
    None
}

pub fn parse_mac(s: &str) -> Option<MacAddr> {
    // Accept both ':' and '-' separators
    let normalized = s.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut addr = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        addr[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(MacAddr(addr))
}
