use crate::net::{NetError, PlcCapture};
use crate::protocol::broadcom;
use crate::protocol::standard;
use crate::types::{Chipset, Device, Link, NetworkScan};
use chrono::Local;
use std::time::Duration;

const DISCOVER_WAIT: Duration = Duration::from_secs(3);
const STATS_WAIT: Duration = Duration::from_secs(2);

pub struct Scanner {
    cap: PlcCapture,
    seq: u8,
}

impl Scanner {
    pub fn new(cap: PlcCapture) -> Self {
        Self { cap, seq: 0 }
    }

    pub fn interface(&self) -> &str {
        &self.cap.iface
    }

    fn next_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Full network scan: discover stations, then query link rates.
    pub fn scan(&mut self) -> Result<NetworkScan, NetError> {
        let iface = self.cap.iface.clone();

        // -- Step 1: CC_DISCOVER_LIST → find local adapter + remote stations --
        let frame = standard::build_discover_list_req(self.cap.mac);
        self.cap.send(&frame)?;

        let mut local_mac = None;
        let mut discovered = Vec::new();

        self.cap.recv_until(DISCOVER_WAIT, |data| {
            if let Some((responder, stations)) = standard::parse_discover_list_cnf(data) {
                local_mac = Some(responder);
                discovered = stations;
                return false; // got it
            }
            true
        })?;

        let local_mac = match local_mac {
            Some(m) => m,
            None => return Ok(NetworkScan::empty(&iface)),
        };

        // -- Step 2: BCM NW_STATS from local adapter --
        let mut links = Vec::new();

        if let Some(rates) = self.query_bcm_stats(local_mac)? {
            for r in &rates {
                links.push(Link {
                    from: local_mac,
                    to: r.mac,
                    tx_mbps: r.tx_mbps,
                    rx_mbps: r.rx_mbps,
                    tx_signal: r.tx_signal.to_string(),
                    rx_signal: r.rx_signal.to_string(),
                });
            }
        }

        // -- Step 3: BCM NW_STATS from each remote (optional, for full matrix) --
        for station in &discovered {
            if let Some(rates) = self.query_bcm_stats(station.mac)? {
                for r in &rates {
                    links.push(Link {
                        from: station.mac,
                        to: r.mac,
                        tx_mbps: r.tx_mbps,
                        rx_mbps: r.rx_mbps,
                        tx_signal: r.tx_signal.to_string(),
                        rx_signal: r.rx_signal.to_string(),
                    });
                }
            }
        }

        // -- Build device list --
        // Start with local adapter, then add discovered stations.
        // Also add any MACs seen in link data but not in CC_DISCOVER_LIST
        // (BCM devices sometimes skip the standard discover response).
        let mut seen_macs = std::collections::HashSet::new();

        let mut devices = vec![Device {
            mac: local_mac,
            model: String::new(),
            firmware: String::new(),
            is_local: true,
            is_cco: false,
            chipset: Chipset::Broadcom,
        }];
        seen_macs.insert(local_mac);

        for s in &discovered {
            if seen_macs.insert(s.mac) {
                devices.push(Device {
                    mac: s.mac,
                    model: String::new(),
                    firmware: String::new(),
                    is_local: false,
                    is_cco: s.is_cco,
                    chipset: Chipset::Broadcom,
                });
            }
        }

        // Add devices discovered only via link data
        for link in &links {
            for mac in [link.from, link.to] {
                if seen_macs.insert(mac) {
                    devices.push(Device {
                        mac,
                        model: String::new(),
                        firmware: String::new(),
                        is_local: false,
                        is_cco: false,
                        chipset: Chipset::Broadcom,
                    });
                }
            }
        }

        // -- Step 4: Try to detect chipset via standard CM_NW_STATS fallback --
        // If no BCM stats came back, try standard messages (may be QCA devices)
        if links.is_empty() {
            let frame = standard::build_nw_stats_req(local_mac, self.cap.mac);
            self.cap.send(&frame)?;
            self.cap.recv_until(STATS_WAIT, |data| {
                if let Some(stats) = standard::parse_nw_stats_cnf(data) {
                    for (mac, tx, rx) in stats {
                        links.push(Link {
                            from: local_mac,
                            to: mac,
                            tx_mbps: tx as u16,
                            rx_mbps: rx as u16,
                            tx_signal: String::new(),
                            rx_signal: String::new(),
                        });
                    }
                    return false;
                }
                true
            })?;

            // Mark chipset as unknown since BCM didn't respond
            for d in &mut devices {
                d.chipset = Chipset::Unknown;
            }
        }

        Ok(NetworkScan {
            timestamp: Local::now(),
            interface: iface,
            devices,
            links,
        })
    }

    fn query_bcm_stats(
        &mut self,
        target: crate::protocol::MacAddr,
    ) -> Result<Option<Vec<broadcom::BcmLinkRate>>, NetError> {
        let seq = self.next_seq();
        let frame = broadcom::build_nw_stats_req(target, self.cap.mac, seq);
        self.cap.send(&frame)?;

        let mut result = None;
        self.cap.recv_until(STATS_WAIT, |data| {
            if let Some((_src, rates)) = broadcom::parse_nw_stats_cnf(data) {
                result = Some(rates);
                return false;
            }
            true
        })?;

        Ok(result)
    }
}

impl NetworkScan {
    pub fn empty(iface: &str) -> Self {
        Self {
            timestamp: Local::now(),
            interface: iface.to_string(),
            devices: vec![],
            links: vec![],
        }
    }
}
