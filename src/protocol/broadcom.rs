//! Broadcom Mediaxtream vendor-specific messages (EtherType 0x8912, OUI 00:1F:84).
//! Reverse-engineered from pla-util and packet captures.

use super::{ETHERTYPE_MEDIAXTREAM, MacAddr, build_bcm_frame, parse_bcm_hdr, parse_eth};

pub const BCM_NW_INFO_REQ: u16 = 0xA028;
pub const BCM_NW_INFO_CNF: u16 = 0xA029;
pub const BCM_NW_STATS_REQ: u16 = 0xA02C;
pub const BCM_NW_STATS_CNF: u16 = 0xA02D;
pub const BCM_STA_INFO_REQ: u16 = 0xA04C;
pub const BCM_STA_INFO_CNF: u16 = 0xA04D;
pub const BCM_STA_RESTART_REQ: u16 = 0xA020;
pub const BCM_STA_RESTART_CNF: u16 = 0xA021;

// -- Result types ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignalType {
    Siso1,
    Siso2,
    Mimo,
    SisoOnly,
}

impl std::fmt::Display for SignalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Siso1 => write!(f, "SISO"),
            Self::Siso2 => write!(f, "SISO2"),
            Self::Mimo => write!(f, "MIMO"),
            Self::SisoOnly => write!(f, "SISO"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BcmLinkRate {
    pub mac: MacAddr,
    pub tx_mbps: u16,
    pub rx_mbps: u16,
    pub tx_signal: SignalType,
    pub rx_signal: SignalType,
}

#[derive(Debug, Clone)]
pub struct BcmStationInfo {
    pub chip_version: u32,
    pub hardware_version: u32,
    pub firmware_svn: u32,
    pub uptime_secs: u32,
}

// -- Builders --------------------------------------------------------------

pub fn build_nw_stats_req(dst: MacAddr, src: MacAddr, seq: u8) -> Vec<u8> {
    build_bcm_frame(dst, src, BCM_NW_STATS_REQ, seq, &[])
}

pub fn build_nw_info_req(dst: MacAddr, src: MacAddr, seq: u8) -> Vec<u8> {
    build_bcm_frame(dst, src, BCM_NW_INFO_REQ, seq, &[])
}

pub fn build_sta_info_req(dst: MacAddr, src: MacAddr, seq: u8) -> Vec<u8> {
    build_bcm_frame(dst, src, BCM_STA_INFO_REQ, seq, &[])
}

pub fn build_sta_restart_req(dst: MacAddr, src: MacAddr, seq: u8) -> Vec<u8> {
    build_bcm_frame(dst, src, BCM_STA_RESTART_REQ, seq, &[])
}

// -- Parsers ---------------------------------------------------------------

fn parse_rate_word(w: u16) -> (u16, SignalType) {
    let rate = w & 0x07FF; // bits 0-10
    let sig = match (w >> 12) & 0x03 {
        0 => SignalType::Siso1,
        1 => SignalType::Siso2,
        2 => SignalType::Mimo,
        _ => SignalType::SisoOnly,
    };
    (rate, sig)
}

/// Parse BCM NW_STATS.CNF — per-station link rates from responder's perspective.
pub fn parse_nw_stats_cnf(data: &[u8]) -> Option<(MacAddr, Vec<BcmLinkRate>)> {
    let (_dst, src, etype, eth_off) = parse_eth(data)?;
    if etype != ETHERTYPE_MEDIAXTREAM {
        return None;
    }
    let (mmtype, _seq, payload) = parse_bcm_hdr(data, eth_off)?;
    if mmtype != BCM_NW_STATS_CNF {
        return None;
    }
    if data.len() <= payload {
        return Some((src, vec![]));
    }

    let num = data[payload] as usize;
    let mut rates = Vec::with_capacity(num);
    let mut off = payload + 1;

    for _ in 0..num {
        if off + 10 > data.len() {
            break;
        }
        let mac = MacAddr::from_bytes(&data[off..off + 6])?;
        let tx_word = u16::from_le_bytes([data[off + 6], data[off + 7]]);
        let rx_word = u16::from_le_bytes([data[off + 8], data[off + 9]]);
        let (tx_mbps, tx_signal) = parse_rate_word(tx_word);
        let (rx_mbps, rx_signal) = parse_rate_word(rx_word);

        rates.push(BcmLinkRate {
            mac,
            tx_mbps,
            rx_mbps,
            tx_signal,
            rx_signal,
        });
        off += 10;
    }

    Some((src, rates))
}

/// Parse BCM NW_INFO.CNF — returns responder MAC and raw payload for inspection.
pub fn parse_nw_info_cnf(data: &[u8]) -> Option<(MacAddr, Vec<u8>)> {
    let (_dst, src, etype, eth_off) = parse_eth(data)?;
    if etype != ETHERTYPE_MEDIAXTREAM {
        return None;
    }
    let (mmtype, _seq, payload_off) = parse_bcm_hdr(data, eth_off)?;
    if mmtype != BCM_NW_INFO_CNF {
        return None;
    }
    Some((src, data[payload_off..].to_vec()))
}

/// Extract MAC addresses found in a raw NW_INFO payload by scanning for
/// 6-byte sequences that look like unicast, non-zero MACs.
pub fn extract_macs_from_payload(payload: &[u8]) -> Vec<MacAddr> {
    let mut macs = Vec::new();
    if payload.len() < 6 {
        return macs;
    }
    let mut seen = std::collections::HashSet::new();
    for i in 0..=payload.len() - 6 {
        let bytes = &payload[i..i + 6];
        if bytes == [0; 6] || bytes == [0xFF; 6] {
            continue;
        }
        if bytes[0] & 1 != 0 {
            continue; // multicast
        }
        if let Some(mac) = MacAddr::from_bytes(bytes) {
            if seen.insert(mac) {
                macs.push(mac);
            }
        }
    }
    macs
}

/// Parse BCM STA_INFO.CNF — chip/firmware metadata.
pub fn parse_sta_info_cnf(data: &[u8]) -> Option<BcmStationInfo> {
    let (_dst, _src, etype, eth_off) = parse_eth(data)?;
    if etype != ETHERTYPE_MEDIAXTREAM {
        return None;
    }
    let (mmtype, _seq, p) = parse_bcm_hdr(data, eth_off)?;
    if mmtype != BCM_STA_INFO_CNF || data.len() < p + 16 {
        return None;
    }

    let r =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

    Some(BcmStationInfo {
        chip_version: r(p),
        hardware_version: r(p + 4),
        firmware_svn: r(p + 8),
        // Uptime is deep in the response; offset varies by firmware. Best-effort.
        uptime_secs: if data.len() >= p + 48 { r(p + 44) } else { 0 },
    })
}
