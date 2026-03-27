//! Standard HomePlug AV messages (EtherType 0x88E1, no vendor OUI).
//! These work on all compliant chipsets (Qualcomm, Broadcom, etc.).

use super::{ETHERTYPE_HPAV, MAC_BROADCAST, MacAddr, build_hpav_frame, parse_eth, parse_hpav};

pub const CC_DISCOVER_LIST_REQ: u16 = 0x0014;
pub const CC_DISCOVER_LIST_CNF: u16 = 0x0015;
pub const CM_NW_STATS_REQ: u16 = 0x6048;
pub const CM_NW_STATS_CNF: u16 = 0x6049;

#[derive(Debug, Clone)]
pub struct DiscoveredStation {
    pub mac: MacAddr,
    pub tei: u8,
    pub same_network: bool,
    pub snid: u8,
    pub is_cco: bool,
}

// -- Builders --------------------------------------------------------------

pub fn build_discover_list_req(src: MacAddr) -> Vec<u8> {
    build_hpav_frame(MAC_BROADCAST, src, CC_DISCOVER_LIST_REQ)
}

pub fn build_nw_stats_req(dst: MacAddr, src: MacAddr) -> Vec<u8> {
    build_hpav_frame(dst, src, CM_NW_STATS_REQ)
}

// -- Parsers ---------------------------------------------------------------

/// Parse a CC_DISCOVER_LIST.CNF frame.
/// Returns (source_mac_of_responder, list_of_discovered_stations).
pub fn parse_discover_list_cnf(data: &[u8]) -> Option<(MacAddr, Vec<DiscoveredStation>)> {
    let (_dst, src, etype, eth_off) = parse_eth(data)?;
    if etype != ETHERTYPE_HPAV {
        return None;
    }
    let (mmtype, payload) = parse_hpav(data, eth_off)?;
    if mmtype != CC_DISCOVER_LIST_CNF {
        return None;
    }
    if data.len() <= payload {
        return Some((src, vec![]));
    }

    let num = data[payload] as usize;
    let mut stations = Vec::with_capacity(num);
    let mut off = payload + 1;

    for _ in 0..num {
        if off + 11 > data.len() {
            break;
        }
        let mac = MacAddr::from_bytes(&data[off..off + 6])?;
        stations.push(DiscoveredStation {
            mac,
            tei: data[off + 6],
            same_network: data[off + 7] != 0,
            snid: data[off + 8],
            is_cco: (data[off + 9] & 0x01) != 0,
        });
        off += 11;
    }

    Some((src, stations))
}

/// Parse CM_NW_STATS.CNF — returns per-station (mac, tx_mbps, rx_mbps).
/// Note: standard message uses 1-byte rates (max 255 Mbps). For higher rates,
/// use vendor-specific messages.
pub fn parse_nw_stats_cnf(data: &[u8]) -> Option<Vec<(MacAddr, u8, u8)>> {
    let (_dst, _src, etype, eth_off) = parse_eth(data)?;
    if etype != ETHERTYPE_HPAV {
        return None;
    }
    let (mmtype, payload) = parse_hpav(data, eth_off)?;
    if mmtype != CM_NW_STATS_CNF {
        return None;
    }
    if data.len() <= payload {
        return Some(vec![]);
    }

    let num = data[payload] as usize;
    let mut stats = Vec::with_capacity(num);
    let mut off = payload + 1;

    for _ in 0..num {
        if off + 8 > data.len() {
            break;
        }
        let mac = MacAddr::from_bytes(&data[off..off + 6])?;
        let tx = data[off + 6];
        let rx = data[off + 7];
        stats.push((mac, tx, rx));
        off += 8;
    }

    Some(stats)
}
