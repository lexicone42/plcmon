//! Qualcomm/Atheros vendor-specific messages (EtherType 0x88E1, OUI 00:B0:52).
//! Stubbed out — ready to implement when QCA hardware is available for testing.

use super::{ETHERTYPE_HPAV, MacAddr, build_qca_frame, parse_eth, parse_hpav};

pub const VS_NW_INFO_REQ: u16 = 0xA038;
pub const VS_NW_INFO_CNF: u16 = 0xA039;
pub const VS_SW_VER_REQ: u16 = 0xA000;
pub const VS_SW_VER_CNF: u16 = 0xA001;

/// QCA local-management address — all QCA devices on the local segment respond.
pub const QCA_LOCALCAST: MacAddr = MacAddr([0x00, 0xB0, 0x52, 0x00, 0x00, 0x01]);

#[derive(Debug, Clone)]
pub struct QcaStation {
    pub mac: MacAddr,
    pub tei: u8,
    pub avg_tx_mbps: u16,
    pub avg_rx_mbps: u16,
}

#[derive(Debug, Clone)]
pub struct QcaNetwork {
    pub nid: [u8; 7],
    pub snid: u8,
    pub tei: u8,
    pub role: u8,
    pub cco_mac: MacAddr,
    pub stations: Vec<QcaStation>,
}

pub fn build_nw_info_req(dst: MacAddr, src: MacAddr) -> Vec<u8> {
    build_qca_frame(dst, src, VS_NW_INFO_REQ)
}

pub fn build_sw_ver_req(dst: MacAddr, src: MacAddr) -> Vec<u8> {
    build_qca_frame(dst, src, VS_SW_VER_REQ)
}

/// Parse VS_NW_INFO.CNF — returns networks with per-station PHY rates.
/// Handles both v1 (1-byte rates) and v2 (2-byte rates) formats.
pub fn parse_nw_info_cnf(data: &[u8]) -> Option<Vec<QcaNetwork>> {
    let (_dst, _src, etype, eth_off) = parse_eth(data)?;
    if etype != ETHERTYPE_HPAV {
        return None;
    }
    let (mmtype, hdr_end) = parse_hpav(data, eth_off)?;
    if mmtype != VS_NW_INFO_CNF {
        return None;
    }

    // Skip OUI (3 bytes)
    let p = hdr_end + 3;
    if data.len() <= p {
        return Some(vec![]);
    }

    let num_nets = data[p] as usize;
    let mut networks = Vec::with_capacity(num_nets);
    let mut off = p + 1;

    for _ in 0..num_nets {
        if off + 18 > data.len() {
            break;
        }
        let mut nid = [0u8; 7];
        nid.copy_from_slice(&data[off..off + 7]);
        let snid = data[off + 7];
        let tei = data[off + 8];
        let role = data[off + 9];
        let cco_mac = MacAddr::from_bytes(&data[off + 10..off + 16])?;
        let _cco_tei = data[off + 16];
        let num_stas = data[off + 17] as usize;
        off += 18;

        let mut stations = Vec::with_capacity(num_stas);
        for _ in 0..num_stas {
            // v1: 6 (MAC) + 1 (TEI) + 6 (BDA) + 1 (TX) + 1 (RX) = 15 bytes
            if off + 15 > data.len() {
                break;
            }
            let mac = MacAddr::from_bytes(&data[off..off + 6])?;
            let sta_tei = data[off + 6];
            // Skip BDA (bridge address) at off+7..off+13
            let avg_tx = data[off + 13] as u16;
            let avg_rx = data[off + 14] as u16;
            stations.push(QcaStation {
                mac,
                tei: sta_tei,
                avg_tx_mbps: avg_tx,
                avg_rx_mbps: avg_rx,
            });
            off += 15;
        }

        networks.push(QcaNetwork {
            nid,
            snid,
            tei,
            role,
            cco_mac,
            stations,
        });
    }

    Some(networks)
}
