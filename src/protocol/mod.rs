pub mod broadcom;
pub mod qualcomm;
pub mod standard;

use serde::Serialize;
use std::fmt;

// -- EtherType constants (big-endian, as they appear on the wire) ----------

pub const ETHERTYPE_HPAV: [u8; 2] = [0x88, 0xE1];
pub const ETHERTYPE_MEDIAXTREAM: [u8; 2] = [0x89, 0x12];

// -- MAC addresses ---------------------------------------------------------

pub const MAC_BROADCAST: MacAddr = MacAddr([0xFF; 6]);

// -- OUIs ------------------------------------------------------------------

pub const OUI_QUALCOMM: [u8; 3] = [0x00, 0xB0, 0x52];
pub const OUI_BROADCOM: [u8; 3] = [0x00, 0x1F, 0x84];

// -- MME version bytes -----------------------------------------------------

pub const HPAV_MMV: u8 = 0x01;
pub const MEDIAXTREAM_MMV: u8 = 0x02;

/// Minimum Ethernet frame size (excluding 4-byte FCS added by hardware).
pub const MIN_FRAME_SIZE: usize = 60;

// ==========================================================================
// MacAddr
// ==========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.get(..6).map(|b| {
            let mut a = [0u8; 6];
            a.copy_from_slice(b);
            MacAddr(a)
        })
    }

    /// Short form for display in tight spaces: last 3 octets.
    pub fn short(&self) -> String {
        format!("{:02X}:{:02X}:{:02X}", self.0[3], self.0[4], self.0[5])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

// ==========================================================================
// Frame builders
// ==========================================================================

/// Build a standard HomePlug AV frame (EtherType 0x88E1).
pub fn build_hpav_frame(dst: MacAddr, src: MacAddr, mmtype: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(MIN_FRAME_SIZE);
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ETHERTYPE_HPAV);
    f.push(HPAV_MMV);
    f.extend_from_slice(&mmtype.to_le_bytes());
    f.resize(MIN_FRAME_SIZE, 0);
    f
}

/// Build a Qualcomm vendor-specific frame (EtherType 0x88E1 + OUI).
pub fn build_qca_frame(dst: MacAddr, src: MacAddr, mmtype: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(MIN_FRAME_SIZE);
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ETHERTYPE_HPAV);
    f.push(HPAV_MMV);
    f.extend_from_slice(&mmtype.to_le_bytes());
    f.extend_from_slice(&OUI_QUALCOMM);
    f.resize(MIN_FRAME_SIZE, 0);
    f
}

/// Build a Broadcom Mediaxtream vendor-specific frame (EtherType 0x8912).
pub fn build_bcm_frame(
    dst: MacAddr,
    src: MacAddr,
    mmtype: u16,
    seq: u8,
    payload: &[u8],
) -> Vec<u8> {
    let needed = 14 + 9 + payload.len();
    let mut f = Vec::with_capacity(needed.max(MIN_FRAME_SIZE));
    // Ethernet header
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ETHERTYPE_MEDIAXTREAM);
    // Mediaxtream MME header (9 bytes)
    f.push(MEDIAXTREAM_MMV);
    f.extend_from_slice(&mmtype.to_le_bytes());
    f.extend_from_slice(&[0x00, 0x00]); // FMI — no fragmentation
    f.extend_from_slice(&OUI_BROADCOM);
    f.push(seq);
    // Payload
    f.extend_from_slice(payload);
    // Pad
    if f.len() < MIN_FRAME_SIZE {
        f.resize(MIN_FRAME_SIZE, 0);
    }
    f
}

// ==========================================================================
// Frame parsers
// ==========================================================================

/// Parse Ethernet header → (dst, src, ethertype, payload_offset).
pub fn parse_eth(data: &[u8]) -> Option<(MacAddr, MacAddr, [u8; 2], usize)> {
    if data.len() < 14 {
        return None;
    }
    Some((
        MacAddr::from_bytes(&data[0..6])?,
        MacAddr::from_bytes(&data[6..12])?,
        [data[12], data[13]],
        14,
    ))
}

/// Parse standard HPAV MME header → (mmtype, payload_offset).
pub fn parse_hpav(data: &[u8], off: usize) -> Option<(u16, usize)> {
    if data.len() < off + 3 || data[off] != HPAV_MMV {
        return None;
    }
    Some((u16::from_le_bytes([data[off + 1], data[off + 2]]), off + 3))
}

/// Parse Mediaxtream header → (mmtype, seq, payload_offset).
pub fn parse_bcm_hdr(data: &[u8], off: usize) -> Option<(u16, u8, usize)> {
    if data.len() < off + 9 || data[off] != MEDIAXTREAM_MMV {
        return None;
    }
    let mmtype = u16::from_le_bytes([data[off + 1], data[off + 2]]);
    let seq = data[off + 8];
    Some((mmtype, seq, off + 9))
}
