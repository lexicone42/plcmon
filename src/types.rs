use crate::protocol::MacAddr;
use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct NetworkScan {
    pub timestamp: DateTime<Local>,
    pub interface: String,
    pub devices: Vec<Device>,
    pub links: Vec<Link>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub mac: MacAddr,
    pub model: String,
    pub firmware: String,
    pub is_local: bool,
    pub is_cco: bool,
    pub chipset: Chipset,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum Chipset {
    Broadcom,
    Qualcomm,
    Unknown,
}

impl std::fmt::Display for Chipset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broadcom => write!(f, "BCM"),
            Self::Qualcomm => write!(f, "QCA"),
            Self::Unknown => write!(f, "???"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Link {
    pub from: MacAddr,
    pub to: MacAddr,
    pub tx_mbps: u16,
    pub rx_mbps: u16,
    pub tx_signal: String,
    pub rx_signal: String,
}

impl NetworkScan {
    /// Build a from→to speed lookup. Value = TX rate from the `from` device.
    pub fn speed_matrix(&self) -> HashMap<(MacAddr, MacAddr), u16> {
        let mut m = HashMap::new();
        for l in &self.links {
            m.insert((l.from, l.to), l.tx_mbps);
        }
        m
    }
}

/// Map TP-Link HFID model codes to human-readable model names.
pub fn hfid_to_model(hfid: &str) -> String {
    let code = hfid
        .strip_prefix("tpver_")
        .and_then(|s| s.split('_').next())
        .unwrap_or("");

    if code.len() < 4 {
        return if hfid.is_empty() {
            String::new()
        } else {
            hfid.to_string()
        };
    }

    match &code[..4] {
        "9021" => "TL-PA9020P".into(),
        "9020" => "TL-PA9020".into(),
        "8010" => "TL-PA8010".into(),
        "7420" => "TL-PA7420".into(),
        "7510" => "TL-PA7510".into(),
        "4220" => "TL-WPA4220".into(),
        "8630" => "TL-WPA8630".into(),
        "9610" => "TL-WPA9610".into(),
        _ => format!("TP-Link ({code})"),
    }
}
