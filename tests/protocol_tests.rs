use plcmon::protocol::*;

#[test]
fn mac_addr_display() {
    let mac = MacAddr([0xD4, 0x6E, 0x0E, 0xF6, 0x96, 0xBF]);
    assert_eq!(mac.to_string(), "D4:6E:0E:F6:96:BF");
}

#[test]
fn mac_addr_short() {
    let mac = MacAddr([0xD4, 0x6E, 0x0E, 0xF6, 0x96, 0xBF]);
    assert_eq!(mac.short(), "F6:96:BF");
}

#[test]
fn mac_addr_from_bytes() {
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF];
    let mac = MacAddr::from_bytes(&bytes).unwrap();
    assert_eq!(mac.0, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    assert!(MacAddr::from_bytes(&[0x01, 0x02]).is_none());
}

#[test]
fn mac_addr_serialize_json() {
    let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let json = serde_json::to_string(&mac).unwrap();
    assert_eq!(json, "\"AA:BB:CC:DD:EE:FF\"");
}

#[test]
fn build_hpav_frame_minimum_size() {
    let src = MacAddr([0x01; 6]);
    let frame = build_hpav_frame(MAC_BROADCAST, src, 0x0014);
    assert!(frame.len() >= MIN_FRAME_SIZE);
    // Check EtherType
    assert_eq!(&frame[12..14], &ETHERTYPE_HPAV);
    // Check MMV
    assert_eq!(frame[14], HPAV_MMV);
    // Check MMTYPE (little-endian)
    assert_eq!(&frame[15..17], &[0x14, 0x00]);
}

#[test]
fn build_bcm_frame_structure() {
    let dst = MacAddr([0xAA; 6]);
    let src = MacAddr([0xBB; 6]);
    let frame = build_bcm_frame(dst, src, 0xA02C, 42, &[0x01, 0x02]);
    assert!(frame.len() >= MIN_FRAME_SIZE);
    // EtherType = Mediaxtream
    assert_eq!(&frame[12..14], &ETHERTYPE_MEDIAXTREAM);
    // MMV = 0x02
    assert_eq!(frame[14], MEDIAXTREAM_MMV);
    // MMTYPE (LE)
    assert_eq!(&frame[15..17], &[0x2C, 0xA0]);
    // FMI = 0
    assert_eq!(&frame[17..19], &[0x00, 0x00]);
    // OUI
    assert_eq!(&frame[19..22], &OUI_BROADCOM);
    // Seq
    assert_eq!(frame[22], 42);
    // Payload
    assert_eq!(&frame[23..25], &[0x01, 0x02]);
}

#[test]
fn build_qca_frame_structure() {
    let dst = MacAddr([0xCC; 6]);
    let src = MacAddr([0xDD; 6]);
    let frame = build_qca_frame(dst, src, 0xA038);
    assert!(frame.len() >= MIN_FRAME_SIZE);
    assert_eq!(&frame[12..14], &ETHERTYPE_HPAV);
    assert_eq!(frame[14], HPAV_MMV);
    assert_eq!(&frame[15..17], &[0x38, 0xA0]);
    assert_eq!(&frame[17..20], &OUI_QUALCOMM);
}

#[test]
fn parse_eth_valid() {
    let mut frame = vec![0u8; 60];
    frame[0..6].copy_from_slice(&[0xFF; 6]); // dst
    frame[6..12].copy_from_slice(&[0x01; 6]); // src
    frame[12..14].copy_from_slice(&ETHERTYPE_HPAV);

    let (dst, src, etype, off) = parse_eth(&frame).unwrap();
    assert!(dst == MAC_BROADCAST);
    assert_eq!(src.0, [0x01; 6]);
    assert_eq!(etype, ETHERTYPE_HPAV);
    assert_eq!(off, 14);
}

#[test]
fn parse_eth_too_short() {
    assert!(parse_eth(&[0u8; 10]).is_none());
}

#[test]
fn parse_hpav_valid() {
    let mut data = vec![0u8; 20];
    data[0] = HPAV_MMV;
    data[1..3].copy_from_slice(&0x0015u16.to_le_bytes());

    let (mmtype, off) = parse_hpav(&data, 0).unwrap();
    assert_eq!(mmtype, 0x0015);
    assert_eq!(off, 3);
}

#[test]
fn parse_hpav_wrong_version() {
    let data = [0x99, 0x15, 0x00];
    assert!(parse_hpav(&data, 0).is_none());
}

#[test]
fn parse_bcm_hdr_valid() {
    let mut data = vec![0u8; 20];
    data[0] = MEDIAXTREAM_MMV;
    data[1..3].copy_from_slice(&0xA02Du16.to_le_bytes());
    data[3..5].copy_from_slice(&[0x00, 0x00]); // FMI
    data[5..8].copy_from_slice(&OUI_BROADCOM);
    data[8] = 7; // seq

    let (mmtype, seq, off) = parse_bcm_hdr(&data, 0).unwrap();
    assert_eq!(mmtype, 0xA02D);
    assert_eq!(seq, 7);
    assert_eq!(off, 9);
}

// -- Standard message tests ------------------------------------------------

mod standard_tests {
    use plcmon::protocol::standard::*;
    use plcmon::protocol::*;

    #[test]
    fn build_discover_list_req() {
        let src = MacAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let frame = plcmon::protocol::standard::build_discover_list_req(src);
        assert!(frame.len() >= MIN_FRAME_SIZE);
        // Destination is broadcast
        assert_eq!(&frame[0..6], &[0xFF; 6]);
        // MMTYPE = CC_DISCOVER_LIST_REQ
        assert_eq!(&frame[15..17], &CC_DISCOVER_LIST_REQ.to_le_bytes());
    }

    #[test]
    fn parse_discover_list_cnf_with_stations() {
        // Construct a fake CC_DISCOVER_LIST.CNF frame
        let mut frame = vec![0u8; 60];
        // Ethernet header
        frame[0..6].copy_from_slice(&[0x01; 6]); // dst (us)
        frame[6..12].copy_from_slice(&[0xD4, 0x6E, 0x0E, 0xF6, 0x96, 0xBF]); // src (responder)
        frame[12..14].copy_from_slice(&ETHERTYPE_HPAV);
        // HPAV header
        frame[14] = HPAV_MMV;
        frame[15..17].copy_from_slice(&CC_DISCOVER_LIST_CNF.to_le_bytes());
        // Payload: 1 station
        frame[17] = 1; // num stations
        // Station: MAC + TEI + SameNetwork + SNID + Flags + SignalLevel
        frame[18..24].copy_from_slice(&[0x98, 0x48, 0x27, 0x4C, 0x02, 0x24]);
        frame[24] = 5; // TEI
        frame[25] = 1; // same network
        frame[26] = 1; // SNID
        frame[27] = 0x01; // flags (CCo)
        frame[28] = 200; // signal level

        let (responder, stations) = parse_discover_list_cnf(&frame).unwrap();
        assert_eq!(responder.to_string(), "D4:6E:0E:F6:96:BF");
        assert_eq!(stations.len(), 1);
        assert_eq!(stations[0].mac.to_string(), "98:48:27:4C:02:24");
        assert_eq!(stations[0].tei, 5);
        assert!(stations[0].same_network);
        assert!(stations[0].is_cco);
    }

    #[test]
    fn parse_discover_list_cnf_wrong_mmtype() {
        let mut frame = vec![0u8; 60];
        frame[0..6].copy_from_slice(&[0x01; 6]);
        frame[6..12].copy_from_slice(&[0x02; 6]);
        frame[12..14].copy_from_slice(&ETHERTYPE_HPAV);
        frame[14] = HPAV_MMV;
        frame[15..17].copy_from_slice(&0x0014u16.to_le_bytes()); // REQ, not CNF

        assert!(parse_discover_list_cnf(&frame).is_none());
    }
}

// -- Broadcom message tests ------------------------------------------------

mod broadcom_tests {
    use plcmon::protocol::broadcom::*;
    use plcmon::protocol::*;

    #[test]
    fn parse_nw_stats_cnf_two_stations() {
        let mut frame = vec![0u8; 60];
        // Ethernet header
        frame[0..6].copy_from_slice(&[0x01; 6]); // dst
        let responder_mac = [0xD4, 0x6E, 0x0E, 0xF6, 0x96, 0xBF];
        frame[6..12].copy_from_slice(&responder_mac); // src
        frame[12..14].copy_from_slice(&ETHERTYPE_MEDIAXTREAM);
        // Mediaxtream header
        frame[14] = MEDIAXTREAM_MMV;
        frame[15..17].copy_from_slice(&BCM_NW_STATS_CNF.to_le_bytes());
        frame[17..19].copy_from_slice(&[0x00, 0x00]); // FMI
        frame[19..22].copy_from_slice(&OUI_BROADCOM);
        frame[22] = 0; // seq
        // Payload: 2 stations
        frame[23] = 2;

        // Station 1: MAC + TX rate word + RX rate word
        frame[24..30].copy_from_slice(&[0x98, 0x48, 0x27, 0x4C, 0x02, 0x24]);
        // TX: 307 Mbps MIMO = 307 | (2 << 12) = 307 | 0x2000 = 0x2133
        let tx1: u16 = 307 | (2 << 12);
        frame[30..32].copy_from_slice(&tx1.to_le_bytes());
        // RX: 330 Mbps MIMO
        let rx1: u16 = 330 | (2 << 12);
        frame[32..34].copy_from_slice(&rx1.to_le_bytes());

        // Station 2: slow link
        frame[34..40].copy_from_slice(&[0xD4, 0x6E, 0x0E, 0xF6, 0x96, 0xBE]);
        // TX: 11 Mbps SISO
        let tx2: u16 = 11;
        frame[40..42].copy_from_slice(&tx2.to_le_bytes());
        // RX: 11 Mbps SISO
        let rx2: u16 = 11;
        frame[42..44].copy_from_slice(&rx2.to_le_bytes());

        let (src, rates) = parse_nw_stats_cnf(&frame).unwrap();
        assert_eq!(src.to_string(), "D4:6E:0E:F6:96:BF");
        assert_eq!(rates.len(), 2);

        assert_eq!(rates[0].mac.to_string(), "98:48:27:4C:02:24");
        assert_eq!(rates[0].tx_mbps, 307);
        assert_eq!(rates[0].rx_mbps, 330);
        assert_eq!(rates[0].tx_signal, SignalType::Mimo);
        assert_eq!(rates[0].rx_signal, SignalType::Mimo);

        assert_eq!(rates[1].mac.to_string(), "D4:6E:0E:F6:96:BE");
        assert_eq!(rates[1].tx_mbps, 11);
        assert_eq!(rates[1].rx_mbps, 11);
        assert_eq!(rates[1].tx_signal, SignalType::Siso1);
    }

    #[test]
    fn parse_nw_stats_cnf_wrong_ethertype() {
        let mut frame = vec![0u8; 60];
        frame[12..14].copy_from_slice(&ETHERTYPE_HPAV); // wrong
        assert!(parse_nw_stats_cnf(&frame).is_none());
    }

    #[test]
    fn rate_word_siso_encoding() {
        // 11 Mbps, SISO1, no beamforming, HPAV1.1
        let frame = build_test_stats_frame(11, 0, 11, 0);
        let (_, rates) = parse_nw_stats_cnf(&frame).unwrap();
        assert_eq!(rates[0].tx_mbps, 11);
        assert_eq!(rates[0].tx_signal, SignalType::Siso1);
    }

    #[test]
    fn rate_word_mimo_encoding() {
        // 400 Mbps, MIMO (signal type 2), HPAV2.0 (spec version 1)
        let tx_word: u16 = 400 | (2 << 12) | (1 << 14);
        let frame = build_test_stats_frame_raw(tx_word, tx_word);
        let (_, rates) = parse_nw_stats_cnf(&frame).unwrap();
        assert_eq!(rates[0].tx_mbps, 400);
        assert_eq!(rates[0].tx_signal, SignalType::Mimo);
    }

    fn build_test_stats_frame(tx_mbps: u16, tx_sig: u16, rx_mbps: u16, rx_sig: u16) -> Vec<u8> {
        let tx_word = tx_mbps | (tx_sig << 12);
        let rx_word = rx_mbps | (rx_sig << 12);
        build_test_stats_frame_raw(tx_word, rx_word)
    }

    fn build_test_stats_frame_raw(tx_word: u16, rx_word: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 60];
        frame[0..6].copy_from_slice(&[0x01; 6]);
        frame[6..12].copy_from_slice(&[0x02; 6]);
        frame[12..14].copy_from_slice(&ETHERTYPE_MEDIAXTREAM);
        frame[14] = MEDIAXTREAM_MMV;
        frame[15..17].copy_from_slice(&BCM_NW_STATS_CNF.to_le_bytes());
        frame[17..19].copy_from_slice(&[0x00, 0x00]);
        frame[19..22].copy_from_slice(&OUI_BROADCOM);
        frame[22] = 0;
        frame[23] = 1; // 1 station
        frame[24..30].copy_from_slice(&[0xAA; 6]); // MAC
        frame[30..32].copy_from_slice(&tx_word.to_le_bytes());
        frame[32..34].copy_from_slice(&rx_word.to_le_bytes());
        frame
    }
}

// -- MAC parsing tests -----------------------------------------------------

mod mac_parsing {
    use plcmon::net::parse_mac;

    #[test]
    fn colon_separated() {
        let mac = parse_mac("d4:6e:0e:f6:96:bf").unwrap();
        assert_eq!(mac.to_string(), "D4:6E:0E:F6:96:BF");
    }

    #[test]
    fn dash_separated() {
        let mac = parse_mac("d4-6e-0e-f6-96-bf").unwrap();
        assert_eq!(mac.to_string(), "D4:6E:0E:F6:96:BF");
    }

    #[test]
    fn invalid_format() {
        assert!(parse_mac("not-a-mac").is_none());
        assert!(parse_mac("").is_none());
        assert!(parse_mac("aa:bb:cc").is_none());
    }
}

// -- Types tests -----------------------------------------------------------

mod types_tests {
    use plcmon::types::hfid_to_model;

    #[test]
    fn known_models() {
        assert_eq!(hfid_to_model("tpver_902101_170118_901"), "TL-PA9020P");
        assert_eq!(hfid_to_model("tpver_801011_151201_002"), "TL-PA8010");
        assert_eq!(hfid_to_model("tpver_422014_160125_901"), "TL-WPA4220");
    }

    #[test]
    fn unknown_model() {
        let result = hfid_to_model("tpver_999901_170118_901");
        assert!(result.contains("9999"));
    }

    #[test]
    fn empty_hfid() {
        assert_eq!(hfid_to_model(""), "");
    }
}
