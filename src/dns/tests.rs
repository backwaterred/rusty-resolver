use super::*;
use super::header::*;
use super::message::*;
use super::question::*;
use super::resourcerecord::*;

#[test]
fn header_with_values_of_different_sorts()
{
    let h = Header {
        id: 0x0,
        qr: QR::Response,
        op: OpCode::StdQuery,
        auth_answ: true,
        trunc_resp: false,
        rec_desired: true,
        rec_avail: false,
        rcode: RespCode::FormatError,
        qd_count: 0,
        an_count: 1,
        ns_count: (u8::MAX as u16) + 1u16,
        ar_count: 0x0A0B,
    };

    let v = vec![
        0,0,
        0b10000101,1,
        0,0,
        0,1,
        1,0,
        0xA,0xB,
    ];

    assert_eq!(v, h.to_bytes())
}

#[test]
fn test_question_to_bytes()
{
    let q = Question {
        qname: String::from("wvs.spooky.com"),
        qtype: QType::CNAME,
        qclass: QClass::IN,
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 0x05]);
    v.extend(&[0x00, 0x01]);

    assert_eq!(v, q.to_bytes());
}

#[test]
fn test_rr_a_in_to_bytes()
{
    let q = ResourceRecord {
        name: String::from("wvs.spooky.com"),
        rr_type: Type::A,
        rr_class: Class::IN,
        ttl: 0xBEEFDEAD,
        rd_len: 0xDEEF,
        rdata: RData::A(255, 254, 253, 252),
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0xBE, 0xEF, 0xDE, 0xAD]);
    v.extend(&[0xDE, 0xEF]);
    v.extend(&[255,254,253,252]);

    assert_eq!(v, q.to_bytes());
}

#[test]
fn test_rr_aaaa_in_to_bytes()
{
    let q = ResourceRecord {
        name: String::from("wvs.spooky.com"),
        rr_type: Type::AAAA,
        rr_class: Class::IN,
        ttl: 0xBEEFDEAD,
        rd_len: 0xDEEF,
        rdata: RData::AAAA(0xDEAD,0xBEEF,0xDEAD,0xBEEF,0xDEAD,0xBEEF,0xDEAD,0xBEEF),
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 28]);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0xBE, 0xEF, 0xDE, 0xAD]);
    v.extend(&[0xDE, 0xEF]);
    v.extend(&[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF]);

    assert_eq!(v, q.to_bytes());
}

#[test]
fn test_rr_aaaa_in_all_zs_to_bytes()
{
    let q = ResourceRecord {
        name: String::from("wvs.spooky.com"),
        rr_type: Type::AAAA,
        rr_class: Class::IN,
        ttl: 0xBEEFDEAD,
        rd_len: 0xDEEF,
        rdata: RData::AAAA(0,0,0,0,0,0,0,0),
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 28]);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0xBE, 0xEF, 0xDE, 0xAD]);
    v.extend(&[0xDE, 0xEF]);
    v.extend(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    assert_eq!(v, q.to_bytes());
}

#[test]
fn test_rr_aaaa_in_localhost_to_bytes()
{
    let q = ResourceRecord {
        name: String::from("wvs.spooky.com"),
        rr_type: Type::AAAA,
        rr_class: Class::IN,
        ttl: 0xBEEFDEAD,
        rd_len: 0xDEEF,
        rdata: RData::AAAA(0,0,0,0,0,0,0,1),
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 28]);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0xBE, 0xEF, 0xDE, 0xAD]);
    v.extend(&[0xDE, 0xEF]);
    v.extend(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    assert_eq!(v, q.to_bytes());
}

#[test]
fn test_rr_aaaa_in_internal_zs_to_bytes()
{
    let q = ResourceRecord {
        name: String::from("wvs.spooky.com"),
        rr_type: Type::AAAA,
        rr_class: Class::IN,
        ttl: 0xBEEFDEAD,
        rd_len: 0xDEEF,
        rdata: RData::AAAA(0x2001,0x1608,0x10,0x25,0,0,0x9249,0xd69b),
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 28]);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0xBE, 0xEF, 0xDE, 0xAD]);
    v.extend(&[0xDE, 0xEF]);
    v.extend(&0x2001_u16.to_be_bytes());
    v.extend(&0x1608_u16.to_be_bytes());
    v.extend(&0x10_u16.to_be_bytes());
    v.extend(&0x25_u16.to_be_bytes());
    v.push(0);
    v.push(0);
    v.push(0);
    v.push(0);
    v.extend(&0x9249_u16.to_be_bytes());
    v.extend(&0xd69b_u16.to_be_bytes());

    let qb = q.to_bytes();

    assert_eq!(v, qb);
}


#[test]
fn test_rr_cname_to_bytes()
{
    let q = ResourceRecord {
        name: String::from("wvs.spooky.com"),
        rr_type: Type::CNAME,
        rr_class: Class::IN,
        ttl: 0x89ABCDEF,
        rd_len: 0xFEED,
        rdata: RData::CNAME(String::from("www.halloween.fr")),
    };

    let mut v = Vec::new();
    v.push(3);
    v.extend(b"wvs");
    v.push(6);
    v.extend(b"spooky");
    v.push(3);
    v.extend(b"com");
    v.push(0);
    v.extend(&[0x00, 0x05]);
    v.extend(&[0x00, 0x01]);
    v.extend(&[0x89, 0xAB, 0xCD, 0xEF]);
    v.extend(&[0xFE, 0xED]);
    v.push(3);
    v.extend(b"www");
    v.push(9);
    v.extend(b"halloween");
    v.push(2);
    v.extend(b"fr");
    v.push(0);

    assert_eq!(v, q.to_bytes());
}

#[test]
fn message_all_lowval_to_bytes()
{
    let h = Header {
        id: 0x0,
        qr: QR::Query,
        op: OpCode::StdQuery,
        auth_answ: false,
        trunc_resp: false,
        rec_desired: false,
        rec_avail: false,
        rcode: RespCode::Ok,
        qd_count: 0,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let m = Message {
        header: h,
        quests: None,
        answs: None,
        auths: None,
        adds: None,
    };

    let v: Vec<u8> = vec![0; 12];

    assert_eq!(v, m.to_bytes())
}

#[test]
fn message_all_highval_to_bytes()
{
    let h = Header {
        id: 0xFFFF,
        qr: QR::Response,
        op: OpCode::Status,
        auth_answ: true,
        trunc_resp: true,
        rec_desired: true,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 0xFFFF,
        an_count: 0x0000,
        ns_count: 0xABCD,
        ar_count: 0xDCBA,
    };

    let m = Message {
        header: h,
        quests: None,
        answs: None,
        auths: None,
        adds: None,
    };

    let v: Vec<u8> = vec![
        0xFF, 0xFF,
        0b10010111, 0b10000101,
        0xFF, 0xFF,
        0x00, 0x00,
        0xAB, 0xCD,
        0xDC, 0xBA,
    ];

    assert_eq!(v, m.to_bytes())
}

#[test]
fn question_simple_to_bytes()
{
    let h = Header {
        id: 0x0,
        qr: QR::Query,
        op: OpCode::StdQuery,
        auth_answ: false,
        trunc_resp: false,
        rec_desired: false,
        rec_avail: false,
        rcode: RespCode::Ok,
        qd_count: 0,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let qs = vec![
        Question {
            qname: String::from("www.example.com"),
            qtype: QType::A,
            qclass: QClass::IN,
        },
    ];

    let m = Message {
        header: h,
        quests: Some(qs),
        answs: None,
        auths: None,
        adds: None,
    };

    let mut v: Vec<u8> = vec![0; 12];

    v.push(3);
    v.extend("www".as_bytes());
    v.push(7);
    v.extend("example".as_bytes());
    v.push(3);
    v.extend("com".as_bytes());
    v.push(0); // str termination
    v.extend(&[0b0, 0b1]);
    v.extend(&[0b0, 0b1]);

    assert_eq!(v, m.to_bytes())
}

#[test]
fn questions_to_bytes()
{
    let h = Header {
        id: 0x0,
        qr: QR::Query,
        op: OpCode::StdQuery,
        auth_answ: false,
        trunc_resp: false,
        rec_desired: false,
        rec_avail: false,
        rcode: RespCode::Ok,
        qd_count: 0,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let qs = vec![
        Question {
            qname: String::from("www.example.com"),
            qtype: QType::A,
            qclass: QClass::IN,
        },
        Question {
            qname: String::from("www.wikipedia.org"),
            qtype: QType::AAAA,
            qclass: QClass::Any,
        },
    ];

    let m = Message {
        header: h,
        quests: Some(qs),
        answs: None,
        auths: None,
        adds: None,
    };

    let mut v: Vec<u8> = vec![0; 12];

    v.push(3);
    v.extend("www".as_bytes());
    v.push(7);
    v.extend("example".as_bytes());
    v.push(3);
    v.extend("com".as_bytes());
    v.push(0); // str termination
    v.extend(&[0b0, 0b1]);
    v.extend(&[0b0, 0b1]);

    v.push(3);
    v.extend("www".as_bytes());
    v.push(9);
    v.extend("wikipedia".as_bytes());
    v.push(3);
    v.extend("org".as_bytes());
    v.push(0); // str termination
    v.extend(&[0b0, 28]);
    v.extend(&[0b0, 0xFF]);

    assert_eq!(v, m.to_bytes())
}
