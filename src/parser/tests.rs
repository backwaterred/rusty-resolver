use super::*;

#[test]
fn test_parse_rname_sections()
{
    let mut v = Vec::new();
    v.push(3);
    v.extend("www".as_bytes());
    v.push(7);
    v.extend("example".as_bytes());
    v.push(3);
    v.extend("com".as_bytes());
    v.push(0);

    let (r, v_parsed) = parse_rname_section(v.as_slice()).unwrap();
    assert_eq!("www", v_parsed);
    let (r, v_parsed) = parse_rname_section(r).unwrap();
    assert_eq!("example", v_parsed);
    let (r, v_parsed) = parse_rname_section(r).unwrap();
    assert_eq!("com", v_parsed);
    let (_, v_parsed) = parse_rname_section(r).unwrap();
    assert_eq!("", v_parsed);

}

#[test]
fn test_parse_rname_mt()
{
    let mut v = Vec::new();
    v.push(0);

    let (_, v_parsed) = parse_rname(v.as_slice()).unwrap();
    assert_eq!(String::from(""), v_parsed);
}

#[test]
fn test_parse_rname()
{
    let mut v = Vec::new();
    v.push(3);
    v.extend("big".as_bytes());
    v.push(7);
    v.extend("badwolf".as_bytes());
    v.push(2);
    v.extend("co".as_bytes());
    v.push(2);
    v.extend("jp".as_bytes());
    v.push(0);

    let (_, v_parsed) = parse_rname(v.as_slice()).unwrap();
    assert_eq!(String::from("big.badwolf.co.jp"), v_parsed);
}


#[test]
fn test_pares_r2_bytes_lowvals()
{
    let v = vec![0; 2];

    let (_, ((qr, op, aa, tr, rd), (ra, rcode))) = parse_r2(v.as_slice()).unwrap();

    assert_eq!(((qr, op, aa, tr, rd), (ra, rcode)),
               ((QR::Query, OpCode::StdQuery, false, false, false), (false, RespCode::Ok)));
}

#[test]
fn test_pares_r2_bytes_highvals()
{
    let v = vec![
        0b10010111, 0b10000101,
    ];

    let (_, ((qr, op, aa, tr, rd), (ra, rcode))) = parse_r2(v.as_slice()).unwrap();

    assert_eq!(((qr, op, aa, tr, rd), (ra, rcode)),
               ((QR::Response,
                 OpCode::Status,
                 true,
                 true,
                 true),
                (true,
                 RespCode::Refused)));
}

#[test]
fn test_parse_header()
{
    let h = Header {
        id: 0xFEED,
        qr: QR::Response,
        op: OpCode::StdQuery,
        auth_answ: true,
        trunc_resp: false,
        rec_desired: true,
        rec_avail: false,
        rcode: RespCode::FormatError,
        qd_count: 0,
        an_count: 0xFF,
        ns_count: 0xAB,
        ar_count: 0xCD,
    };

    let (_, parsed_h) = parse_header(&h.to_bytes()).unwrap();

    assert_eq!(h, parsed_h);
}

#[test]
fn test_parse_header_more()
{
    let h = Header {
        id: 0xABCD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Ok,
        qd_count: 0xDE,
        an_count: 0xAD,
        ns_count: 0xBE,
        ar_count: 0xEF,
    };

    let (_, parsed_h) = parse_header(&h.to_bytes()).unwrap();

    assert_eq!(h, parsed_h);
}

#[test]
fn test_parse_question_basic()
{
    let q = Question {
        qname: String::from("www.example.com"),
        qtype: QType::A,
        qclass: QClass::IN,
    };

    let (_, parsed_q) = parse_question(&q.to_bytes()).unwrap();

    assert_eq!(q, parsed_q);
}

#[test]
fn test_parse_rr_basic()
{
    let rr = ResourceRecord {
        name: String::from("goodtubers.co.uk"),
        rr_type: Type::NS,
        rr_class: Class::IN,
        ttl: 0xDEADBEEF,
        rd_len: 0xBEAD,
        rdata: RData::NS(String::from("turnips.dns.com")),
    };

    let (_, parsed_rr) = parse_rr(&rr.to_bytes()).unwrap();

    assert_eq!(rr, parsed_rr);
}


#[test]
fn test_parse_msg_only_qs()
{
    let h = Header {
        id: 0xBEAD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 5,
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
        Question {
            qname: String::from("www.example.com"),
            qtype: QType::NS,
            qclass: QClass::IN,
        },
        Question {
            qname: String::from("www.wikipedia.org"),
            qtype: QType::CNAME,
            qclass: QClass::Any,
        },
        Question {
            qname: String::from("www.wikipedia.org"),
            qtype: QType::PTR,
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

    let m_bytes = &m.to_bytes();
    let (_, parsed_m) = parse_msg(m_bytes).unwrap();

    assert_eq!(m, parsed_m);
}

#[test]
fn test_parse_msg_rr_a()
{
    let h = Header {
        id: 0xBEAD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 0,
        an_count: 1,
        ns_count: 0,
        ar_count: 0,
    };

    let rrs = vec![
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::A,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::A(255, 254, 253, 252),
        },
    ];

    let m = Message {
        header: h,
        quests: None,
        answs: Some(rrs),
        auths: None,
        adds: None,
    };

    let m_bytes = &m.to_bytes();
    let (_, parsed_m) = parse_msg(m_bytes).unwrap();

    assert_eq!(m, parsed_m);
}

#[test]
fn test_parse_msg_rr_aaaas()
{
    let h = Header {
        id: 0xBEAD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 0,
        an_count: 2,
        ns_count: 0,
        ar_count: 0,
    };

    let rrs = vec![
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::AAAA,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::AAAA(0xDEAD,0xBEEF,0xDEAD,0xBEEF,0xDEAD,0xBEEF,0xDEAD,0xBEEF),
        },
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::AAAA,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::AAAA(0,0,0,0,0,0,0,0),
        },
    ];

    let m = Message {
        header: h,
        quests: None,
        answs: Some(rrs),
        auths: None,
        adds: None,
    };

    let m_bytes = &m.to_bytes();
    let (_, parsed_m) = parse_msg(m_bytes).unwrap();

    assert_eq!(m, parsed_m);
}

#[test]
fn test_parse_msg_rr_ns()
{
    let h = Header {
        id: 0xBEAD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 0,
        an_count: 0,
        ns_count: 1,
        ar_count: 0,
    };

    let rrs = vec![
        ResourceRecord {
            name: String::from("www.myspace.com"),
            rr_type: Type::NS,
            rr_class: Class::IN,
            ttl: 0xDEADBEEF,
            rd_len: 0xBEAD,
            rdata: RData::NS(String::from("turnips.dns.com")),
        },
    ];

    let m = Message {
        header: h,
        quests: None,
        answs: None,
        auths: Some(rrs),
        adds: None,
    };

    let m_bytes = &m.to_bytes();
    let (_, parsed_m) = parse_msg(m_bytes).unwrap();

    assert_eq!(m, parsed_m);
}

#[test]
fn test_parse_msg_rr_cname()
{
    let h = Header {
        id: 0xBEAD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 0,
        an_count: 0,
        ns_count: 0,
        ar_count: 1,
    };

    let rrs = vec![
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::CNAME,
            rr_class: Class::IN,
            ttl: 0x89ABCDEF,
            rd_len: 0xFEED,
            rdata: RData::CNAME(String::from("www.halloween.fr")),
        },
    ];

    let m = Message {
        header: h,
        quests: None,
        answs: None,
        auths: None,
        adds: Some(rrs),
    };

    let m_bytes = &m.to_bytes();
    let (_, parsed_m) = parse_msg(m_bytes).unwrap();

    assert_eq!(m, parsed_m);
}

#[test]
fn test_parse_msg_q_and_rr_many()
{
    let h = Header {
        id: 0xBEAD,
        qr: QR::Query,
        op: OpCode::IvQuery,
        auth_answ: false,
        trunc_resp: true,
        rec_desired: false,
        rec_avail: true,
        rcode: RespCode::Refused,
        qd_count: 5,
        an_count: 5,
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
        Question {
            qname: String::from("www.example.com"),
            qtype: QType::NS,
            qclass: QClass::IN,
        },
        Question {
            qname: String::from("www.wikipedia.org"),
            qtype: QType::CNAME,
            qclass: QClass::Any,
        },
        Question {
            qname: String::from("www.wikipedia.org"),
            qtype: QType::PTR,
            qclass: QClass::IN,
        },
    ];

    let rrs = vec![
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::A,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::A(255, 254, 253, 252),
        },
        ResourceRecord {
            name: String::from("www.myspace.com"),
            rr_type: Type::NS,
            rr_class: Class::IN,
            ttl: 0xDEADBEEF,
            rd_len: 0xBEAD,
            rdata: RData::NS(String::from("turnips.dns.com")),
        },
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::AAAA,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::AAAA(0xDEAD,0xBEEF,0xDEAD,0xBEEF,0xDEAD,0xBEEF,0xDEAD,0xBEEF),
        },
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::AAAA,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::AAAA(0,0,0,0,0,0,0,0),
        },
        ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::CNAME,
            rr_class: Class::IN,
            ttl: 0x89ABCDEF,
            rd_len: 0xFEED,
            rdata: RData::CNAME(String::from("www.halloween.fr")),
        },
    ];

    let m = Message {
        header: h,
        quests: Some(qs),
        answs: Some(rrs),
        auths: None,
        adds: None,
    };

    let m_bytes = &m.to_bytes();
    let (_, parsed_m) = parse_msg(m_bytes).unwrap();

    assert_eq!(m, parsed_m);
}
