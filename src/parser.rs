
use nom::{ IResult };
use nom::number::complete::{ be_u8, be_u16, be_u32 };
use nom::{
    alt,
    bits, do_parse, fold_many0, map,
    map_res, named, take, take_str,
    take_until, take_bits, tuple,
};
use std::convert::TryFrom;

use crate::dns::{
    Header, HeaderRow2, Question,
    Message, QType, QClass, Type,
    Class, RespCode, QR, OpCode,
    ResourceRecord, RData
};

// ----- Helpers -----
#[inline]
fn boolify(n: u8) -> bool
{
    n != 0
}

fn merge_str(mut acc: String, s: &str) -> String
{
    if !s.is_empty()
    {
        acc.push_str(s);
        acc.push_str(".");
        acc
    } else
    {
        acc
    }
}

named!(parse_rname_section<&str>,
    do_parse!(
        len: be_u8 >>
        section: take_str!(len) >>
        (section)
    )
);

fn parse_rname(input: &[u8]) -> IResult<&[u8], String>
{
    named!(take_rname<&[u8]>,
           take_until!("\0")
    );

    named!(parse_rname_inner<String>,
           fold_many0!(parse_rname_section, String::new(), merge_str)
    );

    let (r, rname_input) = take_rname(input)?;
    let (_, mut s) = parse_rname_inner(rname_input)?;

    // advance 'r' to remove '0' left behind by take_until
    let (r, _) = be_u8(r)?;

    if !s.is_empty()
    {
        s.pop();
        Ok((r, s))
    } else
    {
        Ok((r, s))
    }
}

// ----- Header -----
named!(parse_r2_first<(QR,OpCode,bool,bool,bool)>,
       bits!(
           tuple!(
               map_res!(take_bits!(1u8),
                        |b: u8| QR::try_from(b)
               ),
               map_res!(take_bits!(4u8),
                        |b: u8| OpCode::try_from(b)
               ),
               map!(take_bits!(1u8), boolify),
               map!(take_bits!(1u8), boolify),
               map!(take_bits!(1u8), boolify)
           )
       )
);

named!(parse_r2_second<(bool,RespCode)>,
       bits!(
           tuple!(
               map!(take_bits!(1u8), boolify),
               map_res!(
                   take_bits!(7u8),
                   |b: u8| RespCode::try_from(b)
               )
           )
       )
);

named!(parse_r2<HeaderRow2>,
       tuple!(
           parse_r2_first,
           parse_r2_second
       )
);

named!(parse_header<Header>,
       do_parse!(
           id: be_u16       >>
           r2: parse_r2     >>
           qd_count: be_u16 >>
           an_count: be_u16 >>
           ns_count: be_u16 >>
           ar_count: be_u16 >>
           h: map!(take!(0), |_| Header::new(id, r2, qd_count, an_count, ns_count, ar_count)) >>
           (h)
       )
);

// ----- Question -----
named!(parse_question<Question>,
       do_parse!(
           qname: parse_rname >>
           qtype: map_res!(be_u16, | b: u16 | QType::try_from(b)) >>
           qclass: map_res!(be_u16, | b: u16 | QClass::try_from(b)) >>
           (Question { qname, qclass, qtype })
       )
);

// ----- ResourceRecord -----
// named!(parse_rdata_A<RData>,
//        // TODO: COmplete this stub method
//        take!(0)
// );
//
// named!(parse_rdata_AAAA<RData>,
//        // TODO: COmplete this stub method
//        take!(0)
// );
//
// named!(parse_rdata<RData>,
//        // TODO: COmplete this stub method
//        // see: alt!(???) this may not do quite what I want...
//        alt!(parse_rdata_A |
//             parse_rdata_AAAA
//        )
// );

named!(parse_rr<ResourceRecord>,
       do_parse!(
           name: parse_rname >>
           rr_type: map_res!(be_u16, | b: u16 | Type::try_from(b)) >>
           rr_class: map_res!(be_u16, | b: u16 | Class::try_from(b)) >>
           ttl: be_u32 >>
           rd_len: be_u16 >>
           // rdata: parse_rdata >>
           (ResourceRecord { name, rr_type, rr_class, ttl, rd_len, rdata: RData::CNAME(String::from("STUB!!!")) })
       )
);

// ----- Message -----
named!(pub parse_msg<Message>,
       do_parse!(
           header: parse_header >>
           (Message { header, quests: None, answs: None, auths: None, adds: None })
       )
);

#[cfg(test)]
mod tests
{
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
        let (r, v_parsed) = parse_rname_section(r).unwrap();
        assert_eq!("", v_parsed);

    }

    #[test]
    fn test_parse_rname_mt()
    {
        let mut v = Vec::new();
        v.push(0);

        let (r, v_parsed) = parse_rname(v.as_slice()).unwrap();
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

        let (r, v_parsed) = parse_rname(v.as_slice()).unwrap();
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
            qd_count: 0xFF,
            an_count: 0xAF,
            ns_count: 0xBF,
            ar_count: 0xCF,
        };

        let qs = [
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
                qtype: QType::NS,
                qclass: QClass::IN,
            },
];

        let m = Message {
            header: h,
            quests: Some(&qs),
            answs: None,
            auths: None,
            adds: None,
        };

        let m_bytes = &m.to_bytes();
        let (_, parsed_m) = parse_msg(m_bytes).unwrap();

        assert_eq!(m, parsed_m);
    }

#[test]
    fn test_parse_msg_only_rrs()
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
            qd_count: 0xFF,
            an_count: 0xAF,
            ns_count: 0xBF,
            ar_count: 0xCF,
        };

        let rrs = [
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
            answs: Some(&rrs),
            auths: Some(&rrs),
            adds: Some(&rrs),
        };

        let m_bytes = &m.to_bytes();
        let (_, parsed_m) = parse_msg(m_bytes).unwrap();

        assert_eq!(m, parsed_m);
    }
}
