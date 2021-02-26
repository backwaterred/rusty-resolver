
// use nom::{ IResult };
use nom::number::complete::{ be_u16 };
use nom::character::is_alphanumeric;
use nom::{
    bits, do_parse, map, map_res, named,
    take, take_bits, take_while,
    tuple };
use std::convert::TryFrom;

use crate::dns::{ Header, HeaderRow2, Question, Message, QType, QClass, RespCode, QR, OpCode };

#[inline]
fn boolify(n: u8) -> bool
{
    n != 0
}

named!(parse_rname_section<&str>,
       do_parse!(
           len: be_u16 >>
           // section: map!(take!(len), take_while!(is_alphanumeric)) >>
           section: take!(len) >>
           (section)
       )
);

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
       // TODO!
       take!(0)
);

// ----- Message -----
named!(pub parse_msg<Message>,
       do_parse!(
           header: parse_header >>
           m: map!(take!(0), |_| Message { header, quests: None, answs: None, auths: None, adds: None }) >>
           (m)
       )
);

#[cfg(test)]
mod tests
{
    use super::*;

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
            qname: "www.example.com",
            qtype: QType::A,
            qclass: QClass::IN,
        };

        let (_, parsed_q) = parse_question(&q.to_bytes()).unwrap();

        assert_eq!(q, parsed_q);
    }
}
