
use crate::dns;
use nom::{ IResult };
use nom::number::complete::{ be_u16 };
use nom::{ bits, do_parse, map, map_res, named, take, take_bits, tuple };
use std::convert::TryFrom;

#[inline]
fn boolify(n: u8) -> bool
{
    n != 0
}

// ----- Header -----
named!(parse_r2_first<(dns::QR,dns::OpCode,bool,bool,bool)>,
       bits!(
           tuple!(
               map_res!(take_bits!(1u8),
                        |b: u8| dns::QR::try_from(b)
               ),
               map_res!(take_bits!(4u8),
                        |b: u8| dns::OpCode::try_from(b)
               ),
               map!(take_bits!(1u8), boolify),
               map!(take_bits!(1u8), boolify),
               map!(take_bits!(1u8), boolify)
           )
       )
);

named!(parse_r2_second<(bool,dns::RespCode)>,
       bits!(
           tuple!(
               map!(take_bits!(1u8), boolify),
               map_res!(
                   take_bits!(7u8),
                   |b: u8| dns::RespCode::try_from(b)
               )
           )
       )
);

named!(parse_r2<dns::HeaderRow2>,
       tuple!(
           parse_r2_first,
           parse_r2_second
       )
);

use dns::Header;
named!(parse_header<dns::Header>,
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
// TODO

// ----- Message -----
named!(parse_msg<dns::Message>,
       do_parse!(
           h: parse_header >>
           ...
           m: map!(take!(0), |_| Message { header, ... })
       )
);
// consider named!(pub parse_message(...), ...)
// pub fn parse_msg(input: &[u8]) -> IResult<&[u8], dns::Message>
// {
//     panic!()
// }

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
                   ((dns::QR::Query, dns::OpCode::StdQuery, false, false, false), (false, dns::RespCode::Ok)));
    }
   
    #[test]
    fn test_pares_r2_bytes_highvals()
    {
        let v = vec![
            0b10010111, 0b10000101,
        ];

        let (_, ((qr, op, aa, tr, rd), (ra, rcode))) = parse_r2(v.as_slice()).unwrap();

        assert_eq!(((qr, op, aa, tr, rd), (ra, rcode)),
                   ((dns::QR::Response,
                     dns::OpCode::Status,
                     true,
                     true,
                     true),
                    (true,
                     dns::RespCode::Refused)));
    }

    #[test]
    fn test_parse_header()
    {
        let h = dns::Header {
            id: 0xFEED,
            qr: dns::QR::Response,
            op: dns::OpCode::StdQuery,
            auth_answ: true,
            trunc_resp: false,
            rec_desired: true,
            rec_avail: false,
            rcode: dns::RespCode::FormatError,
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
        let h = dns::Header {
            id: 0xABCD,
            qr: dns::QR::Query,
            op: dns::OpCode::IvQuery,
            auth_answ: false,
            trunc_resp: true,
            rec_desired: false,
            rec_avail: true,
            rcode: dns::RespCode::Ok,
            qd_count: 0xDE,
            an_count: 0xAD,
            ns_count: 0xBE,
            ar_count: 0xEF,
        };

        let (_, parsed_h) = parse_header(&h.to_bytes()).unwrap();

        assert_eq!(h, parsed_h);
    }
}
