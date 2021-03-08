
use crate::dns::{
    QType, QClass, Type, Class,
    header::Header, header::HeaderRow2, header::QR, header::OpCode, header::RespCode,
    message::Message,
    question::Question,
    resourcerecord::ResourceRecord, resourcerecord::RData
};
// use nom::lib::std::ops::Fn;
use nom::{ IResult };
use nom::combinator::{ map_res };
use nom::number::complete::{ be_u8, be_u16, be_u32 };
use nom::{
    dbg_dmp,
    bits, do_parse, fold_many0, map, many_m_n,
    map_res, named, take_str,
    take_until, take_bits, tuple,
};

use std::convert::TryFrom;

#[cfg(test)]
mod tests;

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
           (Header::new(id, r2, qd_count, an_count, ns_count, ar_count))
       )
);

// ----- Question -----
named!(parse_question<Question>,
       dbg_dmp!(
       do_parse!(
           qname: parse_rname >>
           qtype: map_res!(be_u16, | b: u16 | QType::try_from(b)) >>
           qclass: map_res!(be_u16, | b: u16 | QClass::try_from(b)) >>
           (Question { qname, qclass, qtype })
       )
       )
);

// ----- ResourceRecord -----
named!(parse_rdata_a<RData>,
       do_parse!(
           b1: be_u8 >>
           b2: be_u8 >>
           b3: be_u8 >>
           b4: be_u8 >>
           (RData::A(b1,b2,b3,b4))
       )
);

named!(parse_rdata_aaaa<RData>,
       // TODO: Complete this stub method
       do_parse!(
           tb1: be_u16 >>
           tb2: be_u16 >>
           tb3: be_u16 >>
           tb4: be_u16 >>
           tb5: be_u16 >>
           tb6: be_u16 >>
           tb7: be_u16 >>
           tb8: be_u16 >>
           (RData::AAAA(tb1,tb2,tb3,tb4,tb5,tb6,tb7,tb8))
       )
);

named!(parse_rdata_ns<RData>,
       do_parse!(
           rname: parse_rname >>
           (RData::NS(rname))
       )
);

named!(parse_rdata_cname<RData>,
       do_parse!(
           rname: parse_rname >>
           (RData::CNAME(rname))
       )
);

named!(parse_rdata_ptr<RData>,
       do_parse!(
           rname: parse_rname >>
           (RData::PTR(rname))
       )
);

fn parse_rdata(t: Type)
              -> impl Fn(&[u8]) -> IResult<&[u8], RData>
{
    match t
    {
        Type::A =>
            parse_rdata_a,
        Type::AAAA =>
            parse_rdata_aaaa,
        Type::NS =>
            parse_rdata_ns,
        Type::CNAME =>
            parse_rdata_cname,
        Type::PTR =>
            parse_rdata_ptr,
    }
}

fn parse_rr(input: &[u8]) -> IResult<&[u8], ResourceRecord>
{
    let (rest, name) = parse_rname(input)?;
    let (rest, rr_type) = map_res(be_u16, Type::try_from)(rest)?;
    let (rest, rr_class) = map_res(be_u16, Class::try_from)(rest)?;
    let (rest, ttl) = be_u32(rest)?;
    let (rest, rd_len) = be_u16(rest)?;
    let (rest, rdata) = parse_rdata(rr_type)(rest)?;

    Ok((rest, ResourceRecord { name, rr_type, rr_class, ttl, rd_len, rdata }))
}

// ----- Message -----
named!(pub parse_msg<Message>,
       do_parse!(
           header: parse_header >>
           quests: many_m_n!(header.qd_count.into(),
                             header.qd_count.into(),
                             parse_question) >>
           answs: many_m_n!(header.an_count.into(),
                            header.an_count.into(),
                            parse_rr) >>
           auths: many_m_n!(header.ns_count.into(),
                            header.ns_count.into(),
                            parse_rr) >>
           adds: many_m_n!(header.ar_count.into(),
                           header.ar_count.into(),
                           parse_rr) >>
          (Message { header,
                     quests: if quests.is_empty() { None } else { Some(quests) },
                     answs:  if answs.is_empty() { None } else { Some(answs) },
                     auths:  if auths.is_empty() { None } else { Some(auths) },
                     adds:   if adds.is_empty() { None } else { Some(adds) },
          })
       )
);
