use std::convert::TryInto;
use std::convert::TryFrom;
use nom::error::{ Error, ErrorKind };

//  ------------ DNS Helper Fns -------------

// EFFECTS: Extends given vector with string in RFC 1035 domain name format
#[inline]
fn append_rname(bytes: &mut Vec<u8>, s: &String) -> Result<(), Box<dyn std::error::Error>>
{
    for w in s.split(".")
    {
        bytes.push(w.len()
                   .try_into()?);
                   // .expect("rname_to_bytes cannot convert hostname section into u8"));
        bytes.extend(w.bytes());
    }
    bytes.push(0);

    Ok(())
}

//  ------------ DNS Data Types -------------
pub type HeaderRow2 = ((QR, OpCode, bool, bool, bool), (bool, RespCode));

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QType
{
    A     = 1,
    AAAA  = 28,
    NS    = 2,
    CNAME = 5,
    PTR   = 12,
}

impl TryFrom<u16> for QType
{
    type Error = &'static str;

    fn try_from(i: u16) -> Result<Self, Self::Error>
    {
        match i {
            1  => Ok(QType::A),
            28 => Ok(QType::AAAA),
            2  => Ok(QType::NS),
            5  => Ok(QType::CNAME),
            12 => Ok(QType::PTR),
            _  => Err("QType Value Not Supported"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type
{
    A     = 1,
    AAAA  = 28,
    NS    = 2,
    CNAME = 5,
    PTR   = 12,
}

impl TryFrom<u16> for Type
{
    type Error = &'static str;

    fn try_from(i: u16) -> Result<Self, Self::Error>
    {
        match i {
            1  => Ok(Type::A),
            28 => Ok(Type::AAAA),
            2  => Ok(Type::NS),
            5  => Ok(Type::CNAME),
            12 => Ok(Type::PTR),
            _  => Err("(RR)Type Value Not Supported"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QClass
{
    IN = 1,
    Any = 255,
}

impl TryFrom<u16> for QClass
{
    type Error = &'static str;

    fn try_from(i: u16) -> Result<Self, Self::Error>
    {
        match i {
            1   => Ok(QClass::IN),
            255 => Ok(QClass::Any),
            _   => Err("QClass Value Not Supported"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Class
{
    IN = 1,
}

impl TryFrom<u16> for Class
{
    type Error = &'static str;

    fn try_from(i: u16) -> Result<Self, Self::Error>
    {
        match i {
            1   => Ok(Class::IN),
            _   => Err("(RR)Class Value Not Supported"),
        }
    }
}

// ------------- Header -------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QR
{
    Query,
    Response,
}

impl TryFrom<u8> for QR
{
    type Error = nom::error::Error<u8>;

    fn try_from(i: u8) -> Result<Self, Self::Error>
    {
        match i {
            0 => Ok(QR::Query),
            1 => Ok(QR::Response),
            _ => Err(Error::new(i, ErrorKind::Not)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCode
{
    StdQuery = 0,
    IvQuery = 1,
    Status = 2,
}

impl TryFrom<u8> for OpCode
{
    type Error = &'static str;

    fn try_from(i: u8) -> Result<Self, Self::Error>
    {
        match i {
            0 => Ok(OpCode::StdQuery),
            1 => Ok(OpCode::IvQuery),
            2 => Ok(OpCode::Status),
            _ => Err("OpCode Value not supported"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RespCode
{
    Ok          = 0,
    FormatError = 1,
    ServFail    = 2,
    NameError   = 3,
    NotImpl     = 4,
    Refused     = 5,
}

impl TryFrom<u8> for RespCode
{
    type Error = &'static str;

    fn try_from(i: u8) -> Result<Self, Self::Error>
    {
        match i {
            0 => Ok(RespCode::Ok),
            1 => Ok(RespCode::FormatError),
            2 => Ok(RespCode::ServFail),
            3 => Ok(RespCode::NameError),
            4 => Ok(RespCode::NotImpl),
            5 => Ok(RespCode::Refused),
            _ => Err("RespCode Value not supported"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Header
{
    // r1
    pub id: u16,
    // r2-1
    pub qr: QR,
    pub op: OpCode,
    pub auth_answ: bool,
    pub trunc_resp: bool,
    pub rec_desired: bool,
    // r2-2
    pub rec_avail: bool,
    pub rcode: RespCode,
    // r3...
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl Header
{
    const QR_SHIFT: u8 = 8 - 1;
    const OP_SHIFT: u8 = 8 - 1 - 4;
    const AA_SHIFT: u8 = 8 - 1 - 4 - 1;
    const TC_SHIFT: u8 = 8 - 1 - 4 - 1 - 1;
    const RD_SHIFT: u8 = 8 - 1 - 4 - 1 - 1 - 1;

    const RA_SHIFT: u8 = 8 - 1;
    const RC_SHIFT: u8 = 8 - 1 - 3 - 4;

    pub fn new(id: u16, r2: HeaderRow2, qd_count: u16, an_count: u16, ns_count: u16, ar_count: u16) -> Self
    {
        let ((qr, op, auth_answ, trunc_resp, rec_desired),
             (rec_avail, rcode)) = r2;

        Header {
            id,
            qr,
            op,
            auth_answ,
            trunc_resp,
            rec_desired,
            rec_avail,
            rcode,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(&self.id.to_be_bytes());

        bytes.extend(self.make_r2_bytes());

        for count in [self.qd_count, self.an_count, self.ns_count, self.ar_count].iter() {
            bytes.extend(&count.to_be_bytes());
        }

        bytes
    }

    fn make_r2_bytes(&self) -> Vec<u8>
    {
        let mut b0: u8 = 0;

        b0 |= (self.qr as u8) << Header::QR_SHIFT;
        b0 |= (self.op as u8) << Header::OP_SHIFT;
        b0 |= (self.auth_answ as u8) << Header::AA_SHIFT;
        b0 |= (self.trunc_resp as u8) << Header::TC_SHIFT;
        b0 |= (self.rec_desired as u8) << Header::RD_SHIFT;

        let mut b1: u8 = 0;

        b1 |= (self.rec_avail as u8) << Header::RA_SHIFT;
        b1 |= (self.rcode as u8) << Header::RC_SHIFT;

        vec![b0, b1]
    }
}

// ------------- Resource Records -------------
#[derive(Debug, PartialEq)]
pub struct Question
{
    pub qname: String,
    pub qtype: QType,
    pub qclass: QClass,
}

impl Question
{
    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut bytes: Vec<u8> = Vec::new();

        append_rname(&mut bytes, &self.qname)
            .expect("Couldn't convert qname to bytes (section too long)");
        bytes.extend(&(self.qtype as u16).to_be_bytes());
        bytes.extend(&(self.qclass as u16).to_be_bytes());

        bytes
    }
}

#[derive(Debug, PartialEq)]
pub enum RData
{
    A(u8,u8,u8,u8),
    AAAA(u16, u16, u16, u16, u16, u16, u16, u16),
    NS(String),
    CNAME(String),
}

impl RData
{
    fn to_bytes(&self) -> Vec<u8>
    {
        match self
        {
            RData::A(b1,b2,b3,b4) => {
                let mut v = Vec::new();
                v.extend(format!("{}.{}.{}.{}", *b1, *b2, *b3, *b4).as_bytes());

                v
            },
            RData::AAAA(0, 0, 0, 0, 0, 0, 0, 0) => 
                vec![b"::"],
            RData::AAAA(tb1, tb2, tb3, tb4, tb5, tb6, tb7, tb8) => {
                let mut v = Vec::new();

                let mut last = false;
                let mut last_last = false;

                for tb in [tb1, tb2, tb3, tb4, tb5, tb6, tb7, tb8].iter()
                {

                    if **tb != 0
                    {
                        last = false;
                        last_last = false;
                        v.extend(tb.to_string().bytes());
                    }
                    else
                    {
                        last_last = last;
                        last = true;
                    }

                    if !(last && last_last)
                    {
                        v.extend(":".bytes());
                    }
                }

                v
            },
            RData::NS(rname) => {
                let mut v = Vec::new();

                append_rname(&mut v, &rname)
                    .expect("Couldn't convert NS to bytes (section too long)");

                v
            }
            RData::CNAME(rname) => {
                let mut v = Vec::new();

                append_rname(&mut v, &rname)
                    .expect("Couldn't convert CName to bytes (section too long)");

                v
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ResourceRecord
{
    pub name: String,
    pub rr_type: Type,
    pub rr_class: Class,
    pub ttl: u32,
    pub rd_len: u16,
    pub rdata: RData,
}

impl ResourceRecord
{
    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut bytes = Vec::new();

        append_rname(&mut bytes, &self.name)
            .expect("Couldn't convert RR Name to bytes (section too long)");
        bytes.extend(&(self.rr_type as u16).to_be_bytes());
        bytes.extend(&(self.rr_class as u16).to_be_bytes());
        bytes.extend(&(self.ttl).to_be_bytes());
        bytes.extend(&(self.rd_len).to_be_bytes());
        bytes.extend(self.rdata.to_bytes());

        bytes
    }
}
// ------------- Message -------------
#[derive(Debug, PartialEq)]
pub struct Message<'a>
{
    pub header: Header,
    pub quests: Option<&'a [Question]>,
    pub answs:  Option<&'a [ResourceRecord]>,
    pub auths:  Option<&'a [ResourceRecord]>,
    pub adds:   Option<&'a [ResourceRecord]>,

}

impl Message<'_>
{
    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut bytes = Vec::new();

        let header = self.header.to_bytes();
        bytes.extend(header);

        if let Some(quests) = self.quests {
            for q in quests {
                bytes.extend(q.to_bytes());
            }
        }

        for aces in [self.answs, self.auths, self.adds].iter() {
            if let Some(ace) = aces {
                for a in *ace {
                    bytes.extend(a.to_bytes());
                }
            }
        }

        bytes
    }

    pub fn build_query<'a>(id: u16, quests: &'a [Question]) -> Message<'a>
    {
        let qd_count: u16 = quests.len()
                                    .try_into()
                                    .expect("Message::build_query couldn't parse number of questions as u16");
        let header = Header {
            id,
            qr: QR::Query,
            op: OpCode::StdQuery,
            auth_answ: false,
            trunc_resp: false,
            rec_desired: false,
            rec_avail: false,
            rcode: RespCode::Ok,
            qd_count,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        Message {
            header,
            quests: Some(quests),
            answs: None,
            auths: None,
            adds: None,
        }
    }

}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn gl_test()
    {
    }

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
    fn test_rr_A_IN_to_bytes()
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
        v.extend("255.254.253.252".bytes());

        assert_eq!(v, q.to_bytes());
    }

    #[test]
    fn test_rr_AAAA_IN_to_bytes()
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
        v.extend("57005:48879:57005:48879:57005:48879:57005:48879".bytes());

        assert_eq!(v, q.to_bytes());
    }

    #[test]
    fn test_rr_AAAA_IN_localhost_to_bytes()
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
        v.extend("::1".bytes());

        assert_eq!(v, q.to_bytes());
    }

    #[test]
    fn test_rr_AAAA_IN_internal_zs_to_bytes()
    {
        let q = ResourceRecord {
            name: String::from("wvs.spooky.com"),
            rr_type: Type::AAAA,
            rr_class: Class::IN,
            ttl: 0xBEEFDEAD,
            rd_len: 0xDEEF,
            rdata: RData::AAAA(2001,1608,10,25,0,0,9249,0xd69b),
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
        v.extend("2001:1608:10:25::9249:d69b".bytes());

        assert_eq!(v, q.to_bytes());
    }


    #[test]
    fn test_rr_CNAME_to_bytes()
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

        let qs = [
            Question {
                qname: String::from("www.example.com"),
                qtype: QType::A,
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
        ];

        let m = Message {
            header: h,
            quests: Some(&qs),
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
}
