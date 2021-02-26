use std::convert::TryInto;
use std::convert::TryFrom;
use nom::error::{ Error, ErrorKind };

//  ------------ DNS Data Types -------------
pub type HeaderRow2 = ((QR, OpCode, bool, bool, bool), (bool, RespCode));

#[derive(Clone, Copy, Debug)]
pub enum QType
{
    A     = 1,
    AAAA  = 28,
    NS    = 2,
    CNAME = 5,
    PTR   = 12,
}

#[derive(Clone, Copy, Debug)]
pub enum QClass
{
    IN = 1,
    Any = 255,
}

// ------------- Header -------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QR
{
    Query,
    Response,
}

impl TryFrom<u8> for QR {
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

impl TryFrom<u8> for OpCode {
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
#[derive(Debug)]
pub struct Question<'a>
{
    pub qname: &'a str,
    pub qtype: QType,
    pub qclass: QClass,
}

impl Question<'_>
{
    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut bytes: Vec<u8> = Vec::new();

        for w in self.qname.split(".") {
            bytes.push(w.len()
                       .try_into()
                       .expect("Question::to_bytes cannot convert hostname section into u8"));
            bytes.extend(w.bytes());
        }
        bytes.push(0);

        bytes.extend(&(self.qtype as u16).to_be_bytes());
        bytes.extend(&(self.qclass as u16).to_be_bytes());

        bytes
    }
}

#[derive(Debug)]
pub struct ResourceRecord
{}

impl ResourceRecord
{
    pub fn to_bytes(&self) -> Vec<u8>
    {
        panic!()
    }
}
// ------------- Message -------------
#[derive(Debug)]
pub struct Message<'a>
{
    pub header: Header,
    pub quests: Option<&'a [Question<'a>]>,
    pub answs:  Option<&'a [ResourceRecord]>,
    pub auths:  Option<&'a [ResourceRecord]>,
    pub adds:   Option<&'a [ResourceRecord]>,

}

impl Message<'_> {
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

    pub fn build_query<'a>(id: u16, quests: &'a [Question<'a>]) -> Message<'a>
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
                qname: "www.example.com",
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
                qname: "www.example.com",
                qtype: QType::A,
                qclass: QClass::IN,
            },
            Question {
                qname: "www.example.com",
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
        v.push(7);
        v.extend("example".as_bytes());
        v.push(3);
        v.extend("com".as_bytes());
        v.push(0); // str termination
        v.extend(&[0b0, 28]);
        v.extend(&[0b0, 0xFF]);

        assert_eq!(v, m.to_bytes())
    }
}
