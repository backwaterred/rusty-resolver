use super::*;

use nom::error::{ Error, ErrorKind };

// ------------- Header -------------
pub type HeaderRow2 = ((QR, OpCode, bool, bool, bool), (bool, RespCode));

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
