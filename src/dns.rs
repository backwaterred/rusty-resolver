use std::convert::TryInto;
use std::convert::TryFrom;

pub mod header;
pub mod message;
pub mod question;
pub mod resourcerecord;

#[cfg(test)]
mod tests;

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

