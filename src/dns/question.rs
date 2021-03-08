use super::*;

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
