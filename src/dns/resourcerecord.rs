use super::*;

// ------------- Resource Record -------------
#[derive(Debug, PartialEq)]
pub enum RData
{
    A(u8,u8,u8,u8),
    AAAA(u16, u16, u16, u16, u16, u16, u16, u16),
    NS(String),
    CNAME(String),
    PTR(String,)
}

impl RData
{
    fn to_bytes(&self) -> Vec<u8>
    {
        match self
        {
            RData::A(b1,b2,b3,b4) => {
                let mut v = Vec::new();
                v.push(*b1);
                v.push(*b2);
                v.push(*b3);
                v.push(*b4);

                v
            },
            RData::AAAA(tb1, tb2, tb3, tb4, tb5, tb6, tb7, tb8) => {
                let mut v: Vec<u8> = Vec::new();

                v.extend(&tb1.to_be_bytes());
                v.extend(&tb2.to_be_bytes());
                v.extend(&tb3.to_be_bytes());
                v.extend(&tb4.to_be_bytes());
                v.extend(&tb5.to_be_bytes());
                v.extend(&tb6.to_be_bytes());
                v.extend(&tb7.to_be_bytes());
                v.extend(&tb8.to_be_bytes());

                v
            },
            RData::NS(rname) => {
                let mut v = Vec::new();

                append_rname(&mut v, &rname)
                    .expect("Couldn't convert NS domain name to bytes (section too long)");

                v
            }
            RData::CNAME(rname) => {
                let mut v = Vec::new();

                append_rname(&mut v, &rname)
                    .expect("Couldn't convert CName domain name to bytes (section too long)");

                v
            }
            RData::PTR(rname) => {
                let mut v = Vec::new();

                append_rname(&mut v, &rname)
                    .expect("Couldn't convert PTR domain name to bytes (section too long)");

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
