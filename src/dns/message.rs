use super::*;
use super::header::*;
use super::question::*;
use super::resourcerecord::*;

// ------------- Message -------------
#[derive(Debug, PartialEq)]
pub struct Message
{
    pub header: Header,
    pub quests: Option<Vec<Question>>,
    pub answs:  Option<Vec<ResourceRecord>>,
    pub auths:  Option<Vec<ResourceRecord>>,
    pub adds:   Option<Vec<ResourceRecord>>,

}

impl Message
{
    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut bytes = Vec::new();

        let header = self.header.to_bytes();
        bytes.extend(header);

        if let Some(quests) = &self.quests {
            for q in quests {
                bytes.extend(q.to_bytes());
            }
        }

        for aces in [&self.answs, &self.auths, &self.adds].iter() {
            if let Some(ace) = aces {
                for a in ace {
                    bytes.extend(a.to_bytes());
                }
            }
        }

        bytes
    }

    pub fn build_query(id: u16, quests: Vec<Question>) -> Message
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
