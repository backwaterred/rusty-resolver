use rand;
use std::error::Error;
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket };

use crate::dns::{ self, message::Message, question::Question };
use crate::parser::parse_msg;

const DNS_SRVR1: IpAddr = IpAddr::V4(Ipv4Addr::new(192,168,1,253));
// const DNS_SRVR1: IpAddr = IpAddr::V4(Ipv4Addr::new(84,200,69,80));
// const DNS_SRVR2: IpAddr = IpAddr::V4(Ipv4Addr::new(84,200,70,40));
const DNS_PORT: u16 = 53;
const RESP_BUFF_SIZE: usize = 128;

pub fn resolve(hostname: &str) -> Result<IpAddr, Box<dyn Error>>
{
    let qs = vec![
        Question {
            qname: hostname.to_string(),
            qtype: dns::QType::A,
            qclass: dns::QClass::IN,
        },
        Question {
            qname: hostname.to_string(),
            qtype: dns::QType::AAAA,
            qclass: dns::QClass::IN,
        },
    ];


    let id: u16 = rand::random();
    let m = Message::build_query(id, qs);
    let m = m.to_bytes();

    let sock = UdpSocket::bind(":::9001")?;
    sock.send_to(m.as_slice(), (DNS_SRVR1, DNS_PORT))?;

    let mut dns_resp = [0; RESP_BUFF_SIZE];

    let (len, _addr) = sock.recv_from(&mut dns_resp)?;

    if let Ok(resp) = parse_msg(&dns_resp[..len])
    {
        println!("Got resp:\n{:?}", resp);
    }

    Ok(IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,1)))
}
