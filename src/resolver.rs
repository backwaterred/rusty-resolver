use rand;
use std::error::Error;
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket };

use crate::dns::{ self, Message, Question };
use crate::parser::parse_msg;

const DNS_SRVR1: IpAddr = IpAddr::V4(Ipv4Addr::new(84,200,69,80));
const DNS_SRVR2: IpAddr = IpAddr::V4(Ipv4Addr::new(84,200,70,40));
const DNS_PORT: u16 = 53;
const RESP_BUFF_SIZE: usize = 128;

pub fn resolve(hostname: &str) -> Result<IpAddr, Box<dyn Error>>
{
    let qs = [
        Question {
            qname: hostname,
            qtype: dns::QType::A,
            qclass: dns::QClass::IN,
        },
        Question {
            qname: hostname,
            qtype: dns::QType::AAAA,
            qclass: dns::QClass::IN,
        },
    ];


    let id: u16 = rand::random();
    let m = Message::build_query(id, &qs);
    let m = m.to_bytes();

    let mut sock = UdpSocket::bind(":::9001")?;
    sock.send_to(m.as_slice(), (DNS_SRVR1, DNS_PORT))?;

    let mut dns_resp = [0; RESP_BUFF_SIZE];

    let (len, r_addr) = sock.recv_from(&mut dns_resp)?;

    let resp = parse_msg(&dns_resp[..len]);

    println!("Got resp:\n{:?}", resp);

    Ok(IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,1)))
}
