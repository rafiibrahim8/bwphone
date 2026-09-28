//! Just enough DNS for one job: read the questions in an mDNS query, and
//! build a one-record A answer. RFC 1035 wire format, RFC 6762 QU bit.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
/// In a question's class field: "answer me unicast".
pub const QU_BIT: u16 = 0x8000;
/// In an answer's class field: "cache flush".
pub const CACHE_FLUSH: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Lowercased, no trailing dot: `abc123.local`.
    pub name: String,
    pub qtype: u16,
    pub unicast: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub questions: Vec<Question>,
}

/// The questions in a query. `None` for anything that is not a query.
pub fn parse_query(packet: &[u8]) -> Option<Query> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut pos = 12;
    let mut questions = Vec::with_capacity(qdcount.min(16));
    for _ in 0..qdcount {
        let (name, next) = read_name(packet, pos, 0)?;
        pos = next;
        let qtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
        let qclass = u16::from_be_bytes([*packet.get(pos + 2)?, *packet.get(pos + 3)?]);
        pos += 4;
        if qclass & 0x7FFF != CLASS_IN {
            continue;
        }
        questions.push(Question { name, qtype, unicast: qclass & QU_BIT != 0 });
    }
    Some(Query { id, questions })
}

/// A name at `pos`, following compression pointers. Returns it lowercased
/// and the position after it (after the first pointer, if any).
fn read_name(packet: &[u8], mut pos: usize, depth: u8) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let target = ((len & 0x3F) << 8) | *packet.get(pos + 1)? as usize;
            let (rest, _) = read_name(packet, target, depth + 1)?;
            if !rest.is_empty() {
                labels.push(rest);
            }
            pos += 2;
            return Some((labels.join("."), pos));
        }
        let label = packet.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    Some((labels.join("."), pos))
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len().min(63) as u8);
        out.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    out.push(0);
}

/// An authoritative response with one A record and no question section:
/// what RFC 6762 §6 asks of a multicast responder.
pub fn build_a_answer(id: u16, name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + name.len() + 16);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // QR, AA
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // 0 questions, 1 answer, 0, 0
    write_name(&mut out, name);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&(CLASS_IN | CACHE_FLUSH).to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

/// The first A record in a response: what the phone does, kept here for the tests.
#[cfg(test)]
pub fn parse_a_answer(packet: &[u8]) -> Option<(String, Ipv4Addr)> {
    if packet.len() < 12 || u16::from_be_bytes([packet[2], packet[3]]) & 0x8000 == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(packet, pos, 0)?;
        pos = next + 4;
    }
    for _ in 0..ancount {
        let (name, next) = read_name(packet, pos, 0)?;
        pos = next;
        let rtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
        let rdlen = u16::from_be_bytes([*packet.get(pos + 8)?, *packet.get(pos + 9)?]) as usize;
        pos += 10;
        let rdata = packet.get(pos..pos + rdlen)?;
        if rtype == TYPE_A && rdlen == 4 {
            return Some((name, Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])));
        }
        pos += rdlen;
    }
    None
}

/// A query for one name, as the phone sends it: QU set, so the answer comes
/// back unicast rather than to the whole network.
#[cfg(test)]
pub fn build_query(id: u16, name: &str, unicast: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    write_name(&mut out, name);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&(CLASS_IN | if unicast { QU_BIT } else { 0 }).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip_and_qu_bit() {
        let q = build_query(0x1234, "Abc123.local", true);
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.questions, vec![Question { name: "abc123.local".into(), qtype: TYPE_A, unicast: true }]);
        let q = build_query(1, "x.local.", false);
        assert!(!parse_query(&q).unwrap().questions[0].unicast);
        assert!(parse_query(&[0; 5]).is_none());
    }

    #[test]
    fn answer_round_trip() {
        let a = build_a_answer(7, "abc123.local", Ipv4Addr::new(10, 0, 0, 5), 10);
        assert!(parse_query(&a).is_none(), "a response is not a query");
        assert_eq!(parse_a_answer(&a), Some(("abc123.local".into(), Ipv4Addr::new(10, 0, 0, 5))));
        assert_eq!(a[2..4], [0x84, 0x00]);
    }

    #[test]
    fn compression_pointers_are_followed_not_looped() {
        // question "a.local", then a second question pointing back at it
        let mut p = vec![0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&[1, b'a', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 0, 1]);
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        let parsed = parse_query(&p).unwrap();
        assert_eq!(parsed.questions.len(), 2);
        assert_eq!(parsed.questions[1].name, "a.local");
        // a pointer to itself must not hang
        let mut looped = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(parse_query(&looped).is_none());
    }
}
