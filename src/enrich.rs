// Enrichissement des hôtes : MAC (table ARP), passerelle, hostname (DNS PTR en UDP pur std),
// vendeur (OUI). Aucun process externe pour le DNS : un resolver injoignable ne fait plus
// aucun bruit et ne bloque pas.
use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

// Liste OUI de démarrage (préfixes les plus courants) — à compléter selon tes besoins.
const OUI: &[(&str, &str)] = &[
    ("00:50:56", "VMware"), ("00:0C:29", "VMware"), ("00:1C:14", "VMware"),
    ("08:00:27", "VirtualBox"), ("52:54:00", "KVM/QEMU"), ("00:15:5D", "Microsoft Hyper-V"),
    ("00:16:3E", "Xen"), ("DC:A6:32", "Raspberry Pi"), ("B8:27:EB", "Raspberry Pi"), ("E4:5F:01", "Raspberry Pi"),
    ("AC:BC:32", "Apple"), ("F0:18:98", "Apple"), ("D8:96:95", "Apple"), ("88:66:A5", "Apple"),
    ("A4:5E:60", "Apple"), ("10:DD:B1", "Apple"), ("AC:DE:48", "Apple"),
    ("00:02:B3", "Intel"), ("00:0E:0C", "Intel"), ("00:1B:21", "Intel"),
    ("00:14:22", "Dell"), ("00:21:9B", "Dell"), ("50:C7:BF", "TP-Link"), ("00:1B:54", "Cisco"),
    ("24:0A:C4", "Espressif (ESP/IoT)"), ("30:AE:A4", "Espressif (ESP/IoT)"),
];

pub fn vendor_of(mac: &str) -> String {
    if mac.len() >= 8 {
        for (oui, name) in OUI {
            if oui.eq_ignore_ascii_case(&mac[..8]) { return name.to_string(); }
        }
    }
    "inconnu".into()
}

fn valid_mac(mac: &str) -> bool {
    mac.len() == 17 && mac.matches(':').count() == 5
}

fn parse_arp(output: &str) -> BTreeMap<Ipv4Addr, String> {
    let mut m = BTreeMap::new();
    for line in output.lines() {
        // format macOS: "? (192.168.1.1) at AA:BB:CC:DD:EE:FF on en0 ifscope [ethernet]"
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(at) = toks.iter().position(|&t| t == "at") {
            if at >= 1 && at + 1 < toks.len() {
                let iptok = toks[at - 1].trim_start_matches('(').trim_end_matches(')');
                let mac = toks[at + 1].to_uppercase();
                if valid_mac(&mac) {
                    if let Ok(ip) = iptok.parse::<Ipv4Addr>() { m.insert(ip, mac); }
                }
            }
        }
    }
    m
}

pub fn arp_table() -> BTreeMap<Ipv4Addr, String> {
    match Command::new("arp").arg("-an").stderr(Stdio::null()).output() {
        Ok(out) => parse_arp(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => BTreeMap::new(),
    }
}

fn parse_ifconfig(output: &str) -> BTreeMap<Ipv4Addr, String> {
    // associe inet <ip> et ether <mac> de chaque bloc d'interface
    let mut m = BTreeMap::new();
    let mut cur_ip: Option<Ipv4Addr> = None;
    let mut cur_mac: Option<String> = None;
    for line in output.lines() {
        let t = line.trim();
        if !t.is_empty() && !line.starts_with(|c: char| c.is_whitespace()) {
            if let (Some(ip), Some(mac)) = (cur_ip.take(), cur_mac.take()) { m.insert(ip, mac); }
        }
        if let Some(rest) = t.strip_prefix("inet ") {
            if let Some(ip) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) { cur_ip = Some(ip); }
        }
        if let Some(rest) = t.strip_prefix("ether ") {
            let mac = rest.split_whitespace().next().unwrap_or("").to_uppercase();
            if valid_mac(&mac) { cur_mac = Some(mac); }
        }
    }
    if let (Some(ip), Some(mac)) = (cur_ip, cur_mac) { m.insert(ip, mac); }
    m
}

// IPs/MACs propres du Mac (l'IP locale n'apparaît jamais dans la table ARP).
pub fn local_ifaces() -> BTreeMap<Ipv4Addr, String> {
    match Command::new("ifconfig").stderr(Stdio::null()).output() {
        Ok(out) => parse_ifconfig(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => BTreeMap::new(),
    }
}

pub fn default_gateway() -> Option<Ipv4Addr> {
    if let Ok(out) = Command::new("route").args(["-n", "get", "default"]).stderr(Stdio::null()).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(r) = line.trim().strip_prefix("gateway:") {
                if let Ok(ip) = r.trim().parse() { return Some(ip); }
            }
        }
    }
    None
}

fn resolv_servers() -> Vec<Ipv4Addr> {
    let mut v = vec![];
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            if it.next() == Some("nameserver") {
                if let Some(ip) = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) { v.push(ip); }
            }
        }
    }
    v
}

fn hosts_file_lookup(ip: Ipv4Addr) -> Option<String> {
    let content = fs::read_to_string("/etc/hosts").ok()?;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut it = line.split_whitespace();
        if let (Some(a), Some(name)) = (it.next(), it.next()) {
            if a.parse::<Ipv4Addr>().ok() == Some(ip) { return Some(name.to_string()); }
        }
    }
    None
}

fn build_ptr_query(ip: Ipv4Addr, id: u16) -> Vec<u8> {
    let mut q = vec![];
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT/NSCOUNT/ARCOUNT
    for &o in ip.octets().iter().rev() {
        let s = o.to_string(); // label = représentation décimale ASCII de l'octet
        q.push(s.len() as u8);
        q.extend_from_slice(s.as_bytes());
    }
    for label in ["in-addr", "arpa"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&12u16.to_be_bytes()); // QTYPE = PTR
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    q
}

// Lit un nom DNS (avec compression par pointeurs) ; retourne (nom, offset juste après dans le flux d'origine).
fn read_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = vec![];
    let mut jumped = false;
    let mut next = 0usize;
    let mut hops = 0usize;
    loop {
        if off >= buf.len() || hops > 16 { return None; }
        let len = buf[off];
        if len & 0xC0 == 0xC0 {
            if off + 1 >= buf.len() { return None; }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[off + 1] as usize;
            if !jumped { next = off + 2; }
            jumped = true;
            off = ptr;
            hops += 1;
            continue;
        }
        if len == 0 {
            if !jumped { next = off + 1; }
            break;
        }
        let l = len as usize;
        if off + 1 + l > buf.len() { return None; }
        labels.push(String::from_utf8_lossy(&buf[off + 1..off + 1 + l]).to_string());
        off += 1 + l;
        hops += 1;
    }
    Some((labels.join("."), next))
}

fn parse_ptr_response(resp: &[u8]) -> Option<String> {
    if resp.len() < 12 { return None; }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut off = 12;
    for _ in 0..qd {
        let (_, n) = read_name(resp, off)?;
        off = n + 4; // QTYPE + QCLASS
    }
    for _ in 0..an {
        let (_, n) = read_name(resp, off)?;
        off = n;
        if off + 10 > resp.len() { return None; }
        let rtype = u16::from_be_bytes([resp[off], resp[off + 1]]);
        let rdlen = u16::from_be_bytes([resp[off + 8], resp[off + 9]]) as usize;
        let rdata_off = off + 10;
        if rdata_off + rdlen > resp.len() { return None; }
        if rtype == 12 {
            if let Some((name, _)) = read_name(resp, rdata_off) {
                let name = name.trim_end_matches('.').to_string();
                if !name.is_empty() { return Some(name); }
            }
        }
        off = rdata_off + rdlen;
    }
    None
}

// Ping ICMP via la commande système `ping -c 1` ; retourne le RTT en ms.
pub fn icmp_ping(ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
    let secs = (timeout.as_millis() as u64 / 1000).max(1);
    let out = Command::new("ping")
        .args(["-c", "1", "-W", &secs.to_string(), &ip.to_string()])
        .stderr(Stdio::null())
        .output().ok()?;
    parse_ping_time(&String::from_utf8_lossy(&out.stdout))
}

fn parse_ping_time(output: &str) -> Option<f64> {
    for line in output.lines() {
        if let Some(i) = line.find("time=") {
            let num: String = line[i + 5..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(ms) = num.parse::<f64>() { return Some(ms); }
        }
    }
    None
}

pub fn resolve_hostname(ip: Ipv4Addr) -> String {
    if let Some(h) = hosts_file_lookup(ip) { return h; }
    for srv in resolv_servers() {
        let sock = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) { Ok(s) => s, Err(_) => continue };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(800)));
        let _ = sock.set_write_timeout(Some(Duration::from_millis(800)));
        if sock.send_to(&build_ptr_query(ip, 0x1234), (srv, 53)).is_ok() {
            let mut buf = [0u8; 512];
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(name) = parse_ptr_response(&buf[..n]) { return name; }
            }
        }
    }
    "-".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_query_bytes() {
        let q = build_ptr_query(Ipv4Addr::new(1, 2, 3, 4), 0x1234);
        assert_eq!(&q[..2], &0x1234u16.to_be_bytes());
        let tail = &q[12..];
        // labels: 4, 3, 2, 1, in-addr, arpa, 0 ; puis QTYPE=12, QCLASS=1
        assert_eq!(tail[0], 1);
        assert_eq!(tail[1], b'4');
        assert_eq!(tail[2], 1);
        assert_eq!(tail[3], b'3');
        let qname_end = tail.iter().position(|&b| b == 0).unwrap();
        assert_eq!(qname_end, 4 * 2 + (1 + 7) + (1 + 4)); // 4 labels de 1 char + "in-addr" + "arpa"
        assert_eq!(&tail[qname_end + 1..qname_end + 3], &12u16.to_be_bytes());
        assert_eq!(&tail[qname_end + 3..qname_end + 5], &1u16.to_be_bytes());
    }

    #[test]
    fn parse_ptr_response_with_compression() {
        let q = build_ptr_query(Ipv4Addr::new(1, 2, 3, 4), 0x1234);
        let mut resp = vec![];
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // réponse, pas d'erreur
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&[0, 0, 0, 0]);
        resp.extend_from_slice(&q[12..]); // question
        resp.extend_from_slice(&[0xC0, 0x0C]); // name = pointeur vers offset 12
        resp.extend_from_slice(&12u16.to_be_bytes()); // PTR
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        let mut rdata = vec![];
        for label in ["host", "example", "com"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        assert_eq!(parse_ptr_response(&resp), Some("host.example.com".to_string()));
    }

    #[test]
    fn parse_ptr_response_rejects_garbage() {
        assert_eq!(parse_ptr_response(&[0u8; 5]), None);
        assert_eq!(parse_ptr_response(&[0u8; 64]), None);
    }

    #[test]
    fn arp_parsing_macos() {
        let sample = "? (192.168.1.1) at a4:5e:60:11:22:33 on en0 ifscope [ethernet]\n\
                      ? (192.168.1.20) at (incomplete) on en0 ifscope [ethernet]\n\
                      ? (10.0.0.5) at 00:50:56:aa:bb:cc on en1 ifscope [ethernet]\n";
        let m = parse_arp(sample);
        assert_eq!(m.get(&Ipv4Addr::new(192, 168, 1, 1)).map(|s| s.as_str()), Some("A4:5E:60:11:22:33"));
        assert_eq!(m.get(&Ipv4Addr::new(10, 0, 0, 5)).map(|s| s.as_str()), Some("00:50:56:AA:BB:CC"));
        assert!(!m.contains_key(&Ipv4Addr::new(192, 168, 1, 20)), "incomplete ignoré");
    }

    #[test]
    fn ifconfig_parsing() {
        let sample = "en0: flags=8863<UP,BROADCAST> mtu 1500\n\
                      \tinet 172.18.58.151 netmask 0xffffff00 broadcast 172.18.58.255\n\
                      \tether 3a:1b:2c:3d:4e:5f\n\
                      en1: flags=8963<UP> mtu 1500\n\
                      \tinet 10.0.0.8 netmask 0xff000000 broadcast 10.255.255.255\n\
                      \tether aa:bb:cc:dd:ee:ff\n";
        let m = parse_ifconfig(sample);
        assert_eq!(m.get(&Ipv4Addr::new(172, 18, 58, 151)).map(|s| s.as_str()), Some("3A:1B:2C:3D:4E:5F"));
        assert_eq!(m.get(&Ipv4Addr::new(10, 0, 0, 8)).map(|s| s.as_str()), Some("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn ping_time_parsing() {
        let mac = "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=0.123 ms\n";
        assert_eq!(parse_ping_time(mac), Some(0.123));
        let linux = "64 bytes from 10.0.0.2: icmp_seq=1 ttl=58 time=12.9 ms\n";
        assert_eq!(parse_ping_time(linux), Some(12.9));
        assert_eq!(parse_ping_time("ping: sendto: No route to host"), None);
    }
}
