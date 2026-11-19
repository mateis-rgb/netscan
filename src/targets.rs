// Parsing des cibles (CIDR, plages, IP seule) et des specs de ports.
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub const DISCOVERY: [u16; 16] = [21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445, 3389, 5900, 8000, 8080, 8443];

// Borne dure sur le nombre d'IPs scannées (règle: boucles/traitements bornés, allocs plafonnées).
pub const MAX_IPS: u64 = 1_048_576; // 2^20

pub const TOP100: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 199, 389, 427, 443, 444, 445, 465, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1883, 1900, 2000, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
    3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999,
];

pub fn expand_targets(targets: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    let mut set = BTreeSet::new();
    for t in targets {
        if let Some((base, prefix)) = t.split_once('/') {
            let b: Ipv4Addr = base.parse().map_err(|_| format!("IP invalide: {}", base))?;
            let prefix: u32 = prefix.parse().map_err(|_| format!("préfixe invalide: {}", prefix))?;
            if prefix > 32 { return Err(format!("préfixe > 32: {}", prefix)); }
            let b = u32::from(b);
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let net = b & mask;
            let bc = net | !mask;
            let (start, end) = if prefix >= 31 { (net, bc) } else { (net + 1, bc - 1) };
            let count = end as u64 - start as u64 + 1;
            if count > MAX_IPS {
                return Err(format!("plage trop grande: {} IPs (max {})", count, MAX_IPS));
            }
            for i in start..=end { set.insert(Ipv4Addr::from(i)); } // borne explicite: start..=end
        } else if let Some((a, b)) = t.split_once('-') {
            let start: Ipv4Addr = a.parse().map_err(|_| format!("IP invalide: {}", a))?;
            let end: Ipv4Addr = if b.contains('.') {
                b.parse().map_err(|_| format!("IP invalide: {}", b))?
            } else {
                let n: u32 = b.parse().map_err(|_| format!("fin de plage invalide: {}", b))?;
                let s = u32::from(start);
                Ipv4Addr::from((s & !0xFF) | (n & 0xFF))
            };
            let (mut s, mut e) = (u32::from(start), u32::from(end));
            if e < s { std::mem::swap(&mut s, &mut e); }
            let count = e as u64 - s as u64 + 1;
            if count > MAX_IPS {
                return Err(format!("plage trop grande: {} IPs (max {})", count, MAX_IPS));
            }
            for i in s..=e { set.insert(Ipv4Addr::from(i)); }
        } else {
            set.insert(t.parse().map_err(|_| format!("cible invalide: {}", t))?);
        }
    }
    Ok(set.into_iter().collect())
}

pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut out: Vec<u16> = vec![];
    for part in spec.split(',') {
        let p = part.trim();
        if p.eq_ignore_ascii_case("all") { out = (1..=65535).collect(); break; } // "all" subsume tout
        if p.eq_ignore_ascii_case("top100") || p.eq_ignore_ascii_case("top") { out.extend_from_slice(TOP100); }
        // preset web : ports connus + 8000-9999 (dev, containers, services internes)
        if p.eq_ignore_ascii_case("web") { out.extend_from_slice(TOP100); out.extend(8000..=9999); }
        else if let Some((a, b)) = p.split_once('-') {
            let a: u16 = a.trim().parse().unwrap_or(1);
            let b: u16 = b.trim().parse().unwrap_or(65535);
            out.extend(a..=b);
        } else if let Ok(n) = p.parse::<u16>() { out.push(n); }
    }
    out.sort_unstable();
    out.dedup();
    assert!(out.windows(2).all(|w| w[0] < w[1]), "postcondition: ports triés sans doublon");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_expansion() {
        let v = expand_targets(&["192.168.1.0/30".to_string()]).unwrap();
        assert_eq!(v, vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]);
    }

    #[test]
    fn range_shorthand() {
        let v = expand_targets(&["10.0.0.250-252".to_string()]).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], Ipv4Addr::new(10, 0, 0, 250));
    }

    #[test]
    fn ports_spec() {
        assert_eq!(parse_ports("22,80,80,443"), vec![22, 80, 443]);
        assert_eq!(parse_ports("top100").len(), TOP100.len());
        assert_eq!(parse_ports("1-10").len(), 10);
        assert_eq!(parse_ports("all").len(), 65535);
    }

    #[test]
    fn web_preset() {
        let v = parse_ports("web");
        assert!(v.contains(&443) && v.contains(&8000) && v.contains(&9999) && v.contains(&8080));
        assert!(v.windows(2).all(|w| w[0] < w[1]), "trié et dédupliqué");
        // combinaison preset + ports additionnels
        let v2 = parse_ports("web,22,3000-3002");
        assert!(v2.contains(&22) && v2.contains(&3000) && v2.contains(&3002) && v2.contains(&9999));
    }
}
