// Positionnement des nœuds du graphe réseau (cercle, étoile autour de la passerelle si connue).
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub type Nodes = BTreeMap<Ipv4Addr, (f64, f64)>;
pub type Edges = Vec<(Ipv4Addr, Ipv4Addr)>;

pub fn layout(ips: &[Ipv4Addr], w: f64, h: f64, gw: Option<Ipv4Addr>) -> (Nodes, Edges) {
    let mut nodes = BTreeMap::new();
    let mut edges = vec![];
    let n = ips.len();
    if n == 0 { return (nodes, edges); }
    let cx = w / 2.0;
    let cy = (h - 80.0) / 2.0 + 40.0;
    let r = ((w.min(h - 80.0)) / 2.0 - 110.0).max(60.0);
    for (i, &ip) in ips.iter().enumerate() {
        let a = -std::f64::consts::FRAC_PI_2 + 2.0 * std::f64::consts::PI * i as f64 / n as f64;
        nodes.insert(ip, (cx + r * a.cos(), cy + r * a.sin()));
    }
    match gw {
        Some(g) if nodes.contains_key(&g) => {
            for &ip in ips { if ip != g { edges.push((g, ip)); } }
        }
        _ => {
            for i in 0..n { edges.push((ips[i], ips[(i + 1) % n])); }
        }
    }
    (nodes, edges)
}
