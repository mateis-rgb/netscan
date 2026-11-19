// Exports : JSON, CSV, HTML (graphe SVG + table) et dispatch PNG. Écriture manuelle, zéro dépendance.
use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;

use crate::graph::layout;
use crate::model::{service, Host, Scan};

pub fn run_exports(s: &Scan, exports: &[String], out: &str) {
    for e in exports {
        let path = format!("{}.{}", out, e);
        let r = match e.as_str() {
            "json" => fs::write(&path, to_json(s)),
            "csv" => fs::write(&path, to_csv(s)),
            "html" => fs::write(&path, to_html(s)),
            "png" => { let img = crate::png::to_png(s); crate::png::write_png(&path, &img) }
            _ => { eprintln!("[!] export inconnu ignoré: {}", e); continue; }
        };
        match r {
            Ok(()) => println!("[+] export: {}", path),
            Err(err) => eprintln!("[!] échec export {}: {}", path, err),
        }
    }
}

fn jesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn to_json(s: &Scan) -> String {
    let mut o = String::from("{\n  \"scan\": {");
    o.push_str(&format!("\"targets\": [{}], ", s.targets.iter().map(|t| format!("\"{}\"", jesc(t))).collect::<Vec<_>>().join(", ")));
    o.push_str(&format!("\"ports\": \"{}\", \"started_unix\": {}, \"duration_s\": {:.2}, \"timeout_ms\": {}, \"workers\": {}, ",
        jesc(&s.ports_desc), s.started_unix, s.duration_s, s.timeout_ms, s.workers));
    let up = s.hosts.iter().filter(|h| h.up).count();
    o.push_str(&format!("\"hosts_total\": {}, \"hosts_up\": {}", s.hosts.len(), up));
    o.push_str("},\n  \"hosts\": [");
    for (i, h) in s.hosts.iter().enumerate() {
        let ping = match h.rtt_ms { Some(v) => format!("{:.2}", v), None => "null".into() };
        o.push_str(&format!(
            "{{\"ip\": \"{}\", \"up\": {}, \"hostname\": \"{}\", \"mac\": \"{}\", \"vendor\": \"{}\", \"ping_ms\": {}, \"open_ports\": [",
            h.ip, h.up, jesc(&h.hostname), jesc(&h.mac), jesc(&h.vendor), ping));
        for (j, p) in h.open_ports.iter().enumerate() {
            o.push_str(&format!("{{\"port\": {}, \"service\": \"{}\", \"banner\": \"{}\"}}",
                p.port, jesc(&service(p.port)), jesc(&p.banner)));
            if j + 1 < h.open_ports.len() { o.push(','); }
        }
        o.push(']');
        o.push('}');
        if i + 1 < s.hosts.len() { o.push(','); }
    }
    o.push_str("]\n}\n");
    o
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

fn to_csv(s: &Scan) -> String {
    let mut o = String::from("ip,up,hostname,mac,vendor,ping_ms,ports_ouverts,services\n");
    for h in &s.hosts {
        let ports = h.open_ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(" ");
        let svcs = h.open_ports.iter().map(|p| service(p.port)).collect::<Vec<_>>().join("; ");
        let ping = h.rtt_ms.map(|v| format!("{:.2}", v)).unwrap_or_default();
        o.push_str(&format!("{},{},{},{},{},{},{},{}\n",
            h.ip, h.up, csv_field(&h.hostname), csv_field(&h.mac), csv_field(&h.vendor), ping,
            csv_field(&ports), csv_field(&svcs)));
    }
    o
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn to_html(s: &Scan) -> String {
    let up: Vec<Ipv4Addr> = s.hosts.iter().filter(|h| h.up).map(|h| h.ip).collect();
    let by_ip: BTreeMap<Ipv4Addr, &Host> = s.hosts.iter().map(|h| (h.ip, h)).collect();
    let w = 1600.0;
    let h = 1150.0;
    let (nodes, edges) = layout(&up, w, h, s.gw);
    let mut svg = format!("<svg width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"background:#0d1117\">", w as usize, h as usize, w as usize, h as usize);
    for (a, b) in &edges {
        let (x1, y1) = nodes[a];
        let (x2, y2) = nodes[b];
        svg.push_str(&format!("<line x1=\"{:.0}\" y1=\"{:.0}\" x2=\"{:.0}\" y2=\"{:.0}\" stroke=\"#475569\" stroke-width=\"1.5\"/>", x1, y1, x2, y2));
    }
    for ip in &up {
        let (x, y) = nodes[ip];
        let host = by_ip[ip];
        let color = if host.open_ports.is_empty() { "#f59e0b" } else { "#22c55e" };
        let title = format!("{} — {} — MAC {} — {} — {} port(s) ouvert(s)", ip, host.hostname, host.mac, host.vendor, host.open_ports.len());
        svg.push_str(&format!(
            "<g><circle cx=\"{:.0}\" cy=\"{:.0}\" r=\"9\" fill=\"{}\" stroke=\"#0d1117\" stroke-width=\"2\"><title>{}</title></circle>\
             <text x=\"{:.0}\" y=\"{:.0}\" fill=\"#cbd5e1\" font-size=\"13\" font-family=\"monospace\" text-anchor=\"middle\">{}</text></g>",
            x, y, color, esc(&title), x, y + 26.0, ip));
    }
    svg.push_str("</svg>");
    let mut rows = String::new();
    for h in s.hosts.iter().filter(|h| h.up) {
        let ports = h.open_ports.iter().map(|p| {
            let b = if p.banner.is_empty() { String::new() } else { format!(" <i>[{}]</i>", esc(&p.banner)) };
            format!("<b>{}</b> {}{}", p.port, esc(&service(p.port)), b)
        }).collect::<Vec<_>>().join("<br>");
        let ping = h.rtt_ms.map(|v| format!("{:.1} ms", v)).unwrap_or_else(|| "-".into());
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            h.ip, esc(&h.hostname), esc(&h.mac), esc(&h.vendor), ping, ports));
    }
    format!("<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>netscan — {}</title>\
        <style>body{{background:#0d1117;color:#e2e8f0;font-family:system-ui,sans-serif;margin:24px}} \
        h1{{font-size:20px}} .meta{{color:#94a3b8;font-size:13px;margin-bottom:16px}} \
        table{{border-collapse:collapse;margin-top:24px;font-size:13px}} td,th{{border:1px solid #334155;padding:6px 12px;text-align:left}} \
        th{{background:#1e293b}} i{{color:#64748b}}</style></head><body>\
        <h1>netscan — rapport de scan</h1>\
        <div class=\"meta\">cibles: {} | ports: {} | {} hôtes up / {} scannés | durée {:.2}s | timeout {} ms</div>\
        {} \
        <table><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendeur</th><th>Ping</th><th>Ports ouverts</th></tr>{}</table>\
        </body></html>",
        esc(&s.targets.join(", ")), esc(&s.targets.join(", ")), esc(&s.ports_desc),
        up.len(), s.hosts.len(), s.duration_s, s.timeout_ms, svg, rows)
}
