// Rendu PNG 100% std : image palettée 8 bits + encodeur zlib "stored blocks" + police 5x7 maison.
use std::fs;
use std::net::Ipv4Addr;
use std::collections::BTreeMap;

use crate::graph::layout;
use crate::model::{Host, Scan};

const PALETTE: [[u8; 3]; 6] = [
    [13, 17, 23],      // 0 fond
    [71, 85, 105],     // 1 arêtes
    [34, 197, 94],     // 2 nœud avec ports ouverts
    [245, 158, 11],    // 3 nœud up sans port ouvert
    [226, 232, 240],   // 4 texte
    [248, 250, 252],   // 5 titre
];

fn glyph(c: char) -> [&'static str; 7] {
    match c {
        '0' => ["01110","10001","10011","10101","11001","10001","01110"],
        '1' => ["00100","01100","00100","00100","00100","00100","01110"],
        '2' => ["01110","10001","00001","00010","00100","01000","11111"],
        '3' => ["01110","10001","00001","00110","00001","10001","01110"],
        '4' => ["00010","00110","01010","10010","11111","00010","00010"],
        '5' => ["11111","10000","11110","00001","00001","10001","01110"],
        '6' => ["01110","10000","10000","11110","10001","10001","01110"],
        '7' => ["11111","00001","00010","00100","00100","00100","00100"],
        '8' => ["01110","10001","10001","01110","10001","10001","01110"],
        '9' => ["01110","10001","10001","01111","00001","00001","01110"],
        'A' => ["01110","10001","10001","11111","10001","10001","10001"],
        'B' => ["11110","10001","10001","11110","10001","10001","11110"],
        'C' => ["01110","10001","10000","10000","10000","10001","01110"],
        'D' => ["11110","10001","10001","10001","10001","10001","11110"],
        'E' => ["11111","10000","10000","11110","10000","10000","11111"],
        'F' => ["11111","10000","10000","11110","10000","10000","10000"],
        'G' => ["01110","10001","10000","10111","10001","10001","01111"],
        'H' => ["10001","10001","10001","11111","10001","10001","10001"],
        'I' => ["01110","00100","00100","00100","00100","00100","01110"],
        'J' => ["00111","00010","00010","00010","00010","10010","01100"],
        'K' => ["10001","10010","10100","11000","10100","10010","10001"],
        'L' => ["10000","10000","10000","10000","10000","10000","11111"],
        'M' => ["10001","11011","10101","10101","10001","10001","10001"],
        'N' => ["10001","11001","11001","10101","10011","10011","10001"],
        'O' => ["01110","10001","10001","10001","10001","10001","01110"],
        'P' => ["11110","10001","10001","11110","10000","10000","10000"],
        'Q' => ["01110","10001","10001","10001","10101","10010","01101"],
        'R' => ["11110","10001","10001","11110","10100","10010","10001"],
        'S' => ["01111","10000","10000","01110","00001","00001","11110"],
        'T' => ["11111","00100","00100","00100","00100","00100","00100"],
        'U' => ["10001","10001","10001","10001","10001","10001","01110"],
        'V' => ["10001","10001","10001","10001","10001","01010","00100"],
        'W' => ["10001","10001","10001","10101","10101","11011","10001"],
        'X' => ["10001","10001","01010","00100","01010","10001","10001"],
        'Y' => ["10001","10001","01010","00100","00100","00100","00100"],
        'Z' => ["11111","00001","00010","00100","01000","10000","11111"],
        '.' => ["00000","00000","00000","00000","00000","01100","01100"],
        ':' => ["00000","01100","01100","00000","01100","01100","00000"],
        '-' => ["00000","00000","00000","11111","00000","00000","00000"],
        '/' => ["00001","00010","00010","00100","01000","01000","10000"],
        ' ' => ["00000","00000","00000","00000","00000","00000","00000"],
        _   => ["01110","10001","00001","00010","00100","00000","00100"], // '?'
    }
}

pub struct Img { w: usize, h: usize, px: Vec<u8> }

impl Img {
    fn new(w: usize, h: usize, bg: u8) -> Self { Img { w, h, px: vec![bg; w * h] } }

    fn set(&mut self, x: i32, y: i32, c: u8) {
        if x >= 0 && y >= 0 && (x as usize) < self.w && (y as usize) < self.h {
            self.px[y as usize * self.w + x as usize] = c;
        }
    }

    fn line(&mut self, mut x0: i32, mut y0: i32, x1: i32, y1: i32, c: u8) {
        let dx = (x1 - x0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            self.set(x0, y0, c);
            if x0 == x1 && y0 == y1 { break; }
            let e2 = 2 * err;
            if e2 >= dy { err += dy; x0 += sx; }
            if e2 <= dx { err += dx; y0 += sy; }
        }
    }

    fn disc(&mut self, cx: i32, cy: i32, r: i32, c: u8) {
        for dy in -r..=r {
            for dx in -r..=r {
                if dx * dx + dy * dy <= r * r { self.set(cx + dx, cy + dy, c); }
            }
        }
    }

    fn text(&mut self, x: i32, y: i32, scale: i32, s: &str, c: u8) {
        let mut cx = x;
        for ch in s.to_uppercase().chars() {
            for (row, r) in glyph(ch).iter().enumerate() {
                for (col, bit) in r.chars().enumerate() {
                    if bit == '1' {
                        for sy in 0..scale {
                            for sx in 0..scale {
                                self.set(cx + col as i32 * scale + sx, y + row as i32 * scale + sy, c);
                            }
                        }
                    }
                }
            }
            cx += 6 * scale;
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data { a = (a + x as u32) % 65521; b = (b + a) % 65521; }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, t: &[u8; 4], d: &[u8]) {
    out.extend_from_slice(&(d.len() as u32).to_be_bytes());
    out.extend_from_slice(t);
    out.extend_from_slice(d);
    let mut c = t.to_vec();
    c.extend_from_slice(d);
    out.extend_from_slice(&crc32(&c).to_be_bytes());
}

pub fn write_png(path: &str, img: &Img) -> std::io::Result<()> {
    let (w, h) = (img.w, img.h);
    let mut raw = Vec::with_capacity((w + 1) * h);
    for y in 0..h { raw.push(0); raw.extend_from_slice(&img.px[y * w..(y + 1) * w]); }
    // zlib: header + blocs deflate "stored" (valide, sans compression) + adler32
    assert!(img.w > 0 && img.h > 0 && img.px.len() == img.w * img.h, "précondition: image cohérente");
    let mut z = vec![0x78u8, 0x01];
    let nchunks = raw.len().div_ceil(65535);
    for (k, chunk) in raw.chunks(65535).enumerate() { // borne explicite: nombre de blocs
        z.push(if k + 1 == nchunks { 1 } else { 0 });
        z.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
        z.extend_from_slice(chunk);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 3, 0, 0, 0]); // 8 bits, couleur = palette
    png_chunk(&mut png, b"IHDR", &ihdr);
    let mut plte = Vec::new();
    for c in PALETTE { plte.extend_from_slice(&c); }
    png_chunk(&mut png, b"PLTE", &plte);
    png_chunk(&mut png, b"IDAT", &z);
    png_chunk(&mut png, b"IEND", &[]);
    fs::write(path, png)
}

pub fn to_png(s: &Scan) -> Img {
    let up: Vec<Ipv4Addr> = s.hosts.iter().filter(|h| h.up).map(|h| h.ip).collect();
    let by_ip: BTreeMap<Ipv4Addr, &Host> = s.hosts.iter().map(|h| (h.ip, h)).collect();
    let n = up.len().max(1);
    let side = (n * 15 + 200).clamp(1200, 3000);
    let w = side;
    let h = side + 120;
    let mut img = Img::new(w, h, 0);
    let raw_title = format!("netscan {} - {} hotes up - {} - timeout {}ms",
        s.targets.join(" "), up.len(), s.ports_desc, s.timeout_ms);
    let title: String = raw_title.chars()
        .map(|c| if c.is_ascii_alphanumeric() || " .:/?-".contains(c) { c } else { '?' })
        .collect();
    img.text(24, 24, 2, &title, 5);
    let (nodes, edges) = layout(&up, w as f64, h as f64, s.gw);
    for (a, b) in &edges {
        let (x1, y1) = nodes[a];
        let (x2, y2) = nodes[b];
        img.line(x1 as i32, y1 as i32, x2 as i32, y2 as i32, 1);
    }
    // shortcut: labels IP uniquement si assez de place (n <= 60), sinon topologie seule
    let labels = up.len() <= 60;
    for ip in &up {
        let (x, y) = nodes[ip];
        let host = by_ip[ip];
        let c = if host.open_ports.is_empty() { 3 } else { 2 };
        img.disc(x as i32, y as i32, 8, c);
        if labels {
            let label = ip.to_string();
            img.text((x - label.len() as f64 * 3.0) as i32, y as i32 + 14, 1, &label, 4);
        }
    }
    img
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn glyphs_are_5x7() {
        for c in ' '..='~' {
            let rows = glyph(c);
            assert!(rows.iter().all(|r| r.len() == 5), "glyph {:?} mal formé", c);
        }
    }

    #[test]
    fn png_chunk_layout() {
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_chunk(&mut png, b"IHDR", &[0, 0, 0, 4, 0, 0, 0, 4, 8, 3, 0, 0, 0]);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes([png[8], png[9], png[10], png[11]]), 13);
    }
}
