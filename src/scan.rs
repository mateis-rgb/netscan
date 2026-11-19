// Moteur de scan : pool de threads, sondes TCP, barre de progression, phases 1-3.
// Stabilité : locks tolérants au poison, catch_unwind par tâche (un panic ne tue pas un worker).
use std::env;
use std::io::{IsTerminal, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::enrich::{arp_table, default_gateway, icmp_ping, local_ifaces, resolve_hostname, vendor_of};
use crate::model::{Host, PortInfo};
use crate::targets::DISCOVERY;

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// Limite douce de descripteurs fichiers du process (ulimit -n) ; chaque thread du pool
// ouvre au plus une socket à la fois, donc plafonner les workers sous cette limite évite
// les erreurs EMFILE qui feraient croire les ports fermés.
fn fd_soft_limit() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        if let Ok(out) = Command::new("sh").args(["-c", "ulimit -n"]).stderr(Stdio::null()).output() {
            if let Ok(n) = String::from_utf8_lossy(&out.stdout).trim().parse() { return n; }
        }
        256
    })
}

pub fn effective_workers(requested: usize) -> usize {
    requested.min(fd_soft_limit().saturating_sub(64).max(16))
}

// Sonde avec retries (phase 2, scan de ports) : backoff sur EMFILE/ENFILE, un retry sur timeout.
pub fn tcp_open(ip: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    for attempt in 0..3 {
        match TcpStream::connect_timeout(&SocketAddr::new(ip.into(), port), timeout) {
            Ok(_) => return true,
            Err(e) => {
                let raw = e.raw_os_error();
                // EMFILE/ENFILE : pool de fd plein, on attend et on retente
                if raw == Some(24) || raw == Some(23) {
                    thread::sleep(Duration::from_millis(20 * (attempt as u64 + 1)));
                    continue;
                }
                // Refusé = port fermé, inutile de retenter
                if e.kind() == std::io::ErrorKind::ConnectionRefused { return false; }
                // Timeout : possible perte de paquet, un seul retry
                if attempt == 0 && matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
                    continue;
                }
                return false;
            }
        }
    }
    false
}

// Sonde simple sans retry (phase 1, découverte) : un seul essai par port.
fn tcp_probe_once(ip: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip.into(), port), timeout).is_ok()
}

// ---------- mode détail (IP / port en cours dans la barre) ----------

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DetailLevel { None, Host, Port, HostPort }

impl DetailLevel {
    pub fn parse(s: &str) -> Option<DetailLevel> {
        match s.to_lowercase().as_str() {
            "aucun" | "none" | "off" => Some(DetailLevel::None),
            "hote" | "host" | "ip" => Some(DetailLevel::Host),
            "port" => Some(DetailLevel::Port),
            "hote:port" | "all" | "full" => Some(DetailLevel::HostPort),
            _ => None,
        }
    }
}

pub struct Detail {
    level: DetailLevel,
    current: Mutex<String>,
}

impl Detail {
    pub fn new(level: DetailLevel) -> Detail {
        Detail { level, current: Mutex::new(String::new()) }
    }

    pub fn note(&self, ip: Ipv4Addr, port: Option<u16>) {
        let s = match self.level {
            DetailLevel::None => return,
            DetailLevel::Host => ip.to_string(),
            DetailLevel::Port => port.map(|p| p.to_string()).unwrap_or_default(),
            DetailLevel::HostPort => match port {
                Some(p) => format!("{}:{}", ip, p),
                None => ip.to_string(),
            },
        };
        if !s.is_empty() { *lock(&self.current) = s; }
    }

    fn current(&self) -> String { lock(&self.current).clone() }
}

// ---------- barre de progression ----------

// Largeur du terminal (pour ne jamais wrappe la barre, sinon chaque \r crée une nouvelle ligne).
fn term_width() -> usize {
    // stty d'abord (fiable sur un vrai tty), puis COLUMNS, puis 80
    if let Ok(out) = Command::new("stty").arg("size").stdin(Stdio::inherit()).stderr(Stdio::null()).output() {
        if let Some(cols) = String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).and_then(|s| s.parse::<usize>().ok()) {
            if cols > 0 { return cols; }
        }
    }
    if let Ok(c) = env::var("COLUMNS") {
        if let Ok(n) = c.parse::<usize>() { if n > 0 { return n; } }
    }
    80
}

struct ProgressInner {
    done: AtomicUsize,
    total: usize,
    label: String,
    stop: AtomicBool,
    start: Instant,
    detail: Option<Arc<Detail>>,
    width: usize,
}

impl ProgressInner {
    fn draw(&self) {
        let d = self.done.load(Ordering::Relaxed).min(self.total);
        let pct = if self.total == 0 { 100 } else { d * 100 / self.total };
        let counts = format!("({}/{})", d, self.total);
        // largeur affichée sans la barre ni le détail: label 14 + " [" + "] " + "100% " + counts
        let base = 14 + 2 + 1 + 1 + 4 + 1 + counts.len();
        let bar_len = self.width.saturating_sub(base + 12).clamp(5, 30);
        let bars = pct * bar_len / 100;
        let bar = format!("{}{}", "█".repeat(bars), "░".repeat(bar_len - bars));
        let mut line = format!("\r\x1b[1;36m{:14}\x1b[0m [{}] {:3}% {}", self.label, bar, pct, counts);
        if let Some(det) = &self.detail {
            let budget = self.width.saturating_sub(base + bar_len + 1); // +1 = espace avant le détail
            if budget > 3 {
                let c: String = det.current().chars().take(budget).collect();
                if !c.is_empty() { line.push_str(&format!(" \x1b[33m{}\x1b[0m", c)); }
            }
        }
        line.push_str("\x1b[K"); // efface la fin de ligne si elle rétrécit
        eprint!("{}", line);
        let _ = std::io::stderr().flush();
    }
}

pub struct Progress {
    inner: Arc<ProgressInner>,
    handle: Option<JoinHandle<()>>,
}

impl Progress {
    pub fn start(label: &str, total: usize, quiet: bool, detail: Option<Arc<Detail>>) -> Progress {
        let inner = Arc::new(ProgressInner {
            done: AtomicUsize::new(0),
            total,
            label: label.to_string(),
            stop: AtomicBool::new(false),
            start: Instant::now(),
            detail,
            width: term_width(),
        });
        let tty = std::io::stderr().is_terminal();
        let handle = if quiet || total == 0 || !tty { None } else {
            let inner = Arc::clone(&inner);
            Some(thread::spawn(move || {
                while !inner.stop.load(Ordering::Relaxed) {
                    inner.draw();
                    thread::sleep(Duration::from_millis(100));
                }
            }))
        };
        Progress { inner, handle }
    }

    pub fn inc(&self) {
        self.inner.done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn finish(self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        let had_bar = self.handle.is_some();
        if let Some(h) = self.handle { let _ = h.join(); }
        if had_bar {
            self.inner.draw();
            eprintln!(" 100% en {:.2}s", self.inner.start.elapsed().as_secs_f64());
        }
    }
}

// ---------- pool de threads ----------

pub fn pool<T, F>(items: Vec<T>, workers: usize, f: F, progress: Option<&Progress>)
where
    T: Copy + Send + Sync,
    F: Fn(T) + Sync,
{
    assert!(workers >= 1, "précondition: au moins un worker");
    if items.is_empty() { return; }
    let items = Arc::new(items);
    let next = AtomicUsize::new(0);
    thread::scope(|s| {
        for _ in 0..workers.min(items.len()) {
            let items = Arc::clone(&items);
            let next = &next;
            let f = &f;
            s.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() { return; }
                let _ = catch_unwind(AssertUnwindSafe(|| f(items[i])));
                if let Some(p) = progress { p.inc(); }
            });
        }
    });
}

// ---------- bannières ----------

pub fn grab_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> String {
    let addr = SocketAddr::new(ip.into(), port);
    if let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) {
        let _ = s.set_read_timeout(Some(timeout));
        if matches!(port, 80 | 443 | 8000 | 8008 | 8009 | 8080 | 8081 | 8443 | 8888 | 9000) {
            let _ = s.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n");
        }
        let mut buf = [0u8; 256];
        if let Ok(n) = s.read(&mut buf) {
            return String::from_utf8_lossy(&buf[..n]).trim().replace(['\r', '\n'], " | ").chars().take(120).collect();
        }
    }
    String::new()
}

// ---------- orchestration des 3 phases ----------

struct Ctx {
    ips: Arc<Vec<Ipv4Addr>>,
    hosts: Arc<Mutex<Vec<Host>>>,
    timeout: Duration,
    workers: usize, // déjà plafonné sous la limite de fd
    banner: bool,
    quiet: bool,
    detail: Arc<Detail>,
}

impl Ctx {
    fn detail_for_bar(&self) -> Option<Arc<Detail>> {
        if self.detail.level == DetailLevel::None { None } else { Some(Arc::clone(&self.detail)) }
    }

    fn up_idx(&self) -> Vec<usize> {
        lock(&self.hosts).iter().enumerate().filter(|(_, h)| h.up).map(|(i, _)| i).collect()
    }
}

pub fn run_scan(
    ips: &Arc<Vec<Ipv4Addr>>,
    ports: &[u16],
    timeout: Duration,
    workers: usize,
    banner: bool,
    quiet: bool,
    detail_level: DetailLevel,
) -> (Vec<Host>, Option<Ipv4Addr>) {
    assert!(!ips.is_empty(), "précondition: au moins une IP");
    assert!(!ports.is_empty(), "précondition: au moins un port");
    let eff = effective_workers(workers);
    let ctx = Ctx {
        ips: Arc::clone(ips),
        hosts: Arc::new(Mutex::new(ips.iter().map(|&ip| Host::new(ip)).collect())),
        timeout,
        workers: eff,
        banner,
        quiet,
        detail: Arc::new(Detail::new(detail_level)),
    };
    if !quiet && eff < workers {
        eprintln!("[*] workers plafonné à {} (limite fd du process: {})", eff, fd_soft_limit());
    }

    let up = phase_decouverte(&ctx, ports);
    if !quiet { eprintln!("[*] {} hôtes up", up); }
    phase_scan_ports(&ctx, ports);
    let gw = phase_enrichissement(&ctx);

    let hosts_vec = lock(&ctx.hosts).clone();
    (hosts_vec, gw)
}

// Phase 1 : découverte — sondes parallélisées (hôte × port), on saute si déjà détecté up.
fn phase_decouverte(ctx: &Ctx, ports: &[u16]) -> usize {
    let mut probe: Vec<u16> = ports.iter().take(4).cloned().collect();
    for &p in DISCOVERY.iter() { if !probe.contains(&p) { probe.push(p); } }
    probe.truncate(12);
    let prog = Progress::start("Découverte", ctx.ips.len() * probe.len(), ctx.quiet, ctx.detail_for_bar());
    let tasks: Vec<(usize, u16)> = (0..ctx.ips.len()).flat_map(|i| probe.iter().map(move |&p| (i, p))).collect();
    pool(tasks, ctx.workers, move |(i, p)| {
        ctx.detail.note(ctx.ips[i], Some(p));
        if lock(&ctx.hosts)[i].up { return; }
        let t = Instant::now();
        if tcp_probe_once(ctx.ips[i], p, ctx.timeout) {
            let mut hs = lock(&ctx.hosts);
            let h = &mut hs[i];
            if !h.up { h.rtt_ms = Some(t.elapsed().as_secs_f64() * 1000.0); } // latence du 1er port répondant
            h.up = true;
        }
    }, Some(&prog));
    prog.finish();
    ctx.up_idx().len()
}

// Phase 2 : scan des ports sur les hôtes up.
fn phase_scan_ports(ctx: &Ctx, ports: &[u16]) {
    let up_idx = ctx.up_idx();
    let prog = Progress::start("Scan ports", up_idx.len() * ports.len(), ctx.quiet, ctx.detail_for_bar());
    let mut tasks = Vec::with_capacity(up_idx.len() * ports.len());
    for &i in &up_idx { for &p in ports { tasks.push((i, p)); } }
    pool(tasks, ctx.workers, move |(i, p)| {
        ctx.detail.note(ctx.ips[i], Some(p));
        if tcp_open(ctx.ips[i], p, ctx.timeout) {
            lock(&ctx.hosts)[i].open_ports.push(PortInfo { port: p, banner: String::new() });
        }
    }, Some(&prog));
    prog.finish();
    let mut hs = lock(&ctx.hosts);
    for h in hs.iter_mut() { h.open_ports.sort_by_key(|x| x.port); }
}

// Phase 3 : enrichissement (DNS inverse, MAC ARP, vendeur, ping ICMP, bannières).
fn phase_enrichissement(ctx: &Ctx) -> Option<Ipv4Addr> {
    let up_idx = ctx.up_idx();
    let arp = Arc::new(arp_table());
    let local = Arc::new(local_ifaces());
    let gw = default_gateway();
    let prog = Progress::start("Enrichissement", up_idx.len(), ctx.quiet, ctx.detail_for_bar());
    let local_c = Arc::clone(&local);
    pool(up_idx, ctx.workers.min(32), move |i| {
        let ip = ctx.ips[i];
        ctx.detail.note(ip, None);
        let hostname = resolve_hostname(ip);
        let mac = arp.get(&ip).cloned().or_else(|| local_c.get(&ip).cloned()).unwrap_or_default();
        let vendor = if mac.is_empty() { "-".to_string() } else { vendor_of(&mac) };
        let to_grab: Vec<u16> = lock(&ctx.hosts)[i].open_ports.iter().take(10).map(|p| p.port).collect();
        let banners: Vec<(u16, String)> = if ctx.banner {
            to_grab.iter().map(|&p| (p, grab_banner(ip, p, ctx.timeout))).collect()
        } else { vec![] };
        let mut hs = lock(&ctx.hosts);
        let h = &mut hs[i];
        h.hostname = hostname;
        h.mac = mac;
        h.vendor = vendor;
        if let Some(ms) = icmp_ping(ip, ctx.timeout) { h.rtt_ms = Some(ms); } // ping ICMP prioritaire
        for (p, b) in banners {
            if let Some(pi) = h.open_ports.iter_mut().find(|x| x.port == p) { pi.banner = b; }
        }
    }, Some(&prog));
    prog.finish();

    // Les pings/connexions de la phase 3 peuplent l'ARP : on relit la table et on complète
    // les MAC manquantes (les hôtes du même segment L2 y figurent maintenant).
    let arp2 = arp_table();
    let mut hs = lock(&ctx.hosts);
    for h in hs.iter_mut() {
        if h.up && h.mac.is_empty() {
            if let Some(mac) = arp2.get(&h.ip).or_else(|| local.get(&h.ip)) {
                h.mac = mac.clone();
                h.vendor = vendor_of(mac);
            }
        }
    }
    gw
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn tcp_open_detects_listener_and_closed_port() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = l.local_addr().unwrap().port();
        assert!(tcp_open(Ipv4Addr::LOCALHOST, open_port, Duration::from_millis(500)));

        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = l2.local_addr().unwrap().port();
        drop(l2); // port refermé -> connexion refusée
        assert!(!tcp_open(Ipv4Addr::LOCALHOST, closed_port, Duration::from_millis(300)));
    }

    #[test]
    fn workers_capped_under_fd_limit() {
        assert!(effective_workers(100_000) <= fd_soft_limit());
        assert!(effective_workers(100_000) >= 16);
        assert_eq!(effective_workers(8), 8);
    }
}
