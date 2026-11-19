// netscan — scanner réseau rapide (TCP connect multithreadé, 100% std, zéro dépendance).
// Lancé sans argument : assistant interactif. Avec arguments : voir --help.
mod cli;
mod enrich;
mod export;
mod graph;
mod model;
mod png;
mod scan;
mod targets;

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use model::{hint, Host, Scan};

fn main() {
    let args = if env::args().len() == 1 {
        cli::interactive()
    } else {
        match cli::parse_args() {
            Ok(a) => a,
            Err(e) => { eprintln!("erreur: {}\n{}", e, cli::usage()); std::process::exit(2); }
        }
    };

    let ips = Arc::new(match targets::expand_targets(&args.targets) {
        Ok(v) => v,
        Err(e) => { eprintln!("erreur cible: {}", e); std::process::exit(2); }
    });
    if ips.is_empty() { eprintln!("aucune IP à scanner"); std::process::exit(2); }
    let ports = targets::parse_ports(&args.ports_spec);
    if ports.is_empty() { // règle 7: valider les paramètres
        eprintln!("erreur: aucun port valide dans --ports '{}'", args.ports_spec);
        std::process::exit(2);
    }

    if !args.quiet {
        eprintln!("[*] {} IP(s), {} port(s)/hôte, {} threads, timeout {} ms",
            ips.len(), ports.len(), args.workers, args.timeout_ms);
    }
    let t0 = Instant::now();
    let started = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (hosts, gw) = scan::run_scan(
        &ips, &ports, Duration::from_millis(args.timeout_ms), args.workers, args.banner, args.quiet, args.detail,
    );
    let duration = t0.elapsed().as_secs_f64();

    let scan_data = Scan {
        targets: args.targets.clone(),
        ports_desc: format!("{} ({} ports)", args.ports_spec, ports.len()),
        started_unix: started,
        duration_s: duration,
        timeout_ms: args.timeout_ms,
        workers: args.workers,
        gw,
        hosts,
    };

    // Console
    let up: Vec<&Host> = scan_data.hosts.iter().filter(|h| h.up).collect();
    println!("{:<16} {:<28} {:<17} {:<16} {:>9}  PORTS OUVERTS", "IP", "HOSTNAME", "MAC", "VENDEUR", "PING");
    for h in &up {
        let mut ports_str = h.open_ports.iter().map(|p| {
            let ht = hint(p.port);
            if ht.is_empty() { p.port.to_string() } else { format!("{} ({})", p.port, ht) }
        }).collect::<Vec<_>>().join(", ");
        if ports_str.len() > 100 { ports_str = format!("{}...", &ports_str[..100]); }
        let ping = h.rtt_ms.map(|v| format!("{:.1} ms", v)).unwrap_or_else(|| "-".into());
        println!("{:<16} {:<28} {:<17} {:<16} {:>9}  {}", h.ip, h.hostname, h.mac, h.vendor, ping, ports_str);
    }
    println!("\n{} hôtes up / {} scannés en {:.2}s", up.len(), scan_data.hosts.len(), duration);

    export::run_exports(&scan_data, &args.exports, &args.out);
}
