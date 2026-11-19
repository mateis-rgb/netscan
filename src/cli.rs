// CLI : parsing des arguments + assistant interactif (lancé quand aucun argument n'est donné).
use std::env;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::scan::DetailLevel;
use crate::targets;

pub struct Args {
    pub targets: Vec<String>,
    pub ports_spec: String,
    pub timeout_ms: u64,
    pub workers: usize,
    pub banner: bool,
    pub exports: Vec<String>,
    pub out: String,
    pub quiet: bool,
    pub detail: DetailLevel,
}

pub fn usage() -> String {
    "netscan — scanner réseau rapide (TCP connect multithreadé, zéro dépendance)\n\
     USAGE:\n  netscan <cible(s)> [options]        (sans aucun argument : assistant interactif)\n\
     CIBLES (plusieurs possibles):\n  192.168.1.0/24 | 192.168.1.10-50 | 192.168.1.10-192.168.1.60 | 10.0.0.5\n\
     OPTIONS:\n  --ports <spec>      top100 (défaut) | web (top100 + 8000-9999) | all | 22,80,443 | 1-1024 | web,3000-3010\n  -t, --timeout-ms <n>  timeout TCP par port (défaut 500 ; 200-300 conseillé en LAN filaire)\n\
     \x20 -w, --workers <n>     threads (défaut 512, plafonné automatiquement sous la limite de fd)\n      --no-banner       pas de capture de bannière\n      --detail <niveau> détail dans la barre de progression: aucun (défaut) | hote | port | hote:port\n\
     \x20     --export <liste>  json,csv,html,png (console seule si absent)\n      --out <prefix>    préfixe des exports (défaut netscan_<timestamp>)\n\
     \x20 -q, --quiet         moins de verbosité (pas de barre de progression)\n  -h, --help\n\
     NOTE: un hôte qui ne répond à aucune sonde TCP est marqué down (pas d'ICMP).\n"
        .to_string()
}

pub fn parse_args() -> Result<Args, String> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut a = Args {
        targets: vec![], ports_spec: "top100".into(), timeout_ms: 500, workers: 512,
        banner: true, exports: vec![], out: format!("netscan_{}", ts), quiet: false,
        detail: DetailLevel::None,
    };
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => { print!("{}", usage()); std::process::exit(0); }
            "-q" | "--quiet" => a.quiet = true,
            "--no-banner" => a.banner = false,
            "--ports" => a.ports_spec = it.next().ok_or("--ports attend une valeur")?,
            "--detail" => {
                let v = it.next().ok_or("--detail attend un niveau (aucun|hote|port|hote:port)")?;
                a.detail = DetailLevel::parse(&v).ok_or(format!("niveau de détail invalide: {} (aucun|hote|port|hote:port)", v))?;
            }
            "-t" | "--timeout-ms" => a.timeout_ms = it.next().ok_or("-t attend un nombre")?.parse().map_err(|_| "timeout invalide")?,
            "-w" | "--workers" => a.workers = it.next().ok_or("-w attend un nombre")?.parse().map_err(|_| "workers invalide")?,
            "--export" => a.exports = it.next().ok_or("--export attend une liste")?.split(',').map(|s| s.trim().to_string()).collect(),
            "--out" => a.out = it.next().ok_or("--out attend un préfixe")?,
            _ if arg.starts_with('-') => return Err(format!("option inconnue: {}", arg)),
            _ => a.targets.push(arg),
        }
    }
    if a.targets.is_empty() { return Err("aucune cible fournie (voir --help)".into()); }
    Ok(a)
}

// ---------- assistant interactif ----------

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";

fn read_line() -> Option<String> {
    let mut s = String::new();
    match io::stdin().read_line(&mut s) {
        Ok(0) => None, // EOF (Ctrl-D)
        Ok(_) => Some(s.trim().to_string()),
        Err(_) => None,
    }
}

fn ask(prompt: &str, default: &str) -> Option<String> {
    print!("{}{}{} ", CYAN, prompt, RESET);
    if !default.is_empty() { print!("{}(défaut: {}){} ", YELLOW, default, RESET); }
    let _ = io::stdout().flush();
    read_line().map(|s| if s.is_empty() { default.to_string() } else { s })
}

fn recap_box(title: &str, rows: &[(&str, String)]) {
    let inner: Vec<String> = rows.iter().map(|(k, v)| format!("  {:<11}: {}", k, v)).collect();
    let w = inner.iter().map(|l| l.chars().count()).max().unwrap_or(0).max(title.chars().count() + 4) + 1;
    println!("\n{BOLD}{CYAN}┌─ {} {}┐{RESET}", title, "─".repeat(w.saturating_sub(title.chars().count() + 3)));
    for l in &inner {
        println!("{CYAN}│{RESET}{}{}{CYAN}│{RESET}", l, " ".repeat(w - l.chars().count()));
    }
    println!("{CYAN}└{}┘{RESET}", "─".repeat(w));
}

fn ask_or_exit(prompt: &str, default: &str) -> String {
    ask(prompt, default).unwrap_or_else(|| std::process::exit(0))
}

fn ask_targets() -> Vec<String> {
    loop {
        let s = ask_or_exit("Cibles (ex: 192.168.1.0/24, 10.0.0.10-50 — plusieurs séparées par des espaces)", "");
        let v: Vec<String> = s.split_whitespace().map(str::to_string).collect();
        if v.is_empty() { println!("{RED}→ au moins une cible est obligatoire{RESET}"); continue; }
        match targets::expand_targets(&v) {
            Ok(_) => return v,
            Err(e) => println!("{RED}→ cible invalide ({}), réessaie{RESET}", e),
        }
    }
}

fn ask_ports_spec() -> String {
    loop {
        let preset = ask_or_exit("Preset de ports [top100 | web | all | spec perso ex: 22,80,1-1024]", "top100");
        let extra = ask_or_exit("Ports additionnels à ajouter au preset (ex: 22,3000-3010 — vide = aucun)", "");
        let spec = if extra.is_empty() { preset } else { format!("{},{}", preset, extra) };
        if targets::parse_ports(&spec).is_empty() {
            println!("{RED}→ aucun port valide dans cette combinaison, réessaie{RESET}");
        } else { return spec; }
    }
}

fn ask_detail() -> DetailLevel {
    loop {
        let s = ask_or_exit("Détail dans la barre de progression [aucun | hote | port | hote:port]", "aucun");
        match DetailLevel::parse(&s) {
            Some(l) => return l,
            None => println!("{RED}→ valeurs possibles: aucun, hote, port, hote:port{RESET}"),
        }
    }
}

fn ask_number(prompt: &str, default: u64) -> u64 {
    loop {
        let s = ask_or_exit(prompt, &default.to_string());
        match s.parse::<u64>() {
            Ok(n) if n > 0 => return n,
            _ => println!("{RED}→ un nombre > 0 est attendu{RESET}"),
        }
    }
}

fn ask_exports() -> Vec<String> {
    let s = ask_or_exit("Exports (json,csv,html,png — ou 'aucun')", "html,png");
    if s.trim().eq_ignore_ascii_case("aucun") { return vec![]; }
    s.split(',').map(|x| x.trim().to_string())
        .filter(|x| ["json", "csv", "html", "png"].contains(&x.as_str()))
        .collect()
}

pub fn interactive() -> Args {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    println!("\n{BOLD}{CYAN}╔══════════════════════════════════════╗");
    println!("║     NETSCAN — assistant de scan      ║");
    println!("╚══════════════════════════════════════╝{RESET}\n");

    let targets = ask_targets();
    let ports_spec = ask_ports_spec();
    let detail = ask_detail();
    let timeout_ms = ask_number("Timeout TCP par port (ms)", 500);
    let workers = ask_number("Nombre de threads", 512) as usize;
    let banner = {
        let s = ask_or_exit("Capturer les bannières des services ? [O/n]", "O");
        !matches!(s.to_lowercase().as_str(), "n" | "non" | "no" | "0")
    };
    let exports = ask_exports();
    let default_out = format!("netscan_{}", ts);
    let out = ask_or_exit("Préfixe des fichiers de sortie", &default_out);

    let rows = vec![
        ("Cibles", targets.join(" ")),
        ("Ports", format!("{} ({} ports)", ports_spec, targets::parse_ports(&ports_spec).len())),
        ("Timeout", format!("{} ms", timeout_ms)),
        ("Threads", workers.to_string()),
        ("Bannières", if banner { "oui".into() } else { "non".into() }),
        ("Détail barre", match detail {
            DetailLevel::None => "aucun".into(),
            DetailLevel::Host => "hote".into(),
            DetailLevel::Port => "port".into(),
            DetailLevel::HostPort => "hote:port".into(),
        }),
        ("Exports", if exports.is_empty() { "aucun".into() } else { exports.join(",") }),
        ("Sortie", out.clone()),
    ];
    recap_box("RÉCAPITULATIF", &rows);

    let s = ask_or_exit("Lancer le scan maintenant ? [O/n]", "O");
    if !matches!(s.to_lowercase().as_str(), "" | "o" | "oui" | "y" | "yes") {
        println!("Scan annulé.");
        std::process::exit(0);
    }

    Args { targets, ports_spec, timeout_ms, workers, banner, exports, out, quiet: false, detail }
}
