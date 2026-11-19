// Types de données centraux + interprétation des ports.
use std::net::Ipv4Addr;

#[derive(Default, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub banner: String,
}

#[derive(Clone)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub up: bool,
    pub hostname: String,
    pub mac: String,
    pub vendor: String,
    pub open_ports: Vec<PortInfo>,
    pub rtt_ms: Option<f64>, // ping ICMP si dispo, sinon latence du connect TCP de découverte
}

impl Host {
    pub fn new(ip: Ipv4Addr) -> Host {
        Host { ip, up: false, hostname: String::new(), mac: String::new(), vendor: String::new(), open_ports: vec![], rtt_ms: None }
    }
}

pub struct Scan {
    pub targets: Vec<String>,
    pub ports_desc: String,
    pub started_unix: u64,
    pub duration_s: f64,
    pub timeout_ms: u64,
    pub workers: usize,
    pub gw: Option<Ipv4Addr>,
    pub hosts: Vec<Host>,
}

pub fn hint(p: u16) -> &'static str {
    match p {
        21 => "FTP (transfert de fichiers)",
        22 => "SSH (admin à distance, chiffré)",
        23 => "Telnet (admin non chiffré — à bannir)",
        25 | 587 => "SMTP (envoi de mail)",
        53 => "DNS (résolution de noms)",
        67 | 68 => "DHCP",
        80 => "HTTP (interface web non chiffrée)",
        110 => "POP3 (réception mail)",
        143 => "IMAP (messagerie)",
        161 | 162 => "SNMP (supervision réseau)",
        389 => "LDAP (annuaire)",
        443 => "HTTPS (interface web sécurisée TLS)",
        445 => "SMB (partage fichiers Windows)",
        465 => "SMTPS (mail chiffré)",
        514 => "Syslog",
        554 | 8554 => "RTSP (flux caméra)",
        623 => "IPMI (admin serveur hors bande)",
        636 => "LDAPS (annuaire chiffré)",
        993 => "IMAPS (messagerie chiffrée)",
        995 => "POP3S (mail chiffré)",
        1080 => "Proxy SOCKS",
        1433 => "Microsoft SQL Server",
        1883 => "MQTT (IoT)",
        2049 => "NFS (partage fichiers Unix)",
        3306 => "MySQL",
        3389 => "RDP (bureau à distance Windows)",
        5000 => "Docker registry / UPnP",
        5432 => "PostgreSQL",
        5900 => "VNC (bureau à distance)",
        6379 => "Redis",
        8000 | 8080 | 8081 | 8888 => "HTTP alternatif / interface web ou proxy",
        8443 => "HTTPS alternatif (souvent admin NAS/box)",
        9000 => "Admin web (ex: phpMyAdmin)",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        37777 => "Interface caméra (Dahua)",
        _ => "",
    }
}

pub fn service(p: u16) -> String {
    let h = hint(p);
    if h.is_empty() { format!("{}/tcp", p) } else { format!("{}/tcp ({})", p, h) }
}
