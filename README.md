# netscan

Scanner réseau rapide en ligne de commande, écrit en **Rust 100% std** (zéro dépendance externe).
Conçu pour remplacer des outils type Angry IP Scanner sur un LAN : découverte des hôtes,
scan de ports avec interprétation, enrichissement (hostname, MAC, vendeur, ping), vue graphe
et exports multi-formats.

## Fonctionnalités

- **Scan rapide** : TCP connect multithreadé, workers plafonnés automatiquement sous la limite
  de descripteurs du process (pas de faux négatifs `EMFILE`), retry sur timeout/EMFILE.
- **Cibles flexibles** : CIDR (`192.168.1.0/24`), plages (`192.168.1.10-50` ou
  `192.168.1.10-192.168.1.60`), IP seule, plusieurs cibles en même temps. Plage max : 2^20 IPs.
- **Découverte + ports** : état up/down, ports ouverts avec interprétation
  (`443 → HTTPS (interface web sécurisée TLS)`), capture de bannière (ex: `Server: Apache/2.x`).
- **Enrichissement** : hostname (DNS PTR en UDP pur std + `/etc/hosts`), ping (ICMP via `ping`,
  sinon latence du connect TCP), MAC + vendeur (table ARP relue après les pings + `ifconfig`
  pour l'IP locale ; MAC dispo uniquement sur le segment L2 local).
- **Presets de ports** : `top100`, `web` (top100 + 8000-9999, dev/containers), `all`, ou spec perso
  (`22,80,443`, `1-1024`), combinables (`web,3000-3010`).
- **Barre de progression** (terminal uniquement) avec mode détail : `--detail aucun|hote|port|hote:port`.
- **Mode interactif** : lancer `netscan` sans aucun argument ouvre un assistant guidé
  (cibles, preset + ports additionnels, timeout, threads, bannières, détail, exports, récap).
- **Exports** : `json`, `csv`, `html` (rapport autonome avec graphe SVG + table), `png` (rendu maison,
  sans aucune dépendance).

## Installation

```bash
cargo build --release
# binaire : ./target/release/netscan
```

Prérequis runtime (macOS/Linux) : `sh`, `arp`, `route`, `ifconfig`, `ping` — tous présents par défaut.

## Usage

```bash
# scan d'un sous-réseau avec exports
./target/release/netscan 192.168.1.0/24 --export json,csv,html,png --out rapport

# preset web (top100 + 8000-9999) sur une plage, timeout court
./target/release/netscan 192.168.1.10-60 --ports web -t 200

# plusieurs cibles, détail dans la barre
./target/release/netscan 192.168.1.0/24 10.0.0.5 --detail hote:port

# assistant interactif
./target/release/netscan
```

### Options

| Option | Défaut | Description |
|---|---|---|
| `<cibles...>` | — | CIDR / plage / IP, plusieurs possibles |
| `--ports <spec>` | `top100` | `top100` \| `web` \| `all` \| `22,80,443` \| `1-1024` \| combinaisons |
| `-t, --timeout-ms <n>` | `500` | timeout TCP par port (200-300 conseillé en LAN filaire) |
| `-w, --workers <n>` | `512` | threads (plafonné auto sous la limite de fd) |
| `--no-banner` | off | désactive la capture de bannières |
| `--detail <niveau>` | `aucun` | `aucun` \| `hote` \| `port` \| `hote:port` dans la barre |
| `--export <liste>` | aucun | `json,csv,html,png` |
| `--out <prefix>` | `netscan_<ts>` | préfixe des fichiers d'export |
| `-q, --quiet` | off | pas de barre de progression |
| `-h, --help` | — | aide |

## Sorties

- **Console** : table IP / HOSTNAME / MAC / VENDEUR / PING / PORTS OUVERTS.
- **JSON** : métadonnées du scan + liste des hôtes (`up`, `hostname`, `mac`, `vendor`, `ping_ms`,
  `open_ports[{port, service, banner}]`).
- **CSV** : `ip,up,hostname,mac,vendor,ping_ms,ports_ouverts,services`.
- **HTML** : page autonome, graphe SVG (étoile autour de la passerelle si connue, sinon anneau ;
  nœud vert = ports ouverts, ambre = up sans port) + table détaillée avec tooltips.
- **PNG** : même graphe rastérisé maison (palette 8 bits + zlib « stored blocks » + police 5x7 intégrée).

## Architecture

```
src/
├── main.rs     orchestration + table console
├── cli.rs      parsing args + assistant interactif
├── targets.rs  parsing cibles (CIDR/plages) + specs ports + presets
├── model.rs    Host/Scan/PortInfo + interprétation des services
├── scan.rs     pool de threads, barre de progression, phases 1-3, tcp_open
├── enrich.rs   ARP/ifconfig/route, DNS PTR (UDP pur std), ping ICMP, OUI
├── graph.rs    layout du graphe (anneau / étoile passerelle)
├── export.rs   JSON / CSV / HTML + dispatch des exports
└── png.rs      rendu PNG 100% std (encodeur zlib maison + police 5x7)
```

Tests : `cargo test --release` (15 tests : parsing, DNS PTR, PNG, ping, ARP, tcp_open, etc.)
Lint : `cargo clippy --all-targets` — warnings en `deny` (voir `Cargo.toml`).

La documentation complète des fonctions (entrées/sorties) est dans [`docs.md`](docs.md).

## Limites connues

- Scan TCP connect uniquement (pas de SYN/ICMP pour la détection d'hôte) : un hôte qui droppe
  toutes les sondes apparaît « down ».
- MAC/vendeur uniquement pour les hôtes du même segment L2 que la machine (limite ARP inhérente).
- DNS inverse : PTR IPv4 uniquement (pas de mDNS `.local`).
- PNG : labels IP affichés seulement si ≤ 60 hôtes up.

---

Fait avec ❤️ en France 🇫🇷 avec Mistral AI
