# netscan — documentation API

Documentation de l'ensemble du code source (`src/`), module par module.
Conventions : « entrées » = paramètres, « sortie » = valeur de retour, « erreurs » = `Err` / `panic` / effets de bord.

Table des modules :

```
main.rs     point d'entrée, orchestration, affichage console
cli.rs      interface ligne de commande + assistant interactif
targets.rs  parsing des cibles et des specs de ports
model.rs    types de données + interprétation des services
scan.rs     moteur de scan (pool, progression, phases, sondes TCP)
enrich.rs   enrichissement : ARP, ifconfig, route, DNS PTR, ping, OUI
graph.rs    positionnement du graphe réseau
export.rs   exports JSON / CSV / HTML
png.rs      rastérisation PNG 100% std
```

---

## `main.rs`

### `fn main()`
Point d'entrée du binaire.
- **Entrées** : arguments du process (`std::env::args`). Sans aucun argument → assistant interactif (`cli::interactive`). Sinon `cli::parse_args`.
- **Sortie** : aucune (retour `()`). Code de sortie : `0` succès, `2` erreur d'arguments/cibles/ports.
- **Effets de bord** : lance le scan, affiche la table console sur stdout, écrit les exports demandés.
- **Flux** : parse args → `targets::expand_targets` → validation ports non vides → `scan::run_scan` → construction du `model::Scan` → table console → `export::run_exports`.

---

## `cli.rs`

### `struct Args`
Configuration complète d'un scan. Champs : `targets: Vec<String>`, `ports_spec: String`, `timeout_ms: u64`, `workers: usize`, `banner: bool`, `exports: Vec<String>`, `out: String`, `quiet: bool`, `detail: scan::DetailLevel`.

### `fn usage() -> String`
- **Sortie** : texte d'aide complet (français).

### `fn parse_args() -> Result<Args, String>`
- **Entrées** : arguments CLI (lus via `env::args`).
- **Sortie** : `Ok(Args)` si cibles présentes et options valides ; `Err(message)` sinon (`--help` affiche l'aide et exit 0).
- **Options** : `--ports`, `-t/--timeout-ms`, `-w/--workers`, `--no-banner`, `--detail <niveau>`, `--export <liste>`, `--out <prefix>`, `-q/--quiet`, `-h/--help` ; positionnels = cibles.

### `fn interactive() -> Args`
Assistant pas à pas (banner, questions avec défauts, récap encadré, confirmation).
- **Entrées** : stdin (ligne par ligne).
- **Sortie** : `Args` validé. EOF (Ctrl-D) ou réponse négative à la confirmation → `exit(0)`.
- **Validation** : cibles via `targets::expand_targets`, ports via `targets::parse_ports`, nombres > 0.

### Helpers privés
| Fonction | Rôle |
|---|---|
| `read_line() -> Option<String>` | lit une ligne stdin ; `None` sur EOF/erreur |
| `ask(prompt, default) -> Option<String>` | affiche la question (couleurs ANSI), retourne la saisie ou le défaut si vide |
| `ask_or_exit(prompt, default) -> String` | `ask` + `exit(0)` sur EOF |
| `ask_targets() -> Vec<String>` | boucle jusqu'à cibles valides |
| `ask_ports_spec() -> String` | preset + ports additionnels, combinés et validés |
| `ask_detail() -> DetailLevel` | niveau de détail de la barre |
| `ask_number(prompt, default) -> u64` | entier > 0 |
| `ask_exports() -> Vec<String>` | liste filtrée parmi `json,csv,html,png` (`aucun` → vide) |
| `recap_box(title, rows)` | affiche le récapitulatif encadré (box drawing) |

---

## `targets.rs`

### Constantes
- `DISCOVERY: [u16; 16]` — ports sondés en phase 1.
- `TOP100: &[u16]` — 97 ports les plus courants.
- `MAX_IPS: u64 = 1_048_576` — borne dure du nombre d'IPs scannables (règle « boucles bornées »).

### `fn expand_targets(targets: &[String]) -> Result<Vec<Ipv4Addr>, String>`
- **Entrées** : liste de cibles textuelles. Formats acceptés : `a.b.c.d/prefix`, `a.b.c.d-n` (dernier octet), `a.b.c.d-a.b.c.n`, `a.b.c.d`.
- **Sortie** : `Ok(Vec<Ipv4Addr>)` trié, dédupliqué, sans adresse réseau/diffusion (sauf /31, /32) ; `Err(msg)` si cible invalide ou plage > `MAX_IPS`.
- **Boucles** : toutes bornées (`for i in start..=end`).

### `fn parse_ports(spec: &str) -> Vec<u16>`
- **Entrées** : spec textuelle, ex. `top100`, `web`, `all`, `22,80,443`, `1-1024`, `web,3000-3010`.
  - `web` = `TOP100` ∪ `8000..=9999` (dev/containers).
  - `all` = 1..=65535 (subsume le reste).
- **Sortie** : `Vec<u16>` trié, dédupliqué (postcondition vérifiée par `assert!`).
- **Erreurs** : aucune ; une spec sans port valide retourne un vec vide (rejeté ensuite par `main`).

---

## `model.rs`

### `struct PortInfo { port: u16, banner: String }`
Un port ouvert et sa bannière éventuelle.

### `struct Host`
Champs : `ip: Ipv4Addr`, `up: bool`, `hostname: String`, `mac: String`, `vendor: String`, `open_ports: Vec<PortInfo>`, `rtt_ms: Option<f64>` (ping ICMP, sinon latence connect TCP, en ms).
- `Host::new(ip)` : constructeur, tous champs à zéro/`None`.

### `struct Scan`
Résultat complet : `targets`, `ports_desc`, `started_unix`, `duration_s`, `timeout_ms`, `workers`, `gw: Option<Ipv4Addr>`, `hosts: Vec<Host>`.

### `fn hint(p: u16) -> &'static str`
- **Entrée** : numéro de port. **Sortie** : interprétation française (ex. `443 → "HTTPS (interface web sécurisée TLS)"`), `""` si inconnu. Table de données pure.

### `fn service(p: u16) -> String`
- **Entrée** : port. **Sortie** : `"443/tcp (HTTPS (...))"` ou `"9999/tcp"` si pas d'interprétation.

---

## `scan.rs`

### `fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T>`
Lock tolérant au poison (récupère le guard même si un thread a paniqué).

### `fn fd_soft_limit() -> usize` / `fn effective_workers(requested: usize) -> usize`
- `fd_soft_limit` : lit `ulimit -n` via `sh -c` (cache `OnceLock`, défaut 256).
- `effective_workers` : `min(requested, fd_limit - 64)`, plancher 16. Évite les faux « port fermé » par `EMFILE`.

### `fn tcp_open(ip, port, timeout) -> bool`
Sonde TCP avec robustesse : retry + backoff sur `EMFILE`/`ENFILE` (errno 24/23), un retry sur timeout (perte de paquet), arrêt immédiat sur `ConnectionRefused`.
- **Entrées** : IP, port, timeout. **Sortie** : `true` si la connexion aboutit.

### `fn tcp_probe_once(ip, port, timeout) -> bool`
Sonde simple sans retry (phase 1).

### `enum DetailLevel { None, Host, Port, HostPort }` + `DetailLevel::parse(&str) -> Option<DetailLevel>`
Niveaux de détail de la barre : `aucun|hote|port|hote:port`.

### `struct Detail` + `new(level)` + `note(ip, port: Option<u16>)`
Mémorise la cible en cours de test (partagé entre workers et barre).

### `struct Progress` + `start(label, total, quiet, detail)` + `inc()` + `finish()`
Barre de progression sur stderr (`\r`, blocs `█░`, `%`, compteurs, détail tronqué à la largeur du terminal via `stty size`/`COLUMNS`). Non affichée si quiet, total = 0, ou stderr non-tty.

### `fn term_width() -> usize`
Largeur du terminal : `stty size` (stdin hérité) → `COLUMNS` → 80.

### `fn pool<T, F>(items: Vec<T>, workers: usize, f: F, progress: Option<&Progress>)`
Pool de threads à compteur atomique (`thread::scope`). Chaque tâche est exécutée dans `catch_unwind` (un panic ne tue pas le worker) et fait avancer la barre.
- **Précondition** : `assert!(workers >= 1)`.
- **Entrées** : tâches `Copy`, nombre de workers, closure `Fn(T) + Sync`, barre optionnelle.

### `fn grab_banner(ip, port, timeout) -> String`
- **Sortie** : bannière texte tronquée à 120 caractères (envoie `HEAD / HTTP/1.0` sur les ports HTTP-like). Vide si échec.

### `struct Ctx` + `fn run_scan(...) -> (Vec<Host>, Option<Ipv4Addr>)`
Orchestration. **Entrées** : `ips: &Arc<Vec<Ipv4Addr>>`, `ports: &[u16]`, `timeout: Duration`, `workers`, `banner`, `quiet`, `detail_level`. **Préconditions** : `assert!` ips et ports non vides. **Sortie** : hôtes enrichis + passerelle détectée. Déclenche les 3 phases :

- `phase_decouverte(ctx, ports) -> usize` : sondes parallélisées (hôte × port, 12 max), saute si déjà up, mesure la latence du 1er port répondant (`rtt_ms`). Retourne le nombre d'hôtes up.
- `phase_scan_ports(ctx, ports)` : tâches (hôte up × port) via `tcp_open`, trie les ports ouverts.
- `phase_enrichissement(ctx) -> Option<Ipv4Addr>` : par hôte up — hostname (`enrich::resolve_hostname`), MAC (`arp_table` + `local_ifaces`), vendeur OUI, ping ICMP (`icmp_ping`, prioritaire sur `rtt_ms`), bannières (10 ports max). Puis **re-lecture de l'ARP** pour compléter les MAC peuplées par les pings. Retourne la passerelle.

---

## `enrich.rs`

### `fn vendor_of(mac: &str) -> String`
Préfixe OUI (3 premiers octets, casse-insensible) → vendeur ; `"inconnu"` sinon. Liste de démarrage dans `const OUI`.

### `fn parse_arp(output: &str) -> BTreeMap<Ipv4Addr, String>` / `fn arp_table() -> BTreeMap<Ipv4Addr, String>`
Parse `arp -an` (format macOS `? (ip) at MAC on iface ...`) ; entrées `(incomplete)` ignorées. `arp_table` exécute la commande (stderr muselé).

### `fn parse_ifconfig(output: &str) -> BTreeMap<Ipv4Addr, String>` / `fn local_ifaces() -> ...`
Associe `inet <ip>` ↔ `ether <mac>` par bloc d'interface → IPs/MACs propres du Mac (l'IP locale n'est jamais dans l'ARP).

### `fn default_gateway() -> Option<Ipv4Addr>`
Parse `route -n get default` (champ `gateway:`).

### `fn icmp_ping(ip, timeout) -> Option<f64>` / `fn parse_ping_time(output: &str) -> Option<f64>`
`ping -c 1 -W <s> <ip>`, parse `time=12.3 ms` → RTT en ms. `None` si échec.

### `fn resolve_hostname(ip) -> String`
Ordre : `/etc/hosts` (`hosts_file_lookup`) → requête **DNS PTR en UDP pur std** (`resolv_servers` lit `/etc/resolv.conf`, `build_ptr_query` construit le paquet, `parse_ptr_response`/`read_name` le décodent avec gestion de la compression, timeout 800 ms par serveur). `"-"` si rien.

---

## `graph.rs`

### `type Nodes = BTreeMap<Ipv4Addr, (f64, f64)>` / `type Edges = Vec<(Ipv4Addr, Ipv4Addr)>`

### `fn layout(ips: &[Ipv4Addr], w: f64, h: f64, gw: Option<Ipv4Addr>) -> (Nodes, Edges)`
- **Entrées** : IPs up, dimensions du canevas, passerelle éventuelle.
- **Sortie** : positions des nœuds (cercle) + arêtes (étoile autour de la passerelle si elle est dans la liste, sinon anneau fermé).

---

## `export.rs`

### `fn run_exports(s: &Scan, exports: &[String], out: &str)`
Dispatch : écrit `<out>.json|csv|html|png` selon la liste ; affiche `[+] export: ...` ou l'erreur. Formats inconnus ignorés avec avertissement.

### `fn to_json(s: &Scan) -> String`
JSON pretty : bloc `scan` (métadonnées) + `hosts[]` (`ip`, `up`, `hostname`, `mac`, `vendor`, `ping_ms` (null si absent), `open_ports[{port, service, banner}]`). Échappement manuel (`jesc`).

### `fn to_csv(s: &Scan) -> String`
CSV `ip,up,hostname,mac,vendor,ping_ms,ports_ouverts,services` (quoting RFC4180 via `csv_field`).

### `fn to_html(s: &Scan) -> String`
Page HTML autonome (dark) : graphe SVG (`graph::layout`, tooltips, nœuds verts/ambres) + table des hôtes up (IP, hostname, MAC, vendeur, ping, ports avec bannière). Échappement `esc`.

---

## `png.rs`

### `const PALETTE: [[u8; 3]; 6]`
6 couleurs : fond, arêtes, nœud-ports-ouverts, nœud-up-sans-port, texte, titre.

### `fn glyph(c: char) -> [&'static str; 7]`
Police 5x7 maison (A-Z, 0-9, `.:-/` et espace ; inconnu → `?`). Validée par test (tous les glyphes font 5x7).

### `struct Img { w, h, px: Vec<u8> }` + méthodes
`new(w, h, bg)`, `set(x, y, c)` (borné), `line` (Bresenham), `disc` (disque plein), `text(x, y, scale, s, c)` (rendu 5x7 en majuscules).

### `fn crc32(&[u8]) -> u32` / `fn adler32(&[u8]) -> u32` / `fn png_chunk(out, t, d)`
Checksums PNG/zlib et construction des chunks (CRC32 en fin de chunk).

### `fn write_png(path, &Img) -> io::Result<()>`
- **Précondition** : `assert!` image cohérente (`px.len() == w*h`).
- **Sortie** : écrit un PNG valide, couleur indexée 8 bits, compression zlib en blocs « stored » (aucune dépendance).

### `fn to_png(s: &Scan) -> Img`
Rastérise le graphe (`graph::layout`) : canevas adaptatif (`clamp(1200, 3000)`), titre, arêtes, nœuds, labels IP si ≤ 60 hôtes up (sinon topologie seule).

---

## Tests (`#[cfg(test)]` dans chaque module)

15 tests : expansion CIDR/plages, specs de ports (incl. preset `web`), encodage/requête DNS PTR + parsing avec compression, rejets de paquets invalides, parsing `time=` du ping, parsing `arp`/`ifconfig`, CRC32/adler32 (vecteurs connus), structure des chunks PNG, police 5x7, `tcp_open` contre un vrai `TcpListener`, plafond de workers vs limite fd.

```bash
cargo test --release   # exécute les tests
cargo clippy --all-targets   # 0 warning (deny, voir Cargo.toml)
```
