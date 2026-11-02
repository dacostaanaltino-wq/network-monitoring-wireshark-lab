# network-monitoring-wireshark-lab

[![Système](https://img.shields.io/badge/labo-namespaces%20Linux-51A2DA)](scripts/setup_lab.sh)
[![Python](https://img.shields.io/badge/python-3.14-3776AB)](analysis/analyze_pcap.py)
[![pytest](https://img.shields.io/badge/pytest-20%20tests%20passing-brightgreen)](tests/)
[![shellcheck](https://img.shields.io/badge/shellcheck-passing-brightgreen)](scripts/)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Analyse et surveillance du trafic réseau dans un laboratoire **100 % virtuel** :
6 scénarios reproductibles (ARP/ICMP, TCP+HTTP en clair, DNS, TLS, perte de
paquets, scan de ports) capturés avec tcpdump ou tshark, puis analysés
automatiquement (top talkers, hiérarchie de protocoles, conversations, drapeaux
TCP, détection de scan SYN, retransmissions).

---

## Objectif

Montrer, capture à l'appui, **ce qui est visible et ce qui ne l'est pas** dans le
trafic réseau :

1. ce qui circule en clair est lisible par un tiers (HTTP, DNS, identifiants) ;
2. le chiffrement TLS protège le contenu mais laisse voir les métadonnées
   (IP, ports, SNI, volume) ;
3. TCP répare les pertes de paquets, et cela se voit ;
4. un scan de ports a une signature reconnaissable — et détectable
   automatiquement.

## Contexte

Projet de portfolio (technicien informatique junior en reconversion vers la
cybersécurité). Il complète `linux-hardening-lab-fedora` (durcir) et
`log-analysis-lab-linux` (lire les journaux) : ici on regarde le **réseau**.

**Périmètre éthique.** Tout se passe entre des *network namespaces* créés sur ma
machine (`10.10.0.0/24`, pont `br-lab`). Aucune capture de Wi-Fi public, aucun
scan d'une machine tierce. Le seul scan de ports est `lab-attacker` → `lab-server`,
deux namespaces qui m'appartiennent.

## Prérequis et outils

| Outil | Version testée | Rôle | Obligatoire ? |
|---|---|---|---|
| Fedora Linux | 44 | système | oui |
| Python | 3.14.8 | analyse des captures | oui |
| pytest | 9.2.0 | tests | pour le développement |
| iproute2 (`ip`) | paquet `iproute2` | namespaces, pont, `tc` | oui |
| `tcpdump` | paquet `tcpdump` | capture (alternative à tshark) | l'un des deux |
| `tshark` / `dumpcap` | paquet `wireshark-cli` | capture + vérifications | l'un des deux |
| Wireshark (interface) | paquet `wireshark` | lecture graphique, captures d'écran | recommandé |
| `nmap` | paquet `nmap` | scénario F uniquement | scénario F |
| `dnsmasq` | paquet `dnsmasq` | serveur DNS du lab | scénario C |
| `openssl` | paquet `openssl` | serveur TLS du lab | scénario D |
| `curl` | paquet `curl` | client HTTP/HTTPS du lab | scénarios B/D/E |

```bash
sudo dnf install iproute tcpdump wireshark-cli wireshark nmap dnsmasq openssl curl
python3 -m venv .venv && source .venv/bin/activate && pip install pytest
```

L'analyseur ne dépend que de la bibliothèque standard : **pas de `scapy`**, pas de
paquet supplémentaire à installer.

## Permissions de capture sous Fedora

Capturer sur une interface demande la capacité `CAP_NET_RAW`. Deux solutions :

```bash
# 1. Capturer en root (simple, pour un lab)
sudo ./scripts/capture.sh --scenario b

# 2. Capturer sans root, avec le groupe wireshark
sudo usermod -aG wireshark "$USER"        # puis se déconnecter/reconnecter
getcap "$(command -v dumpcap)"            # doit afficher cap_net_raw,cap_net_admin=ep
```

Le paquet `wireshark` (ou `wireshark-cli`) applique ces capacités sur `dumpcap`
et `tshark` à l'installation. Vérification :

```bash
id -nG | tr ' ' '\n' | grep -x wireshark        # mon compte est-il dans le groupe ?
getcap /usr/bin/dumpcap                          # capacités du binaire
```

`scripts/capture.sh` détecte les deux cas et explique la solution si les droits
manquent. Un `setcap` manuel (`sudo setcap cap_net_raw,cap_net_admin=eip …`)
fonctionne aussi, mais l'installation du paquet est préférable : elle survit aux
mises à jour.

## Architecture

```text
        machine hôte (Fedora)                     namespaces (chacun a sa pile réseau)
   ┌──────────────────────────┐
   │  br-lab  10.10.0.1/24    │◄──── capture tcpdump/tshark
   └───┬──────────┬───────┬───┘
       │ veth     │ veth  │ veth
   ┌───┴────┐ ┌───┴─────┐ ┌┴──────────┐
   │ lab-   │ │ lab-    │ │ lab-      │
   │ client │ │ server  │ │ attacker  │
   │ .2     │ │ .3 HTTP │ │ .4 nmap   │
   └────────┘ │   DNS   │ └───────────┘
              └─────────┘
```

```text
network-monitoring-wireshark-lab/
├── scripts/
│   ├── setup_lab.sh          création du lab (idempotent, --dry-run, confirmation)
│   ├── teardown_lab.sh       nettoyage complet
│   ├── capture.sh            capture + exécution d'un scénario
│   ├── lib/scenario.sh       code commun aux scénarios
│   └── scenarios/            a_arp_icmp, b_tcp_http, c_dns, d_tls, e_tc_netem, f_port_scan
├── analysis/analyze_pcap.py  analyse d'une capture -> Markdown + CSV
├── captures/                 captures (example.pcap = synthétique, publiée)
├── reports/                  rapport d'exemple
├── tests/                    pcap_builder.py + 20 tests
└── docs/                     wireshark-filters.md, scenarios.md
```

## Étapes pas à pas

### 1. Créer le lab

```bash
sudo ./scripts/setup_lab.sh --dry-run     # voir ce qui sera fait
sudo ./scripts/setup_lab.sh               # demande de confirmer par « oui »
ip netns list                             # lab-client, lab-server, lab-attacker
sudo ip netns exec lab-client ping -c 2 10.10.0.3
```

### 2. Capturer un scénario

```bash
sudo ./scripts/capture.sh --list
sudo ./scripts/capture.sh --scenario a    # ARP + ICMP
sudo ./scripts/capture.sh --scenario f    # scan nmap (lab uniquement)
```

Chaque exécution produit `captures/<scenario>.pcap` et rappelle les filtres
Wireshark à utiliser. Détail des 6 scénarios : [`docs/scenarios.md`](docs/scenarios.md).

### 3. Analyser la capture

```bash
python3 analysis/analyze_pcap.py --input captures/example.pcap --out reports/
wireshark captures/f_port_scan.pcap        # lecture graphique
```

### 4. Nettoyer

```bash
sudo ./scripts/teardown_lab.sh            # namespaces, pont, services
ip netns list                             # doit être vide
```

## Vérification et résultats

Sur la capture d'exemple fournie (`captures/example.pcap`, synthétique, 47
paquets couvrant les six scénarios) :

```text
$ python3 analysis/analyze_pcap.py --input captures/example.pcap --out reports/
Paquets analysés : 47
Conversations    : 37
Scans SYN        : 1
Retransmissions  : 1
Rapport          : reports/analyse-example.md
CSV              : reports/analyse-example.csv
```

Hiérarchie de protocoles extraite du rapport :

```text
| Protocole | Paquets | Part  |
|---|---|---|
| ethernet  | 47      | 100.0 % |
| ipv4      | 45      | 95.7 %  |
| tcp       | 39      | 83.0 %  |
| icmp      | 4       | 8.5 %   |
| arp       | 2       | 4.3 %   |
| http      | 2       | 4.3 %   |
| udp       | 2       | 4.3 %   |
| dns       | 1       | 2.1 %   |
| tls       | 1       | 2.1 %   |
```

Alertes détectées automatiquement :

```text
- Scan SYN probable depuis `10.10.0.4` : 25 ports différents (20, 21, 22, …).
- Retransmissions TCP : 1 segment.
  - `10.10.0.2:40123 → 10.10.0.3:80` : 1 retransmission
```

Tests :

```text
$ python3 -m pytest
20 passed in 0.12s
```

> Les tests fabriquent leurs propres trames (`tests/pcap_builder.py`) : ils ne
> dépendent ni du réseau, ni de `tshark`, ni de droits particuliers. La capture
> d'exemple est régénérable avec `python3 tests/pcap_builder.py captures/example.pcap`.

### Ce qui reste à faire à la main

- Exécuter les 6 scénarios sur ma VM et prendre les **16 captures d'écran**
  listées dans [`docs/scenarios.md`](docs/scenarios.md) (`evidence/screenshots/`).
- Comparer les résultats réels avec la capture d'exemple et noter les écarts.

## Difficultés rencontrées et solutions

| Difficulté | Cause | Solution retenue |
|---|---|---|
| Tester l'analyseur sans réseau ni root | les tests devaient tourner partout | écriture d'un **lecteur pcap en Python** (bibliothèque standard) et d'un générateur de trames de test |
| `tshark` non installable dans tous les environnements | dépendance externe lourde | capture possible avec `tcpdump` ou `tshark`, analyse toujours en Python pur |
| Fichier pcapng refusé | `tshark -w` écrit du pcapng par défaut | `-F pcap` dans `capture.sh`, et message d'erreur explicite avec la commande `editcap` à lancer |
| Trames VLAN mal décodées | étiquette 802.1Q de 4 octets | la boucle de décodage saute les étiquettes VLAN avant de lire le type réel |
| ARP compté deux fois dans la hiérarchie | compté par le type Ethernet **et** par le protocole transport | exclusion explicite dans l'analyseur |
| Lab qui laisse des restes | scripts interrompus | `setup_lab.sh` idempotent + `teardown_lab.sh` qui vérifie l'état final |
| Capture illimitée qui grossit | aucun plafond de taille | avertissement au-delà de 5 Mo et commande `editcap -c` proposée |
| Filtre de capture vs filtre d'affichage | confusion classique | expliqué en tête de `docs/wireshark-filters.md` |

## Compétences démontrées

- **Réseaux** : Ethernet/ARP, IPv4/ICMP, TCP (drapeaux, handshake, retransmissions), UDP/DNS, TLS, notion de métadonnées chiffrées.
- **Analyse de trafic** : lecture de pcap, filtres d'affichage Wireshark/tshark, hiérarchie de protocoles, conversations, détection de scan SYN.
- **Linux** : `ip netns`, paires `veth`, pont, `tc netem`, `setcap`/groupe `wireshark`, idempotence des scripts.
- **Python** : décodage binaire (`struct`), dataclasses, CLI `argparse`, sorties Markdown + CSV, tests `pytest`.
- **Rigueur** : laboratoire reproductible, périmètre éthique explicite, aucune capture réelle publiée.

## Limites et améliorations

- L'analyseur lit le **pcap classique** uniquement (pas pcapng) : conversion indiquée.
- Pas de décodage au-delà de TCP/UDP : TLS est détecté mais pas déchiffré (c'est le principe), pas de suivi de flux HTTP complet.
- La détection de scan SYN est volontairement simple (nombre de ports distincts) : pas de fenêtre temporelle ni de corrélation.
- Pas de capture temps réel continue (ce n'est pas un IDS) ; pas de corrélation avec les journaux du projet 4.
- Améliorations possibles : lecture de pcapng, export vers un format compatible Elasticsearch/Zeek, comparaison automatique de captures (`capinfos` + diff), abonnement à `tcpdump` en continu, corrélation scan + authentifications échouées.
- Les 6 scénarios sont manuels : un enchaînement automatisé des 6 avec génération d'un rapport unique serait un bon ajout.

## Ressources

- `man ip-netns`, `man ip-link`, `man tc-netem`, `man tcpdump`, `man tshark`, `man dumpcap`, `man setcap`
- Wireshark Display Filter Reference — <https://www.wireshark.org/docs/dfref/>
- Wireshark User's Guide (chapitres capture, filtres, statistiques) — <https://www.wireshark.org/docs/wsug_html_chunked/>
- RFC 826 (ARP), RFC 792 (ICMP), RFC 793/9293 (TCP), RFC 1035 (DNS), RFC 8446 (TLS 1.3)
- MITRE ATT&CK : T1046 (Network Service Discovery) pour le scan de ports
- Fedora Docs — <https://docs.fedoraproject.org/>

## Ce que j'ai appris

`À COMPLÉTER PAR ANALTINO`
