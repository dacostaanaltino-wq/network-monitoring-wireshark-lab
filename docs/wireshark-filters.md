# Filtres Wireshark / tshark : lesquels et pourquoi

Deux familles de filtres à ne pas confondre :

- **filtre de capture** (`tcpdump -i br-lab 'port 80'`, `tshark -f "port 80"`) :
  appliqué **avant** l'écriture, en syntaxe BPF. Ce qui est filtré est perdu ;
- **filtre d'affichage** (`tshark -Y "…"`, barre de filtre de Wireshark) :
  appliqué **après** la capture, sur les paquets déjà enregistrés. Rien n'est perdu.

Dans ce projet, on capture **tout** le trafic du pont (petit volume) et on filtre
à l'affichage : c'est la bonne habitude quand on ne sait pas encore ce qu'on
cherche.

## Filtres d'affichage utiles

| Filtre | Ce qu'il montre | Quand l'utiliser |
|---|---|---|
| `arp` | Requêtes et réponses ARP | Voir la résolution d'adresse avant tout échange IP (scénario A) |
| `arp.opcode == 1` | Seulement les requêtes ARP | Repérer un balayage ARP (une machine qui demande toutes les IP du réseau) |
| `icmp` | Tout ICMP | Ping, erreurs de routage |
| `icmp.type == 8` | Echo request (ping sortant) | Vérifier qui ping qui |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN seuls | Détecter un scan de ports (scénario F) |
| `tcp.flags.reset == 1` | RST | Connexions refusées, ports fermés |
| `tcp.flags == 0x002` | SYN strict (aucun autre drapeau) | Même usage, écriture exacte en hexadécimal |
| `tcp.analysis.retransmission` | Segments retransmis | Perte de paquets (scénario E) |
| `tcp.analysis.duplicate_ack` | ACK dupliqués | Congestion ou perte, TCP le signale |
| `tcp.analysis.flags` | Toute anomalie détectée par Wireshark | Vue rapide des problèmes TCP |
| `dns` | Requêtes et réponses DNS | Voir quels noms sont demandés (scénario C) |
| `dns.flags.response == 0` | Requêtes seulement | Liste des noms demandés par une machine |
| `dns.qry.name == "lab.local"` | Un nom précis | Suivre une résolution |
| `http.request` | Requêtes HTTP | Voir méthode, URL, en-têtes (scénario B) |
| `http.request.method == "POST"` | POST seulement | Chercher des formulaires, donc des identifiants |
| `http.response.code == 200` | Réponses 200 | Vérifier ce qui a réussi |
| `http contains "password"` | Chaîne dans le trafic HTTP | Prouver qu'un mot de passe circule **en clair** |
| `tls.handshake` | Handshake TLS | Voir la mise en place du chiffrement (scénario D) |
| `tls.handshake.type == 1` | Client Hello | Voir les propositions de chiffrement (suites) |
| `tls.handshake.extensions_server_name` | SNI | Voir le nom du site visité **malgré** le chiffrement |
| `tcp.port == 8443` | Port TLS du lab | Isoler le trafic du serveur TLS de test |
| `ip.addr == 10.10.0.3` | Tout trafic vers/depuis le serveur | Suivre un hôte |
| `ip.src == 10.10.0.4 && ip.dst == 10.10.0.3` | Un sens précis | Isoler le poste « attaquant » |
| `tcp.stream eq 0` | Une seule connexion TCP | Suivre une conversation de bout en bout |
| `frame contains "MotDePasseFactice123"` | Chaîne dans n'importe quel octet | Prouver la présence d'une donnée sensible |

Les filtres « tcp.flags », « http », « dns » et « tls » sont ceux de la syntaxe
d'affichage de Wireshark 4.x. En cas de doute sur un nom de champ, l'auto-
complétion de la barre de filtre le propose — c'est la référence la plus fiable
pour la version installée.

## Équivalents en ligne de commande (tshark)

```bash
# Compter les paquets qui correspondent à un filtre
tshark -r captures/b_tcp_http.pcap -Y "http.request" | wc -l

# Extraire des champs précis, sans interface graphique
tshark -r captures/b_tcp_http.pcap -Y "http.request" \
       -T fields -e ip.src -e http.request.method -e http.request.uri

# Retrouver un mot de passe en clair (preuve du scénario B)
tshark -r captures/b_tcp_http.pcap -Y 'http contains "password"' -T fields -e http.file_data

# Statistiques intégrées
tshark -r capture.pcap -q -z io,phs          # hiérarchie de protocoles
tshark -r capture.pcap -q -z conv,tcp        # conversations TCP
tshark -r capture.pcap -q -z endpoints,ip    # points d'extrémité
capinfos capture.pcap                        # résumé du fichier
```

## Chaînes de filtres composées

```bash
# Connexions TCP vers le serveur de lab, hors DNS
ip.addr == 10.10.0.3 && tcp && !dns

# SYN sans ACK, hors scan de mon propre poste
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src != 10.10.0.2

# Trafic HTTP contenant un formulaire
http.request && frame matches "username="
```

## Pièges à éviter

| Piège | Conséquence |
|---|---|
| Confondre filtre de capture et filtre d'affichage | un filtre d'affichage passé à `tcpdump` provoque une erreur BPF |
| Filtrer trop tôt à la capture | les paquets écartés ne sont plus analysables |
| Croire que le TLS cache tout | IP, ports, SNI et volume restent visibles |
| Capturer sur `any` | sur certaines interfaces, l'en-tête Ethernet disparaît et le décodage change |
| Oublier `-s 0` (snaplen) | paquets tronqués, payload HTTP illisible |
