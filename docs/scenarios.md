# Les 6 scénarios, un par un

Pour chaque scénario : **objectif**, **commandes**, **ce qu'on voit dans
Wireshark**, **ce que l'analyse automatique doit produire** et **les captures
d'écran à prendre** (pour `evidence/screenshots/`).

Méthode générale :

```bash
sudo ./scripts/setup_lab.sh                 # une seule fois
sudo ./scripts/capture.sh --scenario a      # capture + exécution du scénario
python3 analysis/analyze_pcap.py --input captures/a_arp_icmp.pcap --out reports/
```

---

## Scénario A – ARP puis ICMP

**Objectif.** Voir la résolution d'adresse qui précède tout échange IP sur le
réseau local, puis les allers-retours ICMP.

**Commandes.**

```bash
sudo ./scripts/capture.sh --scenario a
# équivalent manuel :
sudo ip netns exec lab-client ip neigh flush all
sudo ip netns exec lab-client ping -c 4 10.10.0.3
```

**Ce qu'on voit.** Une requête ARP `who has 10.10.0.3? tell 10.10.0.2`, une
réponse ARP, puis 4 `Echo (ping) request` et 4 `Echo (ping) reply`.

**Analyse automatique.** Hiérarchie : `arp` et `icmp` présents. Top talkers :
`10.10.0.2` et `10.10.0.3`. Aucun scan, aucune retransmission.

**Captures d'écran à prendre.**

1. `01-scenario-a-arp.png` – filtre `arp`, la requête et la réponse (colonnes Source/Destination).
2. `02-scenario-a-icmp.png` – filtre `icmp`, les 4 pings et le temps de réponse.

---

## Scénario B – handshake TCP + HTTP en clair

**Objectif.** Montrer qu'un mot de passe envoyé en HTTP est lisible par
n'importe qui capture le trafic. Identifiants **factices**.

**Commandes.**

```bash
sudo ./scripts/capture.sh --scenario b
# équivalent manuel :
sudo ip netns exec lab-client curl -s -o /dev/null http://10.10.0.3/
sudo ip netns exec lab-client curl -s -o /dev/null -X POST \
     -d "username=demo&password=MotDePasseFactice123" http://10.10.0.3/login
```

**Ce qu'on voit.** Le handshake en trois temps (`SYN`, `SYN/ACK`, `ACK`), puis
`GET / HTTP/1.1`, la réponse `HTTP/1.1 200 OK`, puis le `POST /login` avec
`username=demo&password=MotDePasseFactice123` **en clair** dans le payload.

**Analyse automatique.** Protocoles `tcp` et `http` ; le payload du POST est
dans la capture (et donc lisible).

**Captures d'écran à prendre.**

3. `03-scenario-b-handshake.png` – filtre `tcp.flags.syn == 1 || tcp.flags.ack == 1`, les 3 premiers paquets.
4. `04-scenario-b-mot-de-passe-en-clair.png` – filtre `http`, paquet POST développé sur le payload (la preuve).
5. `05-scenario-b-tshark.png` – `tshark … -Y 'http contains "password"' -T fields -e http.file_data`.

---

## Scénario C – DNS

**Objectif.** Montrer que le DNS n'est pas chiffré : tous les noms de domaine
demandés sont visibles.

**Commandes.**

```bash
sudo ./scripts/capture.sh --scenario c
# équivalent manuel :
sudo ip netns exec lab-client dig +short @10.10.0.3 lab.local A
```

**Ce qu'on voit.** Une `Standard query 0x… A lab.local` puis une
`Standard query response 0x… A lab.local A 10.10.0.3`.

**Analyse automatique.** Protocole `dns`, requête `lab.local` listée dans le
rapport.

**Captures d'écran à prendre.**

6. `06-scenario-c-dns.png` – filtre `dns`, question et réponse.
7. `07-scenario-c-analyse.png` – section « Requêtes DNS observées » du rapport.

---

## Scénario D – TLS avec certificat auto-signé

**Objectif.** Comparer avec le scénario B : même type d'échange, mais le contenu
devient illisible.

**Commandes.**

```bash
sudo ./scripts/capture.sh --scenario d
# équivalent manuel :
openssl s_server -quiet -www -accept 8443 -cert /tmp/lab-tls/lab.crt -key /tmp/lab-tls/lab.key &
sudo ip netns exec lab-client curl -sk https://10.10.0.3:8443/
```

**Ce qu'on voit.** `Client Hello` (avec le SNI `lab.local`), `Server Hello`,
`Certificate`, `Server Key Exchange`, puis des `Application Data` opaques.
**Aucun** en-tête HTTP, **aucun** mot de passe.

**Analyse automatique.** Protocole `tls` ; le rapport ne montre que des volumes
et des métadonnées, jamais de contenu.

**Captures d'écran à prendre.**

8. `08-scenario-d-tls-handshake.png` – filtre `tls.handshake`.
9. `09-scenario-d-sni-visible.png` – `Client Hello` développé, extension `server_name`.
10. `10-scenario-d-application-data.png` – filtre `tls.record.content_type == 23` : contenu opaque (comparaison avec le scénario B).

---

## Scénario E – perte de paquets (tc netem) et retransmissions

**Objectif.** Voir TCP réparer une perte de paquets.

**Commandes.**

```bash
sudo ./scripts/capture.sh --scenario e
# équivalent manuel :
sudo ip netns exec lab-client tc qdisc replace dev veth-lab-client-n root netem loss 5%
sudo ip netns exec lab-client curl -s -o /dev/null http://10.10.0.3/big.bin
sudo ip netns exec lab-client tc qdisc del dev veth-lab-client-n root
```

**Ce qu'on voit.** Des segments réémis (`[TCP Retransmission]` en rouge dans
Wireshark), parfois des `[TCP Dup ACK]`, et un débit plus faible — mais le
fichier arrive complet.

**Analyse automatique.** La section « Retransmissions TCP » du rapport indique
le nombre de segments réémis et la conversation concernée.

**Captures d'écran à prendre.**

11. `11-scenario-e-retransmissions.png` – filtre `tcp.analysis.retransmission`.
12. `12-scenario-e-tc-netem.png` – sortie de `tc qdisc show dev veth-lab-client-n`.
13. `13-scenario-e-rapport.png` – section « Retransmissions TCP » du rapport.

---

## Scénario F – scan de ports nmap (serveur de lab uniquement)

**Objectif.** Reconnaître la signature d'un scan SYN, puis vérifier que l'outil
la retrouve automatiquement.

**Périmètre.** Le scan part de `lab-attacker` (10.10.0.4) et ne vise que
`lab-server` (10.10.0.3) — les deux sont des namespaces **sur ma machine**.
Aucun scan vers une machine tierce.

**Commandes.**

```bash
sudo ./scripts/capture.sh --scenario f
# équivalent manuel :
sudo ip netns exec lab-attacker nmap -sS -Pn -n -p 20-40 10.10.0.3
```

**Ce qu'on voit.** 25 SYN vers 25 ports différents, peu ou pas d'ACK :
la signature classique du scan. Les ports 53 et 80 répondent `SYN/ACK`, les
autres `RST/ACK`.

**Analyse automatique.** Une alerte « **Scan SYN probable** depuis
`10.10.0.4` : 25 ports différents ».

**Captures d'écran à prendre.**

14. `14-scenario-f-syn-seuls.png` – filtre `tcp.flags.syn == 1 && tcp.flags.ack == 0`.
15. `15-scenario-f-nmap.png` – sortie de la commande nmap.
16. `16-scenario-f-alerte-scan.png` – section « Alertes » du rapport d'analyse.

---

## Récapitulatif des captures d'écran

| # | Fichier attendu | Contenu |
|---|---|---|
| 1 | `01-scenario-a-arp.png` | ARP requête + réponse |
| 2 | `02-scenario-a-icmp.png` | 4 pings |
| 3 | `03-scenario-b-handshake.png` | handshake TCP en 3 temps |
| 4 | `04-scenario-b-mot-de-passe-en-clair.png` | POST avec identifiant factice visible |
| 5 | `05-scenario-b-tshark.png` | extraction de la chaîne en ligne de commande |
| 6 | `06-scenario-c-dns.png` | question et réponse DNS |
| 7 | `07-scenario-c-analyse.png` | section DNS du rapport |
| 8 | `08-scenario-d-tls-handshake.png` | handshake TLS |
| 9 | `09-scenario-d-sni-visible.png` | SNI visible dans le Client Hello |
| 10 | `10-scenario-d-application-data.png` | contenu TLS opaque |
| 11 | `11-scenario-e-retransmissions.png` | retransmissions TCP |
| 12 | `12-scenario-e-tc-netem.png` | configuration netem |
| 13 | `13-scenario-e-rapport.png` | section retransmissions du rapport |
| 14 | `14-scenario-f-syn-seuls.png` | SYN sans ACK |
| 15 | `15-scenario-f-nmap.png` | sortie nmap |
| 16 | `16-scenario-f-alerte-scan.png` | alerte de scan dans le rapport |

À déposer dans `evidence/screenshots/` après anonymisation (masquer le nom
d'utilisateur du terminal, les adresses MAC réelles et tout nom de machine).
