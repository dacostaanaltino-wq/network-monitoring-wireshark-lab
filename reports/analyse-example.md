# Analyse de la capture `example.pcap`

| Élément | Valeur |
|---|---|
| Paquets | 47 |
| Durée couverte | 0.84 s |
| Adresses IP distinctes | 3 |
| Conversations | 37 |
| Retransmissions TCP | 1 |
| Scans SYN détectés | 1 |

## Top talkers (par IP source ou destination)

| Adresse IP | Paquets | Octets |
|---|---|---|
| `10.10.0.3` | 47 | 3264 |
| `10.10.0.4` | 28 | 1512 |
| `10.10.0.2` | 19 | 1752 |

## Hiérarchie de protocoles

| Protocole | Paquets | Part |
|---|---|---|
| ethernet | 47 | 100.0 % |
| ipv4 | 45 | 95.7 % |
| tcp | 39 | 83.0 % |
| icmp | 4 | 8.5 % |
| arp | 2 | 4.3 % |
| http | 2 | 4.3 % |
| udp | 2 | 4.3 % |
| dns | 1 | 2.1 % |
| tls | 1 | 2.1 % |

> Les pourcentages ne s'additionnent pas : un paquet HTTP compte
> aussi comme ethernet, ipv4 et tcp (c'est une hiérarchie).

## Conversations (par volume)

| Protocole | Source | Destination | Paquets | Octets | Durée (s) |
|---|---|---|---|---|---|
| TCP | `10.10.0.2:40123` | `10.10.0.3:80` | 7 | 983 | 0.78 |
| TCP | `10.10.0.2:40200` | `10.10.0.3:8443` | 2 | 177 | 0.01 |
| TCP | `10.10.0.3:80` | `10.10.0.2:40123` | 2 | 170 | 0.03 |
| ICMP | `10.10.0.2:0` | `10.10.0.3:0` | 2 | 92 | 0.02 |
| ICMP | `10.10.0.3:0` | `10.10.0.2:0` | 2 | 92 | 0.02 |
| UDP | `10.10.0.3:53` | `10.10.0.2:53000` | 1 | 85 | 0.00 |
| UDP | `10.10.0.2:53000` | `10.10.0.3:53` | 1 | 69 | 0.00 |
| TCP | `10.10.0.4:50020` | `10.10.0.3:20` | 1 | 54 | 0.00 |
| TCP | `10.10.0.4:50021` | `10.10.0.3:21` | 1 | 54 | 0.00 |
| TCP | `10.10.0.4:50022` | `10.10.0.3:22` | 1 | 54 | 0.00 |

## Drapeaux TCP

| Drapeau | Nombre de paquets |
|---|---|
| SYN | 28 |
| ACK | 12 |
| FIN | 1 |
| RST | 3 |
| PSH | 6 |
| URG | 0 |

## Alertes

- **Scan SYN probable** depuis `10.10.0.4` : 25 ports différents (20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34…).
  - *Lecture* : balayage de ports. Vérifier s'il vient de mon propre lab, puis si le même hôte a tenté une connexion réelle ensuite.

- **Retransmissions TCP** : 1 segment(s).
  - `10.10.0.2:40123 → 10.10.0.3:80` : 1 retransmission(s)
  - *Lecture* : perte de paquets ou congestion (voir scénario E).

## Requêtes DNS observées

| Nom demandé | Nombre de requêtes |
|---|---|
| `lab.local` | 1 |

> Le DNS n'est pas chiffré : un observateur du réseau voit tous
> les noms de domaine demandés par une machine.

