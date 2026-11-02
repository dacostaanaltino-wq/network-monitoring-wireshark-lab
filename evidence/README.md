# Evidence – projet `network-monitoring-wireshark-lab`

Ce dossier contient les preuves du laboratoire réseau.

## Contenu attendu

```text
evidence/
└── screenshots/
    ├── 01-scenario-a-arp.png
    ├── …
    └── 16-scenario-f-alerte-scan.png
```

La liste exacte des **16 captures** (et ce que chacune doit montrer) est dans
[`../docs/scenarios.md`](../docs/scenarios.md#récapitulatif-des-captures-décran).

## Ce qui n'est jamais publié

- les fichiers `.pcap` réels (adresses MAC, volume, trafic) — voir
  [`../captures/README.md`](../captures/README.md) ;
- le trafic d'un réseau qui n'est pas le lab (`10.10.0.0/24`, pont `br-lab`).

## Avant de publier une capture d'écran

1. Masquer le **prompt** du terminal s'il contient le nom de ma machine.
2. Masquer les adresses MAC réelles (colonnes Source/Destination de Wireshark) :
   seules les adresses du lab (`02:00:00:00:00:xx`) sont acceptées.
3. Vérifier qu'aucune autre interface (Wi-Fi, VPN) n'apparaît dans la barre
   d'outils de Wireshark.
4. Contrôler :

```bash
git grep -nE "([0-9a-f]{2}:){5}[0-9a-f]{2}"      # adresses MAC
git grep -nE "([0-9]{1,3}\.){3}[0-9]{1,3}"       # adresses IP
```

Les seules adresses IP acceptées sont `10.10.0.0/24` (lab) ou celles réservées à
la documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
