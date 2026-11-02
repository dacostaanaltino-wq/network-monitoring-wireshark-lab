# Dossier captures

## `example.pcap` — capture d'exemple synthétique

`example.pcap` **n'est pas** un trafic réel : c'est une capture fabriquée par
`tests/pcap_builder.py`, qui reproduit les six scénarios (ARP, ICMP, handshake
TCP + HTTP avec identifiant factice, DNS, TLS, scan SYN, retransmission). Elle
existe pour que l'analyseur puisse être démontré et testé **sans** réseau,
**sans** droits particuliers et **sans** matériel.

Regénérer le fichier :

```bash
python3 tests/pcap_builder.py captures/example.pcap
python3 analysis/analyze_pcap.py --input captures/example.pcap --out reports/
```

Elle est volontairement minuscule (moins de 5 Ko) pour rester dans le dépôt.

## Mes vraies captures

Les captures produites par `scripts/capture.sh` (scénarios a à f) sont écrites
ici, mais elles **ne sont pas publiées** :

- elles contiennent les adresses MAC de ma machine et son trafic ;
- le scénario B contient un formulaire (factice, mais quand même) ;
- une capture de 30 minutes peut peser plusieurs dizaines de Mo.

`*.pcap` est dans `.gitignore` (sauf `example.pcap`). Pour publier une preuve
d'une vraie capture : extraire les lignes utiles avec `tshark`, ou prendre une
capture d'écran, puis vérifier avec :

```bash
git grep -nE "([0-9a-f]{2}:){5}[0-9a-f]{2}"        # adresses MAC
git grep -nE "([0-9]{1,3}\.){3}[0-9]{1,3}"         # adresses IP
```

Rappel : le trafic capturé doit être **uniquement** celui du lab
(10.10.0.0/24, pont `br-lab`).
