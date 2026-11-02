#!/usr/bin/env python3
"""Analyse une capture pcap et produit un rapport Markdown + un CSV.

Pourquoi un lecteur pcap maison plutôt que `tshark` ? Parce qu'un dépôt de
portfolio doit s'ouvrir et se tester partout : aucune dépendance à installer,
aucun droit particulier, et `pytest` peut vérifier l'analyse sur une capture
synthétique. Le format pcap classique (celui qu'écrivent `tcpdump -w` et
`tshark -w -F pcap`) est simple : un en-tête global, puis par paquet un
en-tête de 16 octets et les données.

Ce que l'outil calcule :
  * top talkers (par IP source) ;
  * hiérarchie de protocoles (ethernet, ipv4, tcp, udp, icmp, arp, dns, http, tls) ;
  * conversations (5-uplets) avec paquets, octets et durée ;
  * compteurs de drapeaux TCP ;
  * détection simple de scan SYN ;
  * retransmissions TCP.

Usage :
    python3 analysis/analyze_pcap.py --input captures/a_arp_icmp.pcap --out reports/
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------

#: Magies possibles d'un fichier pcap (microsecondes/nanosecondes, les deux
#: ordres d'octets). Un fichier pcapng commence par 0x0A0D0D0A : refusé.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
VLAN_TYPES = (0x8100, 0x88A8)

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

FLAG_NAMES = {
    "FIN": TCP_FIN,
    "SYN": TCP_SYN,
    "RST": TCP_RST,
    "PSH": TCP_PSH,
    "ACK": TCP_ACK,
    "URG": TCP_URG,
}

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


class NotAPcapError(ValueError):
    """Le fichier n'est pas au format pcap classique."""


# --------------------------------------------------------------------------
# Structures
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Packet:
    """Un paquet décodé, réduit à ce qui sert à l'analyse."""

    timestamp: float
    length: int  # taille sur le fil
    src_mac: str = ""
    dst_mac: str = ""
    ether_type: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    transport: str = ""  # TCP, UDP, ICMP, OTHER
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    seq: int = 0
    payload: bytes = b""
    dns_query: str = ""
    http_request: bool = False
    tls_handshake: bool = False


@dataclass
class Conversation:
    """Une conversation = un 5-uplet directionnel."""

    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0

    @property
    def duration(self) -> float:
        """Durée entre le premier et le dernier paquet, en secondes."""
        return max(0.0, self.last_ts - self.first_ts)

    def key(self) -> tuple[str, str, int, str, int]:
        """Clé de regroupement."""
        return (self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port)


@dataclass
class Analysis:
    """Résultat complet de l'analyse d'une capture."""

    path: Path
    packet_count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    protocols: Counter = field(default_factory=Counter)
    talkers: dict = field(default_factory=dict)  # ip -> {"packets", "bytes"}
    conversations: list[Conversation] = field(default_factory=list)
    tcp_flags: Counter = field(default_factory=Counter)
    syn_scans: list[dict] = field(default_factory=list)
    retransmissions: list[dict] = field(default_factory=list)
    dns_queries: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        """Durée totale couverte par la capture, en secondes."""
        return max(0.0, self.last_ts - self.first_ts)


# --------------------------------------------------------------------------
# Lecture du fichier pcap
# --------------------------------------------------------------------------


def _mac(raw: bytes) -> str:
    """Formate 6 octets en adresse MAC lisible."""
    return ":".join(f"{octet:02x}" for octet in raw)


def read_pcap(path: str | Path) -> list[Packet]:
    """Lit un fichier pcap classique et retourne les paquets décodés."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"fichier introuvable : {source}")

    data = source.read_bytes()
    if len(data) < 24:
        raise NotAPcapError(f"{source.name} est trop court pour un fichier pcap")

    magic = data[:4]
    if magic not in PCAP_MAGICS:
        if magic == b"\x0a\x0d\x0d\x0a":
            raise NotAPcapError(
                f"{source.name} est au format pcapng ; convertir avec : "
                f"editcap -F pcap {source.name} {source.stem}.pcap"
            )
        raise NotAPcapError(f"{source.name} n'est pas un fichier pcap (magie inconnue)")

    endian, scale = PCAP_MAGICS[magic]
    # En-tête global : 24 octets, le champ « network » (link type) est le dernier.
    (link_type,) = struct.unpack_from(f"{endian}I", data, 20)
    if link_type != 1:  # 1 = Ethernet
        raise NotAPcapError(
            f"type de lien {link_type} non pris en charge (seul Ethernet = 1 l'est)"
        )

    packets: list[Packet] = []
    offset = 24
    header_len = struct.Struct(f"{endian}IIII")
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = header_len.unpack_from(data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break  # capture tronquée : on garde ce qui est lisible
        frame = data[offset : offset + incl_len]
        offset += incl_len
        packets.append(_decode_frame(frame, ts_sec + ts_frac * scale, orig_len))

    return packets


def _decode_frame(frame: bytes, timestamp: float, wire_length: int) -> Packet:
    """Décode une trame Ethernet jusqu'à la couche application."""
    if len(frame) < 14:
        return Packet(timestamp=timestamp, length=wire_length)

    dst_mac = _mac(frame[0:6])
    src_mac = _mac(frame[6:12])
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    payload_offset = 14

    # Trames étiquetées VLAN : on saute l'étiquette pour trouver le vrai type.
    while ether_type in VLAN_TYPES and len(frame) >= payload_offset + 4:
        ether_type = struct.unpack_from("!H", frame, payload_offset + 2)[0]
        payload_offset += 4

    base = dict(
        timestamp=timestamp,
        length=wire_length,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ether_type=ether_type,
    )

    if ether_type == ETH_ARP:
        return _decode_arp(frame, payload_offset, base)
    if ether_type == ETH_IPV6:
        return Packet(**base, transport="OTHER")
    if ether_type != ETH_IPV4:
        return Packet(**base)

    ip_start = payload_offset
    if len(frame) < ip_start + 20:
        return Packet(**base)

    version_ihl = frame[ip_start]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        return Packet(**base)
    proto = frame[ip_start + 9]
    src_ip = ".".join(str(b) for b in frame[ip_start + 12 : ip_start + 16])
    dst_ip = ".".join(str(b) for b in frame[ip_start + 16 : ip_start + 20])
    transport_offset = ip_start + ihl
    base.update(src_ip=src_ip, dst_ip=dst_ip)

    if proto == 6:
        return _decode_tcp(frame, transport_offset, base)
    if proto == 17:
        return _decode_udp(frame, transport_offset, base)
    if proto == 1:
        return Packet(**base, transport="ICMP")
    return Packet(**base, transport="OTHER")


def _decode_arp(frame: bytes, offset: int, base: dict) -> Packet:
    """Décode une trame ARP (adresses IPv4 seulement)."""
    if len(frame) < offset + 28:
        return Packet(**base)
    (opcode,) = struct.unpack_from("!H", frame, offset + 6)
    sender_ip = ".".join(str(b) for b in frame[offset + 14 : offset + 18])
    target_ip = ".".join(str(b) for b in frame[offset + 24 : offset + 28])
    role = "request" if opcode == 1 else "reply" if opcode == 2 else f"op{opcode}"
    return Packet(
        **base,
        src_ip=sender_ip,
        dst_ip=target_ip,
        transport="ARP",
        payload=role.encode(),
        seq=opcode,
    )


def _decode_tcp(frame: bytes, offset: int, base: dict) -> Packet:
    """Décode un segment TCP, puis détecte HTTP et TLS dans les données."""
    if len(frame) < offset + 20:
        return Packet(**base, transport="TCP")
    src_port, dst_port, seq = struct.unpack_from("!HHI", frame, offset)
    data_offset = (frame[offset + 12] >> 4) * 4
    if data_offset < 20:
        data_offset = 20
    flags = frame[offset + 13] & 0x3F
    payload = frame[offset + data_offset :]

    http_request = bool(payload) and payload.startswith(HTTP_METHODS)
    tls_handshake = (
        len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[2] <= 0x04
    )
    return Packet(
        **base,
        transport="TCP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        seq=seq,
        payload=payload,
        http_request=http_request,
        tls_handshake=tls_handshake,
    )


def _decode_udp(frame: bytes, offset: int, base: dict) -> Packet:
    """Décode un datagramme UDP, puis extrait la question DNS si possible."""
    if len(frame) < offset + 8:
        return Packet(**base, transport="UDP")
    src_port, dst_port = struct.unpack_from("!HH", frame, offset)
    payload = frame[offset + 8 :]
    query = ""
    if 53 in (src_port, dst_port):
        query = _dns_question(payload)
    return Packet(
        **base,
        transport="UDP",
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        dns_query=query,
    )


def _dns_question(payload: bytes) -> str:
    """Extrait le nom demandé dans une requête DNS (format d'étiquettes)."""
    if len(payload) < 13:
        return ""
    # Le 3e octet contient le drapeau QR : 0 = question, 1 = réponse.
    if payload[2] & 0x80:
        return ""
    (question_count,) = struct.unpack_from("!H", payload, 4)
    if question_count == 0:
        return ""

    labels: list[str] = []
    position = 12
    while position < len(payload):
        length = payload[position]
        if length == 0:
            position += 1
            break
        if length & 0xC0:  # pointeur de compression : on s'arrête là
            break
        start = position + 1
        label = payload[start : start + length]
        if len(label) != length:
            break
        labels.append(label.decode("ascii", errors="replace"))
        position = start + length
    return ".".join(labels)


# --------------------------------------------------------------------------
# Analyse
# --------------------------------------------------------------------------


def analyze(packets: list[Packet], path: Path) -> Analysis:
    """Calcule toutes les statistiques d'une capture."""
    result = Analysis(path=path, packet_count=len(packets))
    if not packets:
        return result

    result.first_ts = packets[0].timestamp
    result.last_ts = packets[-1].timestamp

    conversations: dict[tuple, Conversation] = {}
    syn_ports: dict[str, set[int]] = defaultdict(set)
    acked: set[str] = set()  # IP qui ont reçu un ACK : elles terminent un handshake
    seen_seq: Counter = Counter()

    for packet in packets:
        # --- Hiérarchie de protocoles ---
        result.protocols["ethernet"] += 1
        if packet.ether_type == ETH_IPV4:
            result.protocols["ipv4"] += 1
        elif packet.ether_type == ETH_IPV6:
            result.protocols["ipv6"] += 1
        elif packet.ether_type == ETH_ARP:
            result.protocols["arp"] += 1

        # ARP est déjà compté par son type Ethernet : ne pas le compter deux fois.
        if packet.transport and packet.transport != "ARP":
            result.protocols[packet.transport.lower()] += 1
        if packet.dns_query:
            result.protocols["dns"] += 1
            result.dns_queries[packet.dns_query] += 1
        if packet.http_request:
            result.protocols["http"] += 1
        if packet.tls_handshake:
            result.protocols["tls"] += 1

        # --- Talkers ---
        for address in (packet.src_ip, packet.dst_ip):
            if not address:
                continue
            entry = result.talkers.setdefault(address, {"packets": 0, "bytes": 0})
            entry["packets"] += 1
            entry["bytes"] += packet.length

        # --- Drapeaux TCP ---
        if packet.transport == "TCP":
            for name, bit in FLAG_NAMES.items():
                if packet.tcp_flags & bit:
                    result.tcp_flags[name] += 1

            # SYN sans ACK = tentative d'ouverture de connexion.
            if (packet.tcp_flags & TCP_SYN) and not (packet.tcp_flags & TCP_ACK):
                syn_ports[packet.src_ip].add(packet.dst_port)
            if packet.tcp_flags & TCP_ACK:
                acked.add(packet.src_ip)

            # Retransmission : même séquence de départ réémise avec des données.
            if packet.payload:
                key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.seq)
                seen_seq[key] += 1
                if seen_seq[key] > 1:
                    result.retransmissions.append(
                        {
                            "src": f"{packet.src_ip}:{packet.src_port}",
                            "dst": f"{packet.dst_ip}:{packet.dst_port}",
                            "seq": packet.seq,
                            "timestamp": packet.timestamp,
                        }
                    )

        # --- Conversations ---
        if packet.transport and packet.src_ip:
            key = (
                packet.transport,
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
            )
            conversation = conversations.get(key)
            if conversation is None:
                conversation = Conversation(
                    proto=packet.transport,
                    src_ip=packet.src_ip,
                    src_port=packet.src_port,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    first_ts=packet.timestamp,
                )
                conversations[key] = conversation
            conversation.packets += 1
            conversation.bytes += packet.length
            conversation.last_ts = packet.timestamp

    result.conversations = sorted(
        conversations.values(), key=lambda item: item.bytes, reverse=True
    )

    # --- Détection de scan SYN ---
    # Un scan se reconnaît à de nombreux SYN vers des ports différents depuis
    # une même source, sans terminer le handshake sur ces ports.
    threshold = 20
    for source, ports in syn_ports.items():
        if len(ports) >= threshold:
            result.syn_scans.append(
                {
                    "src": source,
                    "port_count": len(ports),
                    "ports": sorted(ports),
                    "handshake_completed": source in acked,
                }
            )

    return result


# --------------------------------------------------------------------------
# Rapports
# --------------------------------------------------------------------------


def _useful_protocols(protocols: Counter, total: int) -> list[tuple[str, int, float]]:
    """Retourne (nom, paquets, pourcentage) triés par nombre décroissant."""
    rows = []
    for name, count in protocols.most_common():
        if count == 0:
            continue
        rows.append((name, count, 100.0 * count / total if total else 0.0))
    return rows


def build_markdown(result: Analysis, top: int = 10) -> str:
    """Construit le rapport Markdown de l'analyse."""
    lines: list[str] = []
    lines.append(f"# Analyse de la capture `{result.path.name}`")
    lines.append("")
    lines.append("| Élément | Valeur |")
    lines.append("|---|---|")
    lines.append(f"| Paquets | {result.packet_count} |")
    lines.append(f"| Durée couverte | {result.duration:.2f} s |")
    lines.append(f"| Adresses IP distinctes | {len(result.talkers)} |")
    lines.append(f"| Conversations | {len(result.conversations)} |")
    lines.append(f"| Retransmissions TCP | {len(result.retransmissions)} |")
    lines.append(f"| Scans SYN détectés | {len(result.syn_scans)} |")
    lines.append("")

    if result.packet_count == 0:
        lines.append("Capture vide : rien à analyser.")
        return "\n".join(lines) + "\n"

    lines.append("## Top talkers (par IP source ou destination)")
    lines.append("")
    lines.append("| Adresse IP | Paquets | Octets |")
    lines.append("|---|---|---|")
    for address, stats in sorted(
        result.talkers.items(), key=lambda item: item[1]["packets"], reverse=True
    )[:top]:
        lines.append(f"| `{address}` | {stats['packets']} | {stats['bytes']} |")
    lines.append("")

    lines.append("## Hiérarchie de protocoles")
    lines.append("")
    lines.append("| Protocole | Paquets | Part |")
    lines.append("|---|---|---|")
    for name, count, percent in _useful_protocols(result.protocols, result.packet_count):
        lines.append(f"| {name} | {count} | {percent:.1f} % |")
    lines.append("")
    lines.append("> Les pourcentages ne s'additionnent pas : un paquet HTTP compte")
    lines.append("> aussi comme ethernet, ipv4 et tcp (c'est une hiérarchie).")
    lines.append("")

    lines.append("## Conversations (par volume)")
    lines.append("")
    lines.append("| Protocole | Source | Destination | Paquets | Octets | Durée (s) |")
    lines.append("|---|---|---|---|---|---|")
    for conversation in result.conversations[:top]:
        source = f"{conversation.src_ip}:{conversation.src_port}"
        destination = f"{conversation.dst_ip}:{conversation.dst_port}"
        lines.append(
            f"| {conversation.proto} | `{source}` | `{destination}` | "
            f"{conversation.packets} | {conversation.bytes} | {conversation.duration:.2f} |"
        )
    lines.append("")

    lines.append("## Drapeaux TCP")
    lines.append("")
    lines.append("| Drapeau | Nombre de paquets |")
    lines.append("|---|---|")
    for name in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
        lines.append(f"| {name} | {result.tcp_flags.get(name, 0)} |")
    lines.append("")

    lines.append("## Alertes")
    lines.append("")
    if not result.syn_scans and not result.retransmissions:
        lines.append("Aucune alerte automatique sur cette capture.")
    else:
        for scan in result.syn_scans:
            ports = ", ".join(str(port) for port in scan["ports"][:15])
            suffix = "…" if len(scan["ports"]) > 15 else ""
            lines.append(
                f"- **Scan SYN probable** depuis `{scan['src']}` : "
                f"{scan['port_count']} ports différents ({ports}{suffix})."
            )
            lines.append(
                "  - *Lecture* : balayage de ports. Vérifier s'il vient de mon propre "
                "lab, puis si le même hôte a tenté une connexion réelle ensuite."
            )
        if result.retransmissions:
            by_pair = Counter(
                f"{item['src']} → {item['dst']}" for item in result.retransmissions
            )
            lines.append("")
            lines.append(f"- **Retransmissions TCP** : {len(result.retransmissions)} segment(s).")
            for pair, count in by_pair.most_common(5):
                lines.append(f"  - `{pair}` : {count} retransmission(s)")
            lines.append(
                "  - *Lecture* : perte de paquets ou congestion (voir scénario E)."
            )
    lines.append("")

    lines.append("## Requêtes DNS observées")
    lines.append("")
    if result.dns_queries:
        lines.append("| Nom demandé | Nombre de requêtes |")
        lines.append("|---|---|")
        for name, count in result.dns_queries.most_common(top):
            lines.append(f"| `{name}` | {count} |")
        lines.append("")
        lines.append("> Le DNS n'est pas chiffré : un observateur du réseau voit tous")
        lines.append("> les noms de domaine demandés par une machine.")
    else:
        lines.append("Aucune requête DNS dans cette capture.")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_csv(result: Analysis, path: Path) -> Path:
    """Écrit les conversations dans un CSV trié par volume."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["protocole", "ip_source", "port_source", "ip_destination",
             "port_destination", "paquets", "octets", "duree_s"]
        )
        for conversation in result.conversations:
            writer.writerow(
                [
                    conversation.proto,
                    conversation.src_ip,
                    conversation.src_port,
                    conversation.dst_ip,
                    conversation.dst_port,
                    conversation.packets,
                    conversation.bytes,
                    f"{conversation.duration:.3f}",
                ]
            )
    return path


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Analyse une capture pcap et écrit un rapport Markdown + CSV.",
    )
    parser.add_argument("--input", required=True, metavar="FICHIER", help="Capture à analyser.")
    parser.add_argument(
        "--out", default="reports", metavar="DOSSIER", help="Dossier de sortie (défaut : reports/)."
    )
    parser.add_argument(
        "--top", type=int, default=10, metavar="N", help="Nombre de lignes par tableau (défaut : 10)."
    )
    parser.add_argument(
        "--markdown", action="store_true", help="N'affiche que les fichiers produits."
    )
    args = parser.parse_args(argv)

    try:
        packets = read_pcap(args.input)
    except (FileNotFoundError, NotAPcapError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2

    result = analyze(packets, Path(args.input))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = Path(args.input).stem
    md_path = out_dir / f"analyse-{stem}.md"
    csv_path = out_dir / f"analyse-{stem}.csv"
    md_path.write_text(build_markdown(result, top=args.top), encoding="utf-8")
    write_csv(result, csv_path)

    if args.markdown:
        print(md_path)
        print(csv_path)
    else:
        print(f"Paquets analysés : {result.packet_count}")
        print(f"Conversations    : {len(result.conversations)}")
        print(f"Scans SYN        : {len(result.syn_scans)}")
        print(f"Retransmissions  : {len(result.retransmissions)}")
        print(f"Rapport          : {md_path}")
        print(f"CSV              : {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
