#!/usr/bin/env python3
"""Construit de petites captures pcap pour les tests et pour l'exemple.

Pourquoi fabriquer des trames à la main ? Pour que `pytest` et la
démonstration fonctionnent sans réseau, sans root et sans capture réelle. Les
trames sont simplifiées (les sommes de contrôle valent 0 : l'analyseur ne les
vérifie pas, et ce ne sont pas des paquets destinés à être émis).

Les adresses sont celles du lab (10.10.0.0/24) et les identifiants HTTP sont
factices.

Usage (régénère la capture d'exemple) :
    python3 tests/pcap_builder.py ../captures/example.pcap
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

MAC_CLIENT = "02:00:00:00:00:02"
MAC_SERVER = "02:00:00:00:00:03"
MAC_ATTACKER = "02:00:00:00:00:04"

IP_CLIENT = "10.10.0.2"
IP_SERVER = "10.10.0.3"
IP_ATTACKER = "10.10.0.4"

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806

TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_FIN = 0x01
TCP_RST = 0x04


# --------------------------------------------------------------------------
# Construction des couches
# --------------------------------------------------------------------------


def _mac(text: str) -> bytes:
    """Convertit « 02:00:00:00:00:02 » en 6 octets."""
    return bytes(int(part, 16) for part in text.split(":"))


def _ip(text: str) -> bytes:
    """Convertit « 10.10.0.2 » en 4 octets."""
    return bytes(int(part) for part in text.split("."))


def ethernet(dst: str, src: str, ether_type: int, payload: bytes) -> bytes:
    """Assemble une trame Ethernet II."""
    return _mac(dst) + _mac(src) + struct.pack("!H", ether_type) + payload


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ident: int = 1) -> bytes:
    """Assemble un paquet IPv4 (somme de contrôle laissée à 0)."""
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, en-tête de 5 mots de 32 bits
        0,
        20 + len(payload),
        ident,
        0x4000,  # « don't fragment »
        64,
        protocol,
        0,
        _ip(src),
        _ip(dst),
    )
    return header + payload


def tcp(
    sport: int,
    dport: int,
    flags: int,
    seq: int = 1000,
    ack: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Assemble un segment TCP."""
    header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        (5 << 4),  # data offset : 5 mots, pas d'options
        flags,
        8192,
        0,
        0,
    )
    return header + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    """Assemble un datagramme UDP."""
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(type_: int, code: int = 0, payload: bytes = b"") -> bytes:
    """Assemble un message ICMP."""
    return struct.pack("!BBH", type_, code, 0) + payload


def arp(op: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    """Assemble une trame ARP (op 1 = requête, op 2 = réponse)."""
    return (
        struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, op)
        + _mac(sender_mac)
        + _ip(sender_ip)
        + _mac(target_mac)
        + _ip(target_ip)
    )


def dns_query(name: str, query_id: int = 0x1234) -> bytes:
    """Assemble une question DNS (type A)."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def dns_response(name: str, address: str, query_id: int = 0x1234) -> bytes:
    """Assemble une réponse DNS avec un enregistrement A."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    answer = (
        b"\xc0\x0c"  # pointeur vers le nom de la question
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + _ip(address)
    )
    return (
        struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
        + labels
        + struct.pack("!HH", 1, 1)
        + answer
    )


# --------------------------------------------------------------------------
# Fichier pcap
# --------------------------------------------------------------------------


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    """Écrit une liste de (horodatage, trame) dans un fichier pcap classique."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        # En-tête global : magie (microsecondes, petit-boutiste), version 2.4,
        # fuseau 0, snaplen 65535, type de lien 1 (Ethernet).
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in frames:
            seconds = int(timestamp)
            micro = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, micro, len(frame), len(frame)))
            handle.write(frame)
    return path


# --------------------------------------------------------------------------
# Capture d'exemple
# --------------------------------------------------------------------------


def build_example_frames() -> list[tuple[float, bytes]]:
    """Compose une capture qui contient tous les cas que l'outil doit voir.

    ARP, ICMP, handshake TCP, HTTP (dont un formulaire avec mot de passe
    factice), DNS, TLS, scan SYN et une retransmission TCP.
    """
    frames: list[tuple[float, bytes]] = []
    t = 1_800_000_000.0  # horodatage arbitraire mais réaliste

    def add(frame: bytes, delta: float = 0.01) -> None:
        nonlocal t
        t += delta
        frames.append((t, frame))

    # 1. ARP : qui a 10.10.0.3 ?
    add(
        ethernet(
            "ff:ff:ff:ff:ff:ff",
            MAC_CLIENT,
            ETH_ARP,
            arp(1, MAC_CLIENT, IP_CLIENT, "00:00:00:00:00:00", IP_SERVER),
        )
    )
    add(
        ethernet(
            MAC_CLIENT,
            MAC_SERVER,
            ETH_ARP,
            arp(2, MAC_SERVER, IP_SERVER, MAC_CLIENT, IP_CLIENT),
        )
    )

    # 2. ICMP : deux ping (request type 8, reply type 0).
    for sequence in range(2):
        add(
            ethernet(
                MAC_SERVER,
                MAC_CLIENT,
                ETH_IPV4,
                ipv4(IP_CLIENT, IP_SERVER, 1, icmp(8, 0, bytes([sequence, 0]) * 4), sequence + 1),
            )
        )
        add(
            ethernet(
                MAC_CLIENT,
                MAC_SERVER,
                ETH_IPV4,
                ipv4(IP_SERVER, IP_CLIENT, 1, icmp(0, 0, bytes([sequence, 0]) * 4), sequence + 1),
            )
        )

    # 3. Handshake TCP puis HTTP en clair.
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40123, 80, TCP_SYN, seq=1000)),
        )
    )
    add(
        ethernet(
            MAC_CLIENT, MAC_SERVER, ETH_IPV4,
            ipv4(IP_SERVER, IP_CLIENT, 6, tcp(80, 40123, TCP_SYN | TCP_ACK, seq=5000, ack=1001)),
        )
    )
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40123, 80, TCP_ACK, seq=1001, ack=5001)),
        )
    )
    request = b"GET / HTTP/1.1\r\nHost: 10.10.0.3\r\nUser-Agent: lab\r\n\r\n"
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40123, 80, TCP_PSH | TCP_ACK, seq=1001, ack=5001, payload=request)),
        )
    )
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n<h1>Serveur de lab</h1>"
    add(
        ethernet(
            MAC_CLIENT, MAC_SERVER, ETH_IPV4,
            ipv4(IP_SERVER, IP_CLIENT, 6, tcp(80, 40123, TCP_PSH | TCP_ACK, seq=5001, ack=1001 + len(request), payload=response)),
        )
    )
    form = (
        b"POST /login HTTP/1.1\r\nHost: 10.10.0.3\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 45\r\n\r\n"
        b"username=demo&password=MotDePasseFactice123"
    )
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40123, 80, TCP_PSH | TCP_ACK, seq=1100, ack=5043, payload=form)),
        )
    )

    # 4. DNS : question puis réponse pour lab.local.
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 17, udp(53000, 53, dns_query("lab.local"))),
        )
    )
    add(
        ethernet(
            MAC_CLIENT, MAC_SERVER, ETH_IPV4,
            ipv4(IP_SERVER, IP_CLIENT, 17, udp(53, 53000, dns_response("lab.local", IP_SERVER))),
        )
    )

    # 5. TLS : Client Hello (le contenu applicatif reste chiffré).
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40200, 8443, TCP_SYN, seq=2000)),
        )
    )
    client_hello = b"\x16\x03\x01\x00\x40" + bytes(64)
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40200, 8443, TCP_PSH | TCP_ACK, seq=2001, ack=6001, payload=client_hello)),
        )
    )

    # 6. Scan SYN : 25 ports depuis l'attaquant de lab.
    for port in range(20, 45):
        add(
            ethernet(
                MAC_SERVER, MAC_ATTACKER, ETH_IPV4,
                ipv4(IP_ATTACKER, IP_SERVER, 6, tcp(50000 + port, port, TCP_SYN, seq=3000 + port)),
            ),
            0.002,
        )
    # Réponse RST/ACK sur quelques ports fermés.
    for port in (21, 22, 23):
        add(
            ethernet(
                MAC_ATTACKER, MAC_SERVER, ETH_IPV4,
                ipv4(IP_SERVER, IP_ATTACKER, 6, tcp(port, 50000 + port, TCP_RST | TCP_ACK, seq=7000, ack=3001)),
            )
        )

    # 7. Retransmission : même numéro de séquence, deux fois, avec données.
    duplicate = b"X" * 200
    for _ in range(2):
        add(
            ethernet(
                MAC_SERVER, MAC_CLIENT, ETH_IPV4,
                ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40123, 80, TCP_PSH | TCP_ACK, seq=9000, ack=5043, payload=duplicate)),
            ),
            0.3,
        )

    # 8. Fin de session.
    add(
        ethernet(
            MAC_SERVER, MAC_CLIENT, ETH_IPV4,
            ipv4(IP_CLIENT, IP_SERVER, 6, tcp(40123, 80, TCP_FIN | TCP_ACK, seq=9200, ack=5043)),
        )
    )
    return frames


def build_example_capture(path: Path) -> Path:
    """Écrit la capture d'exemple complète dans ``path``."""
    return write_pcap(path, build_example_frames())


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("example.pcap")
    build_example_capture(destination)
    print(f"Capture d'exemple écrite : {destination}")
