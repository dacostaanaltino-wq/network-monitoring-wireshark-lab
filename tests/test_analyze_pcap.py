"""Tests de l'analyseur de captures.

Chaque test travaille sur une capture fabriquée par ``pcap_builder`` : aucun
réseau, aucun root, aucune capture réelle n'est nécessaire.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "analysis"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import analyze_pcap  # noqa: E402
import pcap_builder  # noqa: E402


@pytest.fixture
def example_pcap(tmp_path: Path) -> Path:
    """Capture d'exemple complète (ARP, ICMP, TCP, HTTP, DNS, TLS, scan)."""
    return pcap_builder.build_example_capture(tmp_path / "example.pcap")


def test_lecture_du_fichier_pcap(example_pcap: Path) -> None:
    packets = analyze_pcap.read_pcap(example_pcap)
    assert len(packets) > 40
    assert packets[0].src_mac == pcap_builder.MAC_CLIENT
    assert packets[0].transport == "ARP"


def test_aucun_paquet_avec_magie_inconnue(tmp_path: Path) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"XXXX" + bytes(40))
    with pytest.raises(analyze_pcap.NotAPcapError, match="magie inconnue"):
        analyze_pcap.read_pcap(path)


def test_pcapng_refuse_avec_un_message_utile(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(40))
    with pytest.raises(analyze_pcap.NotAPcapError, match="editcap"):
        analyze_pcap.read_pcap(path)


def test_fichier_absent(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        analyze_pcap.read_pcap(tmp_path / "absent.pcap")


def test_decodage_arp_et_icmp(example_pcap: Path) -> None:
    packets = analyze_pcap.read_pcap(example_pcap)
    arp_packets = [packet for packet in packets if packet.transport == "ARP"]
    assert arp_packets[0].payload == b"request"
    assert arp_packets[0].src_ip == pcap_builder.IP_CLIENT
    assert arp_packets[1].payload == b"reply"

    icmp_packets = [packet for packet in packets if packet.transport == "ICMP"]
    assert len(icmp_packets) == 4  # 2 requêtes + 2 réponses


def test_decodage_http_et_formulaire_en_clair(example_pcap: Path) -> None:
    packets = analyze_pcap.read_pcap(example_pcap)
    http = [packet for packet in packets if packet.http_request]
    assert len(http) == 2  # GET puis POST
    assert b"password=MotDePasseFactice123" in http[1].payload


def test_decodage_dns(example_pcap: Path) -> None:
    packets = analyze_pcap.read_pcap(example_pcap)
    queries = [packet.dns_query for packet in packets if packet.dns_query]
    assert queries == ["lab.local"]  # la réponse n'est pas une question


def test_decodage_tls(example_pcap: Path) -> None:
    packets = analyze_pcap.read_pcap(example_pcap)
    assert any(packet.tls_handshake for packet in packets)


def test_hierarchie_de_protocoles(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    for protocol in ("ethernet", "ipv4", "arp", "tcp", "udp", "icmp", "dns", "http", "tls"):
        assert result.protocols[protocol] > 0, f"protocole manquant : {protocol}"


def test_top_talkers(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    assert pcap_builder.IP_SERVER in result.talkers
    # Le serveur parle à tout le monde : il doit être en tête.
    top = max(result.talkers.items(), key=lambda item: item[1]["packets"])
    assert top[0] == pcap_builder.IP_SERVER


def test_conversations_triees_par_volume(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    octets = [conversation.bytes for conversation in result.conversations]
    assert octets == sorted(octets, reverse=True)
    assert any(conversation.dst_port == 80 for conversation in result.conversations)


def test_detection_de_scan_syn(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    assert len(result.syn_scans) == 1
    scan = result.syn_scans[0]
    assert scan["src"] == pcap_builder.IP_ATTACKER
    assert scan["port_count"] == 25


def test_pas_de_scan_quand_le_trafic_est_normal(tmp_path: Path) -> None:
    # Une seule connexion TCP : aucun scan ne doit être signalé.
    frames = [
        (
            1_800_000_000.0 + index * 0.01,
            pcap_builder.ethernet(
                pcap_builder.MAC_SERVER,
                pcap_builder.MAC_CLIENT,
                pcap_builder.ETH_IPV4,
                pcap_builder.ipv4(
                    pcap_builder.IP_CLIENT,
                    pcap_builder.IP_SERVER,
                    6,
                    pcap_builder.tcp(40000, 80, pcap_builder.TCP_SYN),
                ),
            ),
        )
        for index in range(3)
    ]
    path = pcap_builder.write_pcap(tmp_path / "normal.pcap", frames)
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(path), path)
    assert result.syn_scans == []


def test_detection_de_retransmission(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    assert len(result.retransmissions) >= 1


def test_drapeaux_tcp_comptes(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    assert result.tcp_flags["SYN"] > 0
    assert result.tcp_flags["ACK"] > 0
    assert result.tcp_flags["FIN"] > 0
    assert result.tcp_flags["RST"] > 0


def test_rapport_markdown(example_pcap: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    rapport = analyze_pcap.build_markdown(result)
    assert "# Analyse de la capture" in rapport
    assert "Top talkers" in rapport
    assert "Hiérarchie de protocoles" in rapport
    assert "Scan SYN probable" in rapport
    assert "Retransmissions TCP" in rapport
    assert "lab.local" in rapport


def test_csv_des_conversations(example_pcap: Path, tmp_path: Path) -> None:
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(example_pcap), example_pcap)
    csv_path = analyze_pcap.write_csv(result, tmp_path / "conv.csv")
    lignes = csv_path.read_text(encoding="utf-8").splitlines()
    assert lignes[0].startswith("protocole,ip_source")
    assert len(lignes) > 1


def test_capture_vide(tmp_path: Path) -> None:
    path = pcap_builder.write_pcap(tmp_path / "vide.pcap", [])
    result = analyze_pcap.analyze(analyze_pcap.read_pcap(path), path)
    assert result.packet_count == 0
    assert "Capture vide" in analyze_pcap.build_markdown(result)


def test_cli_produit_les_deux_fichiers(example_pcap: Path, tmp_path: Path) -> None:
    code = analyze_pcap.main(
        ["--input", str(example_pcap), "--out", str(tmp_path / "out")]
    )
    assert code == 0
    assert (tmp_path / "out" / "analyse-example.md").exists()
    assert (tmp_path / "out" / "analyse-example.csv").exists()


def test_cli_fichier_invalide_retourne_2(tmp_path: Path) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"nope" * 20)
    assert analyze_pcap.main(["--input", str(path)]) == 2
