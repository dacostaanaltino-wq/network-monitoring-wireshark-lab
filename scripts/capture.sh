#!/usr/bin/env bash
# scripts/capture.sh – capture le trafic du lab pendant un scénario.
#
# Le script démarre la capture sur le pont br-lab, lance le scénario demandé,
# puis arrête la capture. Un fichier .pcap par scénario est écrit dans
# captures/, et le trafic capturé est UNIQUEMENT celui du lab (10.10.0.0/24).
#
# Outils : tshark (paquet wireshark-cli) ou tcpdump. Les deux écrivent au
# format pcap classique, celui que lit analysis/analyze_pcap.py.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

BRIDGE="br-lab"
CAPTURE_DIR="$REPO_DIR/captures"
MAX_SIZE_MB=5

SCENARIO=""
TOOL=""
DRY_RUN=0

usage() {
    cat <<'EOF'
capture.sh – capture le trafic d'un scénario du lab.

Usage : sudo ./scripts/capture.sh --scenario LETTRE [OPTIONS]

Options :
  -s, --scenario LETTRE   a, b, c, d, e ou f (voir docs/scenarios.md).
  -t, --tool OUTIL        tshark ou tcpdump (défaut : celui qui est installé).
  -n, --dry-run           Affiche les commandes sans capturer.
  -h, --help              Affiche cette aide.
      --list              Liste les scénarios.

Scénarios :
  a  ARP + ICMP (ping)
  b  Handshake TCP + HTTP en clair
  c  Requête/réponse DNS
  d  TLS avec certificat auto-signé
  e  Perte de paquets (tc netem) et retransmissions
  f  Scan de ports nmap (vers le serveur de lab uniquement)

Le fichier produit est captures/<scenario>.pcap (limite conseillée : 5 Mo).
EOF
}

scenario_script() {
    case "$1" in
        a) echo "$SCRIPT_DIR/scenarios/a_arp_icmp.sh" ;;
        b) echo "$SCRIPT_DIR/scenarios/b_tcp_http.sh" ;;
        c) echo "$SCRIPT_DIR/scenarios/c_dns.sh" ;;
        d) echo "$SCRIPT_DIR/scenarios/d_tls.sh" ;;
        e) echo "$SCRIPT_DIR/scenarios/e_tc_netem.sh" ;;
        f) echo "$SCRIPT_DIR/scenarios/f_port_scan.sh" ;;
        *) return 1 ;;
    esac
}

scenario_name() {
    case "$1" in
        a) echo "a_arp_icmp" ;;
        b) echo "b_tcp_http" ;;
        c) echo "c_dns" ;;
        d) echo "d_tls" ;;
        e) echo "e_tc_netem" ;;
        f) echo "f_port_scan" ;;
        *) return 1 ;;
    esac
}

while (($# > 0)); do
    case "$1" in
        -s | --scenario)
            [[ $# -ge 2 ]] || { echo "L'option $1 demande un argument." >&2; exit 2; }
            SCENARIO="$2"
            shift 2
            ;;
        -t | --tool)
            [[ $# -ge 2 ]] || { echo "L'option $1 demande un argument." >&2; exit 2; }
            TOOL="$2"
            shift 2
            ;;
        -n | --dry-run)
            DRY_RUN=1
            shift
            ;;
        --list)
            printf 'a  ARP + ICMP\nb  TCP + HTTP en clair\nc  DNS\nd  TLS\ne  tc netem (perte de paquets)\nf  scan nmap\n'
            exit 0
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "Option inconnue : $1 (voir --help)" >&2
            exit 2
            ;;
    esac
done

[[ -n "$SCENARIO" ]] || { usage >&2; exit 2; }
SCRIPT_PATH="$(scenario_script "$SCENARIO")" || { echo "Scénario inconnu : $SCENARIO (a à f)" >&2; exit 2; }
NAME="$(scenario_name "$SCENARIO")"
PCAP="$CAPTURE_DIR/$NAME.pcap"

# ---------------------------------------------------------------------------
# Outil de capture
# ---------------------------------------------------------------------------
if [[ -z "$TOOL" ]]; then
    if command -v tshark >/dev/null 2>&1; then
        TOOL="tshark"
    elif command -v tcpdump >/dev/null 2>&1; then
        TOOL="tcpdump"
    else
        echo "Ni tshark ni tcpdump : sudo dnf install wireshark-cli tcpdump" >&2
        exit 1
    fi
fi

case "$TOOL" in
    tshark | tcpdump) ;;
    *)
        echo "Outil non pris en charge : $TOOL (tshark ou tcpdump)" >&2
        exit 2
        ;;
esac

# ---------------------------------------------------------------------------
# Permissions de capture (documenté aussi dans README)
# ---------------------------------------------------------------------------
# Capturer sur une interface demande CAP_NET_RAW (root) ou d'être dans le
# groupe « wireshark » avec les binaires dumpcap/tshark marqués setcap (le
# paquet wireshark fait cela à l'installation).
if ((!DRY_RUN)) && [[ "$(id -u)" -ne 0 ]]; then
    if ! command -v dumpcap >/dev/null 2>&1 || ! getcap "$(command -v dumpcap)" 2>/dev/null | grep -q cap_net_raw; then
        cat >&2 <<'EOF'
Droits de capture insuffisants.

Deux solutions :
  1. lancer ce script avec sudo ;
  2. ajouter mon compte au groupe wireshark (paquet wireshark installé) :
       sudo usermod -aG wireshark "$USER"     # puis se déconnecter/reconnecter
     et vérifier que dumpcap a bien la capacité :
       getcap "$(command -v dumpcap)"          # cap_net_raw,cap_net_admin=ep
EOF
        exit 1
    fi
fi

# En dry-run, le lab n'a pas besoin d'exister : on affiche seulement les commandes.
if ((!DRY_RUN)) && ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    echo "Le pont $BRIDGE n'existe pas : sudo ./scripts/setup_lab.sh" >&2
    exit 1
fi

mkdir -p "$CAPTURE_DIR"

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------
start_capture() {
    if [[ "$TOOL" == "tshark" ]]; then
        # -F pcap : format pcap classique (et non pcapng), lisible partout.
        tshark -i "$BRIDGE" -w "$PCAP" -F pcap -q >/dev/null 2>&1 &
    else
        # -U : écrit les paquets au fur et à mesure (important en direct).
        tcpdump -i "$BRIDGE" -w "$PCAP" -s 0 -U -q >/dev/null 2>&1 &
    fi
    CAPTURE_PID=$!
}

stop_capture() {
    if [[ -n "${CAPTURE_PID:-}" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
        # SIGINT : les deux outils vident alors leur tampon et ferment le fichier.
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi
}

if ((DRY_RUN)); then
    cat >&2 <<EOF
[DRY-RUN] capture ${TOOL} sur ${BRIDGE} -> $PCAP
[DRY-RUN] exécuterait : sudo $SCRIPT_PATH
EOF
    exit 0
fi

trap stop_capture EXIT INT TERM

echo "Capture démarrée ($TOOL) sur $BRIDGE -> $PCAP" >&2
start_capture
sleep 1

echo "== Exécution du scénario $NAME ==" >&2
if ! bash "$SCRIPT_PATH"; then
    echo "Le scénario a échoué : la capture est conservée pour analyse." >&2
fi

stop_capture
CAPTURE_PID=""

# ---------------------------------------------------------------------------
# Bilan
# ---------------------------------------------------------------------------
SIZE_BYTES=$(stat -c '%s' "$PCAP" 2>/dev/null || echo 0)
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

cat >&2 <<EOF

Capture terminée : $PCAP
Taille : ${SIZE_BYTES} octets

Étape suivante :
  python3 analysis/analyze_pcap.py --input "$PCAP" --out reports/ --markdown
  wireshark "$PCAP"
EOF

if ((SIZE_MB > MAX_SIZE_MB)); then
    cat >&2 <<EOF

ATTENTION : $PCAP dépasse ${MAX_SIZE_MB} Mo.
Réduis la durée du scénario, ou filtre la capture, ou découpe avec editcap :
  editcap -c 100000 "$PCAP" captures/${NAME}_partie.pcap
EOF
fi
