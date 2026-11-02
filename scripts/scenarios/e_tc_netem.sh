#!/usr/bin/env bash
# Scénario E – 5 % de perte de paquets avec tc netem, puis retransmissions TCP.
#
# Objectif : voir comment TCP réagit à la perte. Chaque segment perdu est
# retransmis (après un délai de retransmission) : le débit baisse, mais les
# données arrivent quand même. C'est la robustesse de TCP, et c'est aussi ce qui
# permet de repérer un problème réseau dans une capture.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_NAME="e_tc_netem"

# shellcheck source=../lib/scenario.sh
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/../lib/scenario.sh"

parse_scenario_args "$@"
check_lab

LOSS="5%"
FILE_URL="http://${SERVER_IP}/big.bin"

# Fichier de 200 Ko pour avoir assez de segments TCP à observer.
if ((DRY_RUN)); then
    echo "[DRY-RUN] créait /srv/lab-http/big.bin (200 Ko) et démarrait la perte $LOSS" >&2
else
    mkdir -p /srv/lab-http
    if [[ ! -f /srv/lab-http/big.bin ]]; then
        dd if=/dev/urandom of=/srv/lab-http/big.bin bs=1k count=200 status=none
        echo "Fichier de test créé : /srv/lab-http/big.bin (200 Ko)" >&2
    fi
fi

cleanup() {
    if ((!DRY_RUN)); then
        ip netns exec "$NS_CLIENT" tc qdisc del dev "$CLIENT_IF" root 2>/dev/null || true
        echo "Perte de paquets retirée (tc qdisc del)." >&2
    fi
}
trap cleanup EXIT

echo "== Ajout de ${LOSS} de perte sur l'interface client ($CLIENT_IF) ==" >&2
nsrun "$NS_CLIENT" tc qdisc replace dev "$CLIENT_IF" root netem loss "$LOSS"

echo "== Téléchargement de 200 Ko (le transfert doit ralentir) ==" >&2
nsrun "$NS_CLIENT" curl -s -o /dev/null -w 'octets reçus : %{size_download} en %{time_total}s\n' "$FILE_URL"

echo "== Deuxième transfert pour comparaison ==" >&2
nsrun "$NS_CLIENT" curl -s -o /dev/null -w 'octets reçus : %{size_download} en %{time_total}s\n' "$FILE_URL"

cat >&2 <<'EOF'

Résultat attendu :
  - des segments TCP retransmis (tcp.analysis.retransmission dans Wireshark) ;
  - éventuellement des « duplicate ACK » et une réduction de la fenêtre ;
  - le fichier est tout de même téléchargé en entier (TCP protège les données).

La commande tc est annulée automatiquement à la fin du scénario.
EOF

print_filters "tcp.analysis.retransmission || tcp.analysis.duplicate_ack"
