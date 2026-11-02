#!/usr/bin/env bash
# Scénario F – scan de ports nmap et sa détection dans la capture.
#
# PÉRIMÈTRE : le scan part du namespace « attaquant de lab » et ne vise QUE le
# serveur de lab (10.10.0.3), qui m'appartient puisqu'il tourne sur ma machine.
# Scanner une autre machine est illégal et n'est jamais couvert par ce projet.
#
# Objectif : reconnaître la signature d'un scan SYN dans une capture, puis
# vérifier que l'outil d'analyse la retrouve automatiquement.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_NAME="f_port_scan"

# shellcheck source=../lib/scenario.sh
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/../lib/scenario.sh"

parse_scenario_args "$@"
check_lab

if ((!DRY_RUN)) && ! command -v nmap >/dev/null 2>&1; then
    cat >&2 <<'EOF'
nmap est absent. Installation : sudo dnf install nmap
(Le scénario ne fait rien sans nmap.)
EOF
    exit 1
fi

# Plage volontairement petite : 21 ports, uniquement vers le serveur de lab.
PORTS="20-40"

echo "== Scan SYN de ${ATTACKER_IP} vers ${SERVER_IP} (ports ${PORTS}) ==" >&2
nsrun "$NS_ATTACKER" nmap -sS -Pn -n -p "$PORTS" "$SERVER_IP"

cat >&2 <<'EOF'

Résultat attendu :
  - beaucoup de paquets SYN vers de nombreux ports, presque aucun ACK final :
    c'est la signature d'un scan de ports ;
  - les ports 53 (DNS) et 80 (HTTP) répondent SYN/ACK, les autres répondent
    RST/ACK (fermés) ;
  - l'analyse automatique doit produire une alerte « scan SYN » pour l'IP
    source 10.10.0.4.

Un scan ne prouve pas une intention, mais un scan suivi d'une exploitation,
c'est une intrusion.
EOF

print_filters "tcp.flags.syn==1 && tcp.flags.ack==0"
