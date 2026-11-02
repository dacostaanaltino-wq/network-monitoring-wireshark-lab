#!/usr/bin/env bash
# Scénario C – requête et réponse DNS.
#
# Objectif : voir la question DNS en clair (« quel est le nom ? ») et sa
# réponse. Le DNS n'est pas chiffré : un observateur du réseau voit tous les
# noms de domaine demandés par une machine.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_NAME="c_dns"

# shellcheck source=../lib/scenario.sh
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/../lib/scenario.sh"

parse_scenario_args "$@"
check_lab

echo "== Requête DNS vers le serveur de lab (${SERVER_IP}) ==" >&2

if command -v dig >/dev/null 2>&1; then
    nsrun "$NS_CLIENT" dig +short "@${SERVER_IP}" lab.local A
    nsrun "$NS_CLIENT" dig +nocmd +noall +answer "@${SERVER_IP}" lab.local A
else
    echo "dig absent (paquet bind-utils) : repli sur Python." >&2
    nsrun "$NS_CLIENT" python3 -c "
import socket
print(socket.gethostbyname_ex('lab.local'))
"
fi

cat >&2 <<EOF

Résultat attendu :
  - une requête DNS (port 53/udp) demandant lab.local ;
  - une réponse contenant ${SERVER_IP}.

Filtre utile : dns et dns.qry.name == "lab.local"
EOF

print_filters "dns"
