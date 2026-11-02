#!/usr/bin/env bash
# Scénario B – handshake TCP + HTTP en clair.
#
# Objectif : montrer qu'un identifiant envoyé en HTTP (donc NON chiffré) est
# lisible par n'importe qui capture le trafic. Les identifiants utilisés ici
# sont FACTICES : ils ne servent qu'à la démonstration.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_NAME="b_tcp_http"

# shellcheck source=../lib/scenario.sh
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/../lib/scenario.sh"

parse_scenario_args "$@"
check_lab

command -v curl >/dev/null 2>&1 || { echo "curl est requis." >&2; exit 1; }

echo "== 1. Requête GET (handshake TCP + HTTP) ==" >&2
nsrun "$NS_CLIENT" curl -s -o /dev/null -w 'code HTTP : %{http_code}\n' "http://${SERVER_IP}/"

echo "" >&2
echo "== 2. Envoi d'un identifiant FACTICE en clair ==" >&2
nsrun "$NS_CLIENT" curl -s -o /dev/null -X POST \
    -d "username=demo&password=MotDePasseFactice123" \
    "http://${SERVER_IP}/login"

cat >&2 <<'EOF'

Résultat attendu :
  - handshake TCP en 3 temps (SYN, SYN/ACK, ACK) ;
  - une requête HTTP GET puis une POST contenant
    « username=demo&password=MotDePasseFactice123 » en clair.

C'est exactement pour cela que HTTP ne doit jamais transporter de mot de passe :
le mot de passe ci-dessus est faux, mais la démonstration est valable.
EOF

print_filters "tcp.flags.syn==1 || http.request"
