#!/usr/bin/env bash
# Scénario A – ARP puis ICMP (ping).
#
# Objectif : voir la résolution d'adresse (ARP) qui précède tout échange IP sur
# le réseau local, puis les allers-retours ICMP (echo request/reply).
#
# Ce qu'on doit voir : une requête ARP « who has 10.10.0.3? tell 10.10.0.2 »,
# une réponse, puis 4 paires ICMP de type 8 (request) et 0 (reply).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_NAME="a_arp_icmp"

# shellcheck source=../lib/scenario.sh
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/../lib/scenario.sh"

parse_scenario_args "$@"
check_lab

# On vide la table ARP du client pour forcer une résolution observable.
nsrun "$NS_CLIENT" ip neigh flush all || true
nsrun "$NS_CLIENT" ping -c 4 -W 2 "$SERVER_IP"

echo "" >&2
echo "Résultat attendu : ARP (request + reply) puis 4 ICMP echo request/reply." >&2
print_filters "arp || icmp"
