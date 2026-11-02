#!/usr/bin/env bash
# scripts/lib/scenario.sh – code commun aux 6 scénarios.
#
# À charger avec :  source "$SCRIPT_DIR/lib/scenario.sh"
# Fournit les noms/adresses du lab, l'aide commune, le mode --dry-run et les
# fonctions nsrun/check_lab.

# shellcheck shell=bash
# Ces variables sont consommées par les scripts qui chargent ce fichier :
# shellcheck disable=SC2034

NS_CLIENT="lab-client"
NS_SERVER="lab-server"
NS_ATTACKER="lab-attacker"

HOST_IP="10.10.0.1"
CLIENT_IP="10.10.0.2"
SERVER_IP="10.10.0.3"
ATTACKER_IP="10.10.0.4"

CLIENT_IF="veth-lab-client-n"

DRY_RUN=0

# Aide commune aux scénarios.
print_scenario_help() {
    local name="$1"
    cat <<EOF
${name} – scénario du lab network-monitoring-wireshark-lab.

Usage : sudo ./scripts/scenarios/${name} [OPTIONS]

Options :
  -n, --dry-run   Affiche les commandes sans les exécuter.
  -h, --help      Affiche cette aide.

Prérequis : sudo ./scripts/setup_lab.sh (réseau de lab créé).
Tout le trafic reste entre les namespaces du lab (10.10.0.0/24).
EOF
}

# Analyse les options communes. À appeler après avoir défini $SCENARIO_NAME.
parse_scenario_args() {
    while (($# > 0)); do
        case "$1" in
            -n | --dry-run)
                DRY_RUN=1
                shift
                ;;
            -h | --help)
                print_scenario_help "${SCENARIO_NAME:-scenario}"
                exit 0
                ;;
            *)
                echo "Option inconnue : $1 (voir --help)" >&2
                exit 2
                ;;
        esac
    done
}

# Vérifie que le lab existe (inutile en dry-run).
check_lab() {
    if ((DRY_RUN)); then
        echo "[DRY-RUN] (lab non vérifié en simulation)" >&2
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Ce scénario doit être lancé avec sudo." >&2
        exit 1
    fi
    if ! ip netns list | awk '{print $1}' | grep -qx "$NS_SERVER"; then
        echo "Le lab n'existe pas encore : sudo ./scripts/setup_lab.sh" >&2
        exit 1
    fi
}

# Exécute une commande dans un namespace (ou l'affiche en dry-run).
nsrun() {
    local ns="$1"
    shift
    if ((DRY_RUN)); then
        printf '[DRY-RUN] ip netns exec %s %s\n' "$ns" "$*" >&2
        return 0
    fi
    printf '[EXEC] ip netns exec %s %s\n' "$ns" "$*" >&2
    ip netns exec "$ns" "$@"
}

# Rappelle les filtres Wireshark/tshark utiles pour le scénario.
print_filters() {
    local filter="$1"
    cat >&2 <<EOF

Filtre d'affichage Wireshark/tshark :
  ${filter}

Analyse automatique après capture :
  python3 analysis/analyze_pcap.py --input captures/${SCENARIO_NAME}.pcap \\
          --out reports/ --markdown
EOF
}
