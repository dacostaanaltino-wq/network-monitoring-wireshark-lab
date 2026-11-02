#!/usr/bin/env bash
# scripts/teardown_lab.sh – remet le système dans son état initial.
#
# Supprime : les processus HTTP/DNS du lab, les 3 namespaces (ce qui supprime
# aussi leurs paires veth), le pont br-lab et les fichiers de /run/netlab.
# Le script est idempotent : le lancer deux fois ne produit pas d'erreur.

set -euo pipefail

BRIDGE="br-lab"
NAMESPACES=("lab-client" "lab-server" "lab-attacker")
RUN_DIR="/run/netlab"

DRY_RUN=0
ASSUME_YES=0

usage() {
    cat <<'EOF'
teardown_lab.sh – supprime le réseau de lab virtuel.

Usage : sudo ./scripts/teardown_lab.sh [OPTIONS]

Options :
  -y, --yes       Ne pas demander de confirmation.
  -n, --dry-run   Affiche ce qui serait supprimé.
  -h, --help      Affiche cette aide.

Supprime les namespaces lab-client/lab-server/lab-attacker, le pont br-lab,
les paires veth associées et /run/netlab. Ne touche à rien d'autre.
EOF
}

while (($# > 0)); do
    case "$1" in
        -y | --yes)
            ASSUME_YES=1
            shift
            ;;
        -n | --dry-run)
            DRY_RUN=1
            shift
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

log() { printf '[lab] %s\n' "$*" >&2; }
run() {
    if ((DRY_RUN)); then
        printf '[DRY-RUN] %s\n' "$*" >&2
        return 0
    fi
    printf '[EXEC] %s\n' "$*" >&2
    "$@" || log "échec ignoré : $*"
}

if ((!DRY_RUN)) && [[ "$(id -u)" -ne 0 ]]; then
    echo "Ce script doit être lancé avec sudo (ou --dry-run)." >&2
    exit 1
fi

if ((!ASSUME_YES)) && ((!DRY_RUN)); then
    echo "Cette commande supprime le lab (namespaces, pont br-lab, services)." >&2
    printf 'Tape « oui » pour continuer : ' >&2
    answer=""
    read -r answer || true
    case "$answer" in
        oui | Oui | OUI | yes | y) ;;
        *)
            echo "Annulé." >&2
            exit 1
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# 1. Services du lab
# ---------------------------------------------------------------------------
for pidfile in "$RUN_DIR/http.pid" "$RUN_DIR/dnsmasq.pid"; do
    if [[ -f "$pidfile" ]]; then
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" 2>/dev/null; then
            log "Arrêt du processus $pid ($pidfile)"
            run kill "$pid"
        else
            log "Processus $pid déjà arrêté"
        fi
    fi
done

# Filet de sécurité : un serveur HTTP resté dans un namespace du lab.
for ns in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        run ip netns pids "$ns" | xargs -r kill
    fi
done

# ---------------------------------------------------------------------------
# 2. Namespaces (supprime aussi les veth qui y sont attachés)
# ---------------------------------------------------------------------------
for ns in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        run ip netns del "$ns"
    else
        log "Namespace $ns absent"
    fi
done

# ---------------------------------------------------------------------------
# 3. Pont et restes éventuels
# ---------------------------------------------------------------------------
if ip link show "$BRIDGE" >/dev/null 2>&1; then
    run ip link set "$BRIDGE" down
    run ip link del "$BRIDGE"
else
    log "Pont $BRIDGE absent"
fi

for host_end in veth-lab-client-h veth-lab-server-h veth-lab-attacker-h; do
    if ip link show "$host_end" >/dev/null 2>&1; then
        run ip link del "$host_end"
    fi
done

run rm -rf "$RUN_DIR"

# ---------------------------------------------------------------------------
# 4. Vérification
# ---------------------------------------------------------------------------
if ((!DRY_RUN)); then
    remaining="$(ip netns list || true)"
    if [[ -n "$remaining" ]]; then
        log "Namespaces restants (peuvent appartenir à un autre outil) :"
        printf '%s\n' "$remaining" >&2
    else
        log "Aucun namespace restant : système propre."
    fi
    if ip link show "$BRIDGE" >/dev/null 2>&1; then
        log "ATTENTION : $BRIDGE existe encore."
    else
        log "Pont $BRIDGE supprimé."
    fi
fi

log "Nettoyage terminé."
