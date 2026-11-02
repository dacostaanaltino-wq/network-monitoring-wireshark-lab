#!/usr/bin/env bash
# scripts/setup_lab.sh – crée un réseau de lab 100 % virtuel (aucun matériel).
#
# Topologie créée :
#
#   br-lab  10.10.0.1/24   (pont sur la machine hôte)
#     ├── veth-lab-client   ── lab-client    10.10.0.2
#     ├── veth-lab-server   ── lab-server    10.10.0.3   (HTTP + DNS local)
#     └── veth-lab-attacker ── lab-attacker  10.10.0.4   (poste « attaquant »)
#
# Les trois hôtes sont des « network namespaces » Linux : chacun a sa pile
# réseau, ses routes et ses sockets. Aucun impact sur le réseau réel, et tout
# disparaît avec teardown_lab.sh.
#
# Ce script est idempotent : le relancer ne casse rien et ne crée pas de doublon.

set -euo pipefail

BRIDGE="br-lab"
SUBNET="10.10.0.0/24"
HOST_IP="10.10.0.1"
CLIENT_IP="10.10.0.2"
SERVER_IP="10.10.0.3"
ATTACKER_IP="10.10.0.4"

NS_CLIENT="lab-client"
NS_SERVER="lab-server"
NS_ATTACKER="lab-attacker"

RUN_DIR="/run/netlab"
PID_HTTP="$RUN_DIR/http.pid"
PID_DNS="$RUN_DIR/dnsmasq.pid"

DRY_RUN=0
ASSUME_YES=0
START_SERVICES=1

usage() {
    cat <<EOF
setup_lab.sh – crée le réseau de lab virtuel (pont + 3 namespaces).

Usage : sudo ./scripts/setup_lab.sh [OPTIONS]

Options :
  -y, --yes          Ne pas demander de confirmation (script automatisé).
      --no-services  Crée la topologie sans démarrer HTTP ni DNS.
  -n, --dry-run      Affiche les commandes sans rien créer.
  -h, --help         Affiche cette aide.

Topologie : ${BRIDGE} ${HOST_IP}/24, client ${CLIENT_IP}, serveur ${SERVER_IP},
attaquant ${ATTACKER_IP}. Tout est supprimé par teardown_lab.sh.
EOF
}

while (($# > 0)); do
    case "$1" in
        -y | --yes)
            ASSUME_YES=1
            shift
            ;;
        --no-services)
            START_SERVICES=0
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
    "$@"
}

# ---------------------------------------------------------------------------
# Garde-fous
# ---------------------------------------------------------------------------
if ((!DRY_RUN)) && [[ "$(id -u)" -ne 0 ]]; then
    echo "Ce script doit être lancé avec sudo (ou --dry-run)." >&2
    exit 1
fi

if ((!ASSUME_YES)) && ((!DRY_RUN)); then
    cat >&2 <<EOF
Ce script va créer sur CETTE machine :
  - un pont réseau ${BRIDGE} (${SUBNET}) ;
  - 3 namespaces réseau et 3 paires veth ;
  - éventuellement 2 petits serveurs (HTTP, DNS) dans le namespace serveur.

Rien n'est envoyé vers l'extérieur. Tout est supprimé par teardown_lab.sh.
Tape « oui » pour continuer :
EOF
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

command -v ip >/dev/null 2>&1 || { echo "iproute2 est requis (commande ip)." >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Pont
# ---------------------------------------------------------------------------
if ip link show "$BRIDGE" >/dev/null 2>&1; then
    log "Pont $BRIDGE déjà présent"
else
    run ip link add "$BRIDGE" type bridge
fi

if ip -4 addr show dev "$BRIDGE" 2>/dev/null | grep -q "${HOST_IP}/"; then
    log "Adresse $HOST_IP déjà configurée sur $BRIDGE"
else
    run ip addr add "${HOST_IP}/24" dev "$BRIDGE"
fi
run ip link set "$BRIDGE" up

# ---------------------------------------------------------------------------
# 2. Namespaces et paires veth
# ---------------------------------------------------------------------------
ensure_namespace() {
    local ns="$1"
    local ip_addr="$2"
    local host_end="veth-${ns}-h"
    local ns_end="veth-${ns}-n"

    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        log "Namespace $ns déjà présent"
    else
        run ip netns add "$ns"
    fi

    if ip link show "$host_end" >/dev/null 2>&1; then
        log "veth $host_end déjà présent"
    else
        run ip link add "$host_end" type veth peer name "$ns_end"
        run ip link set "$host_end" master "$BRIDGE"
        run ip link set "$host_end" up
        run ip link set "$ns_end" netns "$ns"
    fi

    # Idempotence : on vérifie l'adresse avant de l'ajouter.
    if ip netns exec "$ns" ip -4 addr show dev "$ns_end" 2>/dev/null | grep -q "$ip_addr/"; then
        log "Adresse $ip_addr déjà posée dans $ns"
    else
        run ip netns exec "$ns" ip addr add "$ip_addr/24" dev "$ns_end"
    fi
    run ip netns exec "$ns" ip link set "$ns_end" up
    run ip netns exec "$ns" ip link set lo up

    # IPv6 désactivé : les captures restent lisibles (pas de NDP parasite).
    if ((!DRY_RUN)); then
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || \
            log "IPv6 non désactivé dans $ns (pas bloquant)"
    fi
}

ensure_namespace "$NS_CLIENT" "$CLIENT_IP"
ensure_namespace "$NS_SERVER" "$SERVER_IP"
ensure_namespace "$NS_ATTACKER" "$ATTACKER_IP"

# ---------------------------------------------------------------------------
# 3. Services dans le namespace serveur
# ---------------------------------------------------------------------------
if ((START_SERVICES)); then
    run mkdir -p "$RUN_DIR"

    # HTTP : le serveur web intégré de Python, suffisant pour un lab.
    if ((!DRY_RUN)) && [[ -f "$PID_HTTP" ]] && kill -0 "$(cat "$PID_HTTP")" 2>/dev/null; then
        log "Serveur HTTP déjà lancé (PID $(cat "$PID_HTTP"))"
    else
        if ((DRY_RUN)); then
            log "[DRY-RUN] démarrait python3 -m http.server 80 dans $NS_SERVER"
        else
            # Sert le dossier /srv/lab-http (créé au besoin), pas la racine.
            mkdir -p /srv/lab-http
            if [[ ! -f /srv/lab-http/index.html ]]; then
                printf '%s\n' '<h1>Serveur de lab</h1><p>Réseau de test uniquement.</p>' \
                    >/srv/lab-http/index.html
            fi
            ip netns exec "$NS_SERVER" python3 -m http.server 80 \
                --directory /srv/lab-http >/dev/null 2>&1 &
            echo $! >"$PID_HTTP"
            log "Serveur HTTP lancé (PID $(cat "$PID_HTTP")) sur ${SERVER_IP}:80"
        fi
    fi

    # DNS : dnsmasq, seulement s'il est installé.
    if command -v dnsmasq >/dev/null 2>&1; then
        if ((!DRY_RUN)) && [[ -f "$PID_DNS" ]] && kill -0 "$(cat "$PID_DNS")" 2>/dev/null; then
            log "dnsmasq déjà lancé (PID $(cat "$PID_DNS"))"
        else
            if ((DRY_RUN)); then
                log "[DRY-RUN] démarrait dnsmasq dans $NS_SERVER (zone lab.local)"
            else
                CONF="$RUN_DIR/dnsmasq.conf"
                cat >"$CONF" <<EOF
# dnsmasq du lab : répond uniquement pour lab.local
port=53
bind-interfaces
listen-address=${SERVER_IP}
no-resolv
no-hosts
domain-needed
local=/lab.local/
address=/lab.local/${SERVER_IP}
log-queries
EOF
                ip netns exec "$NS_SERVER" dnsmasq --conf-file="$CONF" \
                    --pid-file="$PID_DNS" >/dev/null 2>&1 || \
                    log "dnsmasq n'a pas démarré (voir journalctl | grep dnsmasq)"
                [[ -f "$PID_DNS" ]] && log "dnsmasq lancé (PID $(cat "$PID_DNS")) sur ${SERVER_IP}:53" || true
            fi
        fi
    else
        log "dnsmasq absent : scénario DNS limité. Installation : sudo dnf install dnsmasq"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Résumé
# ---------------------------------------------------------------------------
if ((DRY_RUN)); then
    log "Simulation terminée : aucune modification."
    exit 0
fi

cat >&2 <<EOF

Réseau de lab prêt :
  ${BRIDGE} (hôte)      ${HOST_IP}/24
  ${NS_CLIENT}         ${CLIENT_IP}     (poste client)
  ${NS_SERVER}         ${SERVER_IP}     (HTTP :80, DNS :53)
  ${NS_ATTACKER}       ${ATTACKER_IP}   (poste « attaquant » de lab)

Vérifier :
  ip netns list
  ip -br addr show ${BRIDGE}
  sudo ip netns exec ${NS_CLIENT} ping -c 2 ${SERVER_IP}

Capturer puis rejouer un scénario :
  sudo ./scripts/capture.sh --scenario a
  sudo ./scripts/teardown_lab.sh          # nettoyage complet
EOF
