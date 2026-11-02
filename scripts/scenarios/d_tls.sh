#!/usr/bin/env bash
# Scénario D – TLS avec certificat auto-signé.
#
# Objectif : comparer avec le scénario B. Ici le contenu (URL, en-têtes,
# formulaire, mot de passe) n'est plus lisible : seuls le handshake TLS, le
# nom du serveur (SNI) et les métadonnées (IP, ports, volume) restent visibles.
#
# Le certificat est auto-signé et généré localement : normal qu'un navigateur
# affiche un avertissement, c'est le principe du certificat auto-signé.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_NAME="d_tls"

# shellcheck source=../lib/scenario.sh
# shellcheck source-path=SCRIPTDIR
source "$SCRIPT_DIR/../lib/scenario.sh"

parse_scenario_args "$@"
check_lab

command -v openssl >/dev/null 2>&1 || { echo "openssl est requis." >&2; exit 1; }

CERT_DIR="/tmp/lab-tls"
CERT="$CERT_DIR/lab.crt"
KEY="$CERT_DIR/lab.key"

if ((DRY_RUN)); then
    echo "[DRY-RUN] création du certificat auto-signé dans $CERT_DIR" >&2
else
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj "/CN=lab.local" -addext "subjectAltName=DNS:lab.local,IP:${SERVER_IP}" \
        -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
    echo "Certificat auto-signé créé : $CERT" >&2
fi

echo "== Démarrage du serveur TLS dans $NS_SERVER (port 8443) ==" >&2
if ((DRY_RUN)); then
    echo "[DRY-RUN] démarrait openssl s_server -www -accept 8443 dans $NS_SERVER" >&2
    SERVER_PID=""
else
    ip netns exec "$NS_SERVER" openssl s_server -quiet -www \
        -accept 8443 -cert "$CERT" -key "$KEY" >/dev/null 2>&1 &
    SERVER_PID=$!
    sleep 1
fi

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        echo "Serveur TLS arrêté." >&2
    fi
}
trap cleanup EXIT

echo "== Requête HTTPS (d'où le -k : certificat auto-signé) ==" >&2
nsrun "$NS_CLIENT" curl -sk -o /dev/null -w 'code HTTPS : %{http_code}\n' "https://${SERVER_IP}:8443/"

cat >&2 <<EOF

Résultat attendu :
  - handshake TLS visible : Client Hello, Server Hello, certificat, échange de clés ;
  - le SNI « lab.local » est visible dans le Client Hello ;
  - AUCUN en-tête HTTP, AUCUN formulaire, AUCUN mot de passe lisible ;
  - seuls restent visibles : IP source/destination, ports, quantité de données.

À comparer avec le scénario B : même type d'échange, résultat opposé.
EOF

print_filters "tls.handshake || tcp.port == 8443"
