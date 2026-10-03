#!/usr/bin/env bash
# Private CA + server certificate (for the stunnel terminator) + one client certificate per forwarding host (for NXLog), all PEM.
#
#   ./make-certs.sh logunify.corp.example.com WinServer-01 [more-client-names...]          # DNS name the forwarders will connect to
#   ./make-certs.sh 10.0.5.20 WinServer-01                                                  # or an IP address
#   OUT=/secure/place DAYS_SERVER=730 DAYS_CLIENT=365 ./make-certs.sh ...
#
# Output (default ./certs): ca.crt  ca.key | logunify-server.crt  logunify-server.key | <client>.crt  <client>.key
#   * ca.key signs every certificate: move it OFFLINE after this run; whoever holds it can mint a certificate that is accepted by the listener.
#   * the server name you pass MUST be the exact name/IP the forwarders connect to (it goes into the certificate's subjectAltName).
#   * keys are written 0600, unencrypted (NXLog's om_ssl cannot prompt for a passphrase): protect them with file permissions.
# Needs: bash, openssl >= 1.1.1.   Never overwrites existing files. Run it again later with the same OUT and a new client name to add a host: the CA and the server certificate are reused
# (ca.key must be back in OUT for that). To re-issue something, delete it deliberately.
set -euo pipefail
[ $# -ge 2 ] || { sed -n '2,13p' "$0"; exit 2; }
SERVER="$1"; shift
OUT="${OUT:-./certs}"; DAYS_CA="${DAYS_CA:-1825}"; DAYS_SERVER="${DAYS_SERVER:-730}"; DAYS_CLIENT="${DAYS_CLIENT:-365}"
umask 077; mkdir -p "$OUT"
[[ "$SERVER" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "server name must be a DNS name or IP address" >&2; exit 2; }
for c in "$@"; do [[ "$c" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad client name '$c' (letters, digits, . _ -)" >&2; exit 2; }; done
if [[ "$SERVER" =~ ^[0-9.]+$ || "$SERVER" == *:* ]]; then SAN="IP:$SERVER"; else SAN="DNS:$SERVER"; fi
guard() { [ ! -e "$1" ] || { echo "refusing to overwrite $1 (delete it to re-issue)" >&2; exit 1; }; }
EXT="$(mktemp)"; trap 'rm -f "$EXT"' EXIT

if [ -e "$OUT/ca.crt" ] && [ -e "$OUT/ca.key" ]; then
  echo "reusing the existing CA in $OUT (it needs ca.key to be present: bring it back from offline storage to issue more certificates)"
else
  guard "$OUT/ca.crt"; guard "$OUT/ca.key"
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days "$DAYS_CA" -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
    -subj "/O=LogUnify forwarders/CN=LogUnify forwarder CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

issue() {   # name  extension-block  days
  local name="$1" ext="$2" days="$3"
  guard "$OUT/$name.crt"; guard "$OUT/$name.key"
  openssl req -newkey rsa:3072 -nodes -keyout "$OUT/$name.key" -out "$OUT/$name.csr" -subj "/O=LogUnify forwarders/CN=$name" 2>/dev/null
  printf '%s\n' "$ext" > "$EXT"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial -sha256 -days "$days" -extfile "$EXT" -out "$OUT/$name.crt" 2>/dev/null
  rm -f "$OUT/$name.csr"; chmod 600 "$OUT/$name.key"
  echo "issued $name  (valid $days days)"
}
if [ -e "$OUT/logunify-server.crt" ]; then echo "keeping the existing server certificate (the name you pass is only used when it is first issued)"; else
issue logunify-server "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN" "$DAYS_SERVER"
fi
for c in "$@"; do
  issue "$c" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth" "$DAYS_CLIENT"
done
rm -f "$OUT"/ca.srl
cat <<MSG

Done. In $OUT:
  LogUnify host (stunnel):  logunify-server.crt  logunify-server.key  ca.crt        -> /etc/stunnel/ (server cert, key, and ca.crt as forwarders-ca.crt)
  each Windows host:        <name>.crt  <name>.key  ca.crt                         -> NXLog's cert folder (see WINSERVER-01.md)
  OFFLINE after this run:   ca.key
Certificates expire (server $DAYS_SERVER d, clients $DAYS_CLIENT d): put the dates in a calendar; an expired certificate silently stops the feed.
MSG
