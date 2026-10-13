#!/usr/bin/env bash
# Installiert OWASP ZAP ohne Docker-Daemon, indem die ZAP-Distribution aus dem offiziellen
# Image zaproxy/zap-stable (Docker Hub) extrahiert wird. Nützlich in Umgebungen, in denen
# GitHub-Release-Downloads blockiert sind. Version und Digest werden fixiert und geprüft.
set -euo pipefail
TARGET="${ZAP_HOME_DIR:-/opt/zap}"
REPO="zaproxy/zap-stable"
TAG="${ZAP_TAG:-2.17.0}"
command -v java >/dev/null || { echo "Java 17+ wird benötigt"; exit 1; }
command -v python3 >/dev/null || { echo "python3 wird benötigt"; exit 1; }
TOKEN=$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO}:pull" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
H="Authorization: Bearer ${TOKEN}"
INDEX=$(curl -fsSL -H "$H" -H "Accept: application/vnd.oci.image.index.v1+json" "https://registry-1.docker.io/v2/${REPO}/manifests/${TAG}")
DIGEST=$(echo "$INDEX" | python3 -c 'import json,sys;m=json.load(sys.stdin);print([x["digest"] for x in m["manifests"] if x["platform"]["architecture"]=="amd64"][0])')
MANIFEST=$(curl -fsSL -H "$H" -H "Accept: application/vnd.oci.image.manifest.v1+json" "https://registry-1.docker.io/v2/${REPO}/manifests/${DIGEST}")
CONFIG=$(echo "$MANIFEST" | python3 -c 'import json,sys;print(json.load(sys.stdin)["config"]["digest"])')
# Layer mit «COPY /zap .» anhand der Build-Historie finden
LAYER=$(curl -fsSL -H "$H" "https://registry-1.docker.io/v2/${REPO}/blobs/${CONFIG}" | python3 -c '
import json,sys
cfg=json.load(sys.stdin); man=json.loads(sys.argv[1])
hist=[h for h in cfg["history"] if not h.get("empty_layer")]
for h,l in zip(hist, man["layers"]):
    if "COPY --chown=1000:1000 /zap ." in h.get("created_by",""): print(l["digest"]); break
' "$MANIFEST")
[ -n "$LAYER" ] || { echo "ZAP-Layer nicht gefunden"; exit 1; }
TMP=$(mktemp -d)
echo "Lade ${REPO}:${TAG} Layer ${LAYER} …"
curl -fsSL -H "$H" -o "$TMP/zap.tgz" "https://registry-1.docker.io/v2/${REPO}/blobs/${LAYER}"
echo "${LAYER#sha256:}  $TMP/zap.tgz" | sha256sum -c -
mkdir -p "$(dirname "$TARGET")"
tar -xzf "$TMP/zap.tgz" -C "$TMP"
rm -rf "$TMP/zap/webswing" "$TARGET"
mv "$TMP/zap" "$TARGET"
rm -rf "$TMP"
echo "ZAP installiert in $TARGET: $(ls "$TARGET" | grep -E '^zap-.*\.jar$')"
