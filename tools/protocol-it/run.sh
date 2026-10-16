#!/usr/bin/env bash
# Arranca/para los servidores Java reales (StorageService, RetrieveService y
# el servicio de firma trifasica/lotes) en un Tomcat 9 de Docker para las
# pruebas de integracion de afirma-protocol.
#
#   tools/protocol-it/run.sh start   # arranca y escribe la URL base
#   tools/protocol-it/run.sh url     # URL base (IP del contenedor, no localhost:
#                                    # AutoFirma rechaza los servicios locales)
#   tools/protocol-it/run.sh stop
#   tools/protocol-it/run.sh hmac    # reinicia el servicio trifasico con
#                                    # verification.key y lotes concurrentes
#                                    # (ejecutar las pruebas con AFIRMA_IT_HMAC=1)
#
# Pruebas:
#   AFIRMA_IT=1 AFIRMA_IT_BASE=$(tools/protocol-it/run.sh url) \
#     CARGO_TARGET_DIR=target/agents/afirma-protocol cargo test -p afirma-protocol --test java_servers -- --test-threads=1
#
# Variables: WARS_DIR (directorio con los modulos Java compilados),
# AFIRMA_IT_IMAGE (imagen, por defecto tomcat:9-jdk11), AFIRMA_IT_NAME.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="${AFIRMA_IT_NAME:-afirma-protocol-it}"
IMAGE="${AFIRMA_IT_IMAGE:-tomcat:9-jdk11}"
WARS_DIR="${WARS_DIR:-/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/java-src}"

war() { ls "$WARS_DIR/$1"/target/"$1"-*.war | head -1; }

url() {
  local ip
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")
  echo "http://$ip:8080"
}

case "${1:-}" in
  start)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker create --name "$NAME" -e CATALINA_OPTS="-Dclienteafirma.config.path=/config" "$IMAGE" >/dev/null
    docker cp "$(war afirma-signature-storage)" "$NAME:/usr/local/tomcat/webapps/afirma-signature-storage.war"
    docker cp "$(war afirma-signature-retriever)" "$NAME:/usr/local/tomcat/webapps/afirma-signature-retriever.war"
    docker cp "$(war afirma-server-triphase-signer)" "$NAME:/usr/local/tomcat/webapps/afirma-server-triphase-signer.war"
    docker cp "$HERE/config/." "$NAME:/config"
    docker start "$NAME" >/dev/null
    base=$(url)
    for _ in $(seq 1 120); do
      if curl -fs "$base/afirma-signature-storage/StorageService?op=check" >/dev/null 2>&1 &&
         curl -fs "$base/afirma-signature-retriever/RetrieveService?op=check" >/dev/null 2>&1 &&
         curl -s -o /dev/null -w '%{http_code}' -X POST -d 'op=x' "$base/afirma-server-triphase-signer/SignatureService" | grep -q 200; then
        echo "$base"
        exit 0
      fi
      sleep 1
    done
    echo "Los servidores no han arrancado; registro:" >&2
    docker logs "$NAME" 2>&1 | tail -50 >&2
    exit 1
    ;;
  url) url ;;
  stop) docker rm -f "$NAME" >/dev/null 2>&1 || true ;;
  hmac)
    # Reinicia el servicio trifasico con verificacion HMAC (tps_config_hmac).
    docker cp "$HERE/config/tps_config_hmac.properties" "$NAME:/config/tps_config.properties"
    docker restart "$NAME" >/dev/null
    "$0" wait ;;
  wait)
    base=$(url)
    for _ in $(seq 1 120); do
      curl -fs "$base/afirma-signature-storage/StorageService?op=check" >/dev/null 2>&1 && \
        curl -s -o /dev/null -w '%{http_code}' -X POST -d 'op=x' "$base/afirma-server-triphase-signer/SignatureService" | grep -q 200 && { echo "$base"; exit 0; }
      sleep 1
    done
    exit 1 ;;
  logs) docker logs "$NAME" ;;
  *) echo "uso: $0 start|url|stop|logs|hmac|wait" >&2; exit 2 ;;
esac
