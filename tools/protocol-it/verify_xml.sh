#!/usr/bin/env bash
# Valida firmas XML (XMLDSig/XAdES) con Apache Santuario mediante
# tools/oracle/XmlSigVerify.java. Uso: verify_xml.sh firma.xml [...]
# XADES_RUN: directorio con lib/*.jar y classes de afirma-crypto-core-xml.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
XADES_RUN="${XADES_RUN:-/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/xades-run}"
OUT="${TMPDIR:-/tmp}/afirma-protocol-xmlverify"
CP="$(ls "$XADES_RUN"/lib/*.jar | tr '\n' :)$XADES_RUN/classes"
if [ ! -f "$OUT/XmlSigVerify.class" ]; then
  mkdir -p "$OUT"
  javac -cp "$CP" -d "$OUT" "$ROOT/tools/oracle/XmlSigVerify.java"
fi
exec java -cp "$CP:$OUT" XmlSigVerify "$@"
