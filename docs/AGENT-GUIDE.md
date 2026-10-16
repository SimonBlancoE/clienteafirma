# Guía de trabajo para implementar módulos de AutoFirma-rs

(Documento interno para quien implemente un crate, persona o agente.)

## Entorno

- Repositorio: `/home/octo/Projects/autofirma` (fork de clienteafirma). El código Java
  original está en los directorios `afirma-*`: **solo lectura**, es la referencia.
- Lee primero `docs/ARCHITECTURE.md` y las especificaciones de `docs/spec/` que te
  correspondan. Ante dudas, la fuente de verdad es el código Java.
- Interfaces compartidas (no las cambies sin necesidad; si hace falta, documéntalo en
  tu informe final): `afirma_core::{Signer, SigningKey, ExtraParams, AfirmaError,
  error::codes, SignersTree, SimpleSignInfo, validity::SignValidity, algorithms::*,
  cert::*}`.
- PKI de pruebas: `testdata/pki` (contraseña de los .p12: `12341234`; alias = nombre
  del fichero sin extensión). `testdata/pki/gen.sh` la regenera.
- Oráculo Java ya compilado: `AFIRMA_JAR=/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/java-src/afirma-simple/target/autofirma.jar`
  con `tools/oracle/afj.sh` (CLI: `sign|cosign|countersign|listaliases|batchsign`,
  `-config` para extraParams). Puedes escribir pequeños programas Java en
  `tools/oracle/` que usen las clases de ese JAR (classpath) para validar o inspeccionar
  firmas. Jars de los módulos sueltos en `/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/java-src/*/target/` y dependencias en
  `/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/m2`.
- Validadores externos: `openssl`, `pdfsig`, y un entorno Python con `lxml`, `pyhanko`,
  `signxml`, `asn1crypto`, `cryptography` en `/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/venv` (usa `/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/venv/bin/python -I`).
- Imagen Docker `autofirma-cross:latest` (Rust + mingw + wine64 + zig/cargo-zigbuild +
  objetivos `x86_64-pc-windows-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`) para
  comprobar que compila en Windows/macOS:
  `docker run --rm -v /home/octo/Projects/autofirma:/src -v $HOME/.cargo/registry:/usr/local/cargo/registry -e CARGO_TARGET_DIR=/src/target/cross autofirma-cross cargo check -p <crate> --target x86_64-pc-windows-gnu`
  (para macOS: `cargo zigbuild`/`cargo check --target aarch64-apple-darwin`).

## Reglas

1. Modifica **solo** tu(s) crate(s) asignado(s) y, si lo necesitas, ficheros nuevos en
   `testdata/<tu-área>/` y `tools/oracle/`. No toques otros crates ni el `Cargo.toml` raíz:
   añade dependencias en el `Cargo.toml` de tu crate (usa `workspace = true` si ya están
   declaradas en la raíz; si no, con versión explícita).
2. Usa SIEMPRE un directorio de compilación propio para no bloquear a otros:
   `CARGO_TARGET_DIR=/home/octo/Projects/autofirma/target/agents/<tu-crate> cargo test -p <tu-crate>`.
3. No hagas `git commit`, `git push` ni cambies la configuración de git: el integrador
   revisa y confirma los cambios.
4. Estilo: Rust edición 2024, comentarios y documentación en español (como el código
   existente), mensajes al usuario en español. Sin `unsafe` salvo en FFI con el sistema
   (y documentado). Sin `unwrap()` en caminos que dependan de datos externos.
5. **Paridad**: reproduce exactamente formatos de salida, nombres y valores por defecto de
   parámetros, códigos de error y comportamiento observable de la versión Java. Si el
   original tiene un **fallo claro** que hace que una función no funcione (p. ej. un
   parámetro que se ignora por error), implementa el comportamiento correcto **solo si no
   rompe la interoperabilidad** y anótalo en `docs/deviations/<tu-crate>.md` (qué hace
   Java, qué hacemos y por qué).
6. Pruebas: unitarias en el crate y, cuando aplique, pruebas diferenciales contra el
   oráculo Java o validadores externos. Guarda las salidas de referencia como ficheros
   *golden* en `testdata/<tu-área>/` para que `cargo test` funcione sin Java.
7. Al terminar: `cargo test`, `cargo clippy` sin avisos relevantes y un informe breve de lo
   hecho, lo pendiente y cualquier cambio que necesites en crates ajenos.
