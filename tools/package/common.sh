# shellcheck shell=bash
# Funciones comunes de los scripts de empaquetado (se cargan con `source`).

# Raíz del repositorio.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '==> %s\n' "$*" >&2
}

warn() {
    printf 'AVISO: %s\n' "$*" >&2
}

# Versión del espacio de trabajo ([workspace.package] version del Cargo.toml raíz).
workspace_version() {
    sed -n '/^\[workspace\.package\]/,/^\[/{s/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p}' "$ROOT/Cargo.toml" | head -n 1
}

# Versión para Debian/RPM/AppStream: el guion de una versión previa se convierte en «~»
# para que 2.0.0~alpha.1 < 2.0.0 (2.0.0-alpha.1 → 2.0.0~alpha.1).
pkg_version() {
    printf '%s' "${1//-/\~}"
}

# Versión numérica de tres componentes (2.0.0-alpha.1 → 2.0.0) para MSI y macOS.
numeric_version() {
    printf '%s' "${1%%[-+]*}"
}

# `true` si la versión $1 <= $2 (componentes numéricos separados por puntos).
version_le() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" = "$1" ]
}

# SHA-256 de un fichero (Linux y macOS).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Descarga un fichero y comprueba su SHA-256.
fetch_verified() {
    local url="$1" dest="$2" sha="$3"
    if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$sha" ]; then
        return 0
    fi
    mkdir -p "$(dirname "$dest")"
    info "Descargando $url"
    curl -fsSL --retry 3 -o "$dest.part" "$url" || die "no se pudo descargar $url"
    local got
    got="$(sha256_of "$dest.part")"
    if [ "$got" != "$sha" ]; then
        rm -f "$dest.part"
        die "SHA-256 inesperado para $url: $got (se esperaba $sha)"
    fi
    mv "$dest.part" "$dest"
}

# Directorio de caché para herramientas descargadas.
tools_cache_dir() {
    printf '%s' "${AUTOFIRMA_TOOLS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/autofirma-rs-packaging}"
}

# Ejecutables que se empaquetan: siempre autofirma y, si existe, autofirma-cli.
packaged_binaries() {
    local dir="$1"
    printf '%s\n' autofirma
    if [ -f "$dir/autofirma-cli" ] || [ -f "$dir/autofirma-cli.exe" ]; then
        printf '%s\n' autofirma-cli
    fi
}
