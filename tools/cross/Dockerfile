# Imagen de compilación cruzada para AutoFirma-rs.
# Permite compilar (y en Windows, ejecutar bajo Wine) los binarios de Windows y
# comprobar que el código de macOS compila, desde un host Linux.
FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        mingw-w64 wine64 xz-utils curl ca-certificates pkg-config \
        libssl-dev clang llvm lld \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-pc-windows-gnu x86_64-apple-darwin aarch64-apple-darwin \
    && rustup component add clippy rustfmt

# Zig como enlazador/compilador C cruzado para macOS (cargo-zigbuild).
ARG ZIG_VERSION=0.13.0
RUN curl -sSL https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz \
        | tar -xJ -C /opt \
    && ln -s /opt/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig \
    && cargo install --locked cargo-zigbuild

ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine64
WORKDIR /src
