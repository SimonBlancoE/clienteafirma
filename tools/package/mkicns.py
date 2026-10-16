#!/usr/bin/env python3
"""Genera un fichero .icns a partir de los PNG de packaging/icons sin herramientas de Apple.

En macOS, tools/package/macos.sh usa `iconutil`; este script es la alternativa para
montar y revisar el paquete .app desde Linux. Los iconos se guardan como PNG en los
tipos que macOS admite desde 10.7 (icp4..ic14).

Uso: mkicns.py <directorio con autofirma-<n>.png> <salida.icns>
"""

import struct
import sys
from pathlib import Path

# Tipo OSType -> tamaño en píxeles del PNG de origen.
TYPES = [
    ("icp4", 16),
    ("icp5", 32),
    ("icp6", 64),
    ("ic07", 128),
    ("ic08", 256),
    ("ic09", 512),
    ("ic10", 1024),  # 512x512@2x
    ("ic11", 32),  # 16x16@2x
    ("ic12", 64),  # 32x32@2x
    ("ic13", 256),  # 128x128@2x
    ("ic14", 512),  # 256x256@2x
]

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def png_size(data: bytes) -> tuple[int, int]:
    if not data.startswith(PNG_MAGIC) or data[12:16] != b"IHDR":
        raise ValueError("no es un PNG válido")
    return struct.unpack(">II", data[16:24])


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    chunks = []
    for ostype, px in TYPES:
        data = (src / f"autofirma-{px}.png").read_bytes()
        if png_size(data) != (px, px):
            raise SystemExit(f"autofirma-{px}.png no mide {px}x{px}")
        chunks.append(ostype.encode("ascii") + struct.pack(">I", len(data) + 8) + data)
    body = b"".join(chunks)
    out.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
