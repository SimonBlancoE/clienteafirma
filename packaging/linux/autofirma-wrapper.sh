#!/bin/sh
# /usr/bin/autofirma: el ejecutable real vive en /usr/lib/autofirma-rs, junto a los
# certificados locales que genera `autofirma install --system`.
exec /usr/lib/autofirma-rs/autofirma "$@"
