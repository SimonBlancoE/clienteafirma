# %preun de autofirma-rs ($1 = 0 desinstalación, 1 actualización): deshace la integración
# solo al desinstalar.
if [ "$1" -eq 0 ]; then
    /usr/lib/autofirma-rs/configure-hook.sh uninstall /usr/lib/autofirma-rs/autofirma
    # Ficheros generados que rpm no conoce (para que pueda borrar el directorio).
    for f in autofirma.pfx Autofirma_ROOT.cer autofirma.cer; do
        rm -f "/usr/lib/autofirma-rs/$f"
    done
fi
