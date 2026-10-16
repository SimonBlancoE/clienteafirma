# %postun de autofirma-rs: retira los certificados generados que rpm no conoce.
if [ "$1" -eq 0 ]; then
    for f in autofirma.pfx Autofirma_ROOT.cer autofirma.cer; do
        rm -f "/usr/lib/autofirma-rs/$f"
    done
    rmdir /usr/lib/autofirma-rs 2>/dev/null || :
fi
