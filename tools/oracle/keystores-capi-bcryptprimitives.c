/*
 * Sustituto mínimo de bcryptprimitives.dll para ejecutar en Wine 8 los
 * binarios de prueba de Rust para Windows (la biblioteca estándar de Rust
 * importa ProcessPrng, que Wine 8 no implementa). Solo para pruebas.
 *
 *   x86_64-w64-mingw32-gcc -shared -o bcryptprimitives.dll \
 *       keystores-capi-bcryptprimitives.c -ladvapi32
 */
#include <windows.h>

BOOLEAN WINAPI SystemFunction036(PVOID buffer, ULONG length); /* RtlGenRandom */

__declspec(dllexport) BOOL WINAPI ProcessPrng(PBYTE data, SIZE_T len)
{
    while (len > 0) {
        ULONG chunk = len > 0x10000000 ? 0x10000000 : (ULONG)len;
        if (!SystemFunction036(data, chunk)) {
            return FALSE;
        }
        data += chunk;
        len -= chunk;
    }
    return TRUE;
}
