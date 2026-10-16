/* Sustituto de bcryptprimitives.dll (ProcessPrng) para Wine 8, que no la incluye. Solo para pruebas. */
#include <windows.h>
BOOLEAN WINAPI SystemFunction036(PVOID buf, ULONG len);
__declspec(dllexport) BOOL WINAPI ProcessPrng(PBYTE data, SIZE_T len) {
    while (len) {
        ULONG n = len > 0x40000000 ? 0x40000000 : (ULONG)len;
        if (!SystemFunction036(data, n)) return FALSE;
        data += n; len -= n;
    }
    return TRUE;
}
