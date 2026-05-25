/*
 *  PPLShade - pe_parse.c
 *  Manual PE loading + export resolution.
 *  Reads ntoskrnl.exe via CreateFile/ReadFile into a heap buffer,
 *  maps sections at their VirtualAddress offsets, and walks the
 *  export directory to resolve exports by name.
 *
 *  This replaces LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES) + GetProcAddress
 *  which S1 detects when combined with a BYOVD driver handle.
 */

#include "pe_parse.h"

HMANUAL_PE ManualPeLoad(const char* filePath) {
    HMANUAL_PE hPe = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPVOID pRaw = NULL;

    // Open the file
    hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    // Read entire file into raw buffer
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_DOS_HEADER)) goto fail;

    pRaw = HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!pRaw) goto fail;

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, pRaw, fileSize, &bytesRead, NULL) || bytesRead != fileSize) goto fail;
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    // Validate DOS header
    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pRaw;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) goto fail;
    if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) goto fail;

    // Validate NT headers
    IMAGE_NT_HEADERS64* pNt = (IMAGE_NT_HEADERS64*)((BYTE*)pRaw + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) goto fail;
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) goto fail;

    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    if (!imageSize) goto fail;

    // Allocate image buffer at SizeOfImage
    LPVOID pImage = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, imageSize);
    if (!pImage) goto fail;

    // Copy headers
    DWORD headerSize = pNt->OptionalHeader.SizeOfHeaders;
    if (headerSize > fileSize) headerSize = fileSize;
    memcpy(pImage, pRaw, headerSize);

    // Map sections to their virtual offsets
    IMAGE_SECTION_HEADER* pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (pSec[i].PointerToRawData + pSec[i].SizeOfRawData > fileSize) continue;
        if (pSec[i].VirtualAddress + pSec[i].SizeOfRawData > imageSize) continue;

        memcpy(
            (BYTE*)pImage + pSec[i].VirtualAddress,
            (BYTE*)pRaw + pSec[i].PointerToRawData,
            pSec[i].SizeOfRawData
        );
    }

    // Done with raw file buffer
    HeapFree(GetProcessHeap(), 0, pRaw);
    pRaw = NULL;

    // Allocate and fill the handle
    hPe = (HMANUAL_PE)HeapAlloc(GetProcessHeap(), 0, sizeof(MANUAL_PE));
    if (!hPe) { HeapFree(GetProcessHeap(), 0, pImage); return NULL; }
    hPe->Base = pImage;
    hPe->ImageSize = imageSize;
    return hPe;

fail:
    if (pRaw) HeapFree(GetProcessHeap(), 0, pRaw);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return NULL;
}

FARPROC ManualPeGetExport(HMANUAL_PE hPe, const char* exportName) {
    if (!hPe || !hPe->Base || !exportName) return NULL;

    BYTE* pBase = (BYTE*)hPe->Base;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
    IMAGE_NT_HEADERS64* pNt = (IMAGE_NT_HEADERS64*)(pBase + pDos->e_lfanew);

    // Get export directory
    IMAGE_DATA_DIRECTORY* pExpDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!pExpDir->VirtualAddress || !pExpDir->Size) return NULL;
    if (pExpDir->VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > hPe->ImageSize) return NULL;

    IMAGE_EXPORT_DIRECTORY* pExp = (IMAGE_EXPORT_DIRECTORY*)(pBase + pExpDir->VirtualAddress);

    DWORD* pNames    = (DWORD*)(pBase + pExp->AddressOfNames);
    WORD*  pOrdinals = (WORD*)(pBase + pExp->AddressOfNameOrdinals);
    DWORD* pFuncs    = (DWORD*)(pBase + pExp->AddressOfFunctions);

    // Linear search through name table
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        if (pNames[i] >= hPe->ImageSize) continue;
        const char* name = (const char*)(pBase + pNames[i]);

        if (strcmp(name, exportName) == 0) {
            WORD ordinal = pOrdinals[i];
            if (ordinal >= pExp->NumberOfFunctions) return NULL;

            DWORD funcRva = pFuncs[ordinal];
            if (!funcRva || funcRva >= hPe->ImageSize) return NULL;

            // Check for forwarded export (RVA points inside export directory)
            if (funcRva >= pExpDir->VirtualAddress &&
                funcRva < pExpDir->VirtualAddress + pExpDir->Size) {
                // Forwarded — not supported, return NULL
                return NULL;
            }

            return (FARPROC)(pBase + funcRva);
        }
    }

    return NULL;
}

void ManualPeFree(HMANUAL_PE hPe) {
    if (!hPe) return;
    if (hPe->Base) HeapFree(GetProcessHeap(), 0, hPe->Base);
    HeapFree(GetProcessHeap(), 0, hPe);
}
