/*
 *  PPLShade - pe_parse.h
 *  Manual PE loading + export resolution via ReadFile.
 *  Replaces LoadLibraryEx + GetProcAddress to avoid S1 detection.
 */

#pragma once
#include "common.h"

typedef struct _MANUAL_PE {
    LPVOID  Base;       // heap buffer with sections mapped at virtual offsets
    DWORD   ImageSize;  // SizeOfImage
} MANUAL_PE, *HMANUAL_PE;

// Load PE from disk into heap with sections at correct virtual offsets
HMANUAL_PE ManualPeLoad(const char* filePath);

// Walk export directory to resolve an export by name (like GetProcAddress)
FARPROC ManualPeGetExport(HMANUAL_PE hPe, const char* exportName);

// Free the mapped image
void ManualPeFree(HMANUAL_PE hPe);
