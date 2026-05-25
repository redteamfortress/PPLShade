/*
 *  PPLShade - common.h
 *  Shared types and definitions.
 */

#pragma once

#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// ====================== ANSI Color Codes ======================
#define C_RST   "\x1b[0m"
#define C_RED   "\x1b[38;5;196m"
#define C_GRN   "\x1b[38;5;46m"
#define C_YLW   "\x1b[38;5;214m"
#define C_CYN   "\x1b[38;5;51m"
#define C_GRY   "\x1b[38;5;245m"
#define C_MAG   "\x1b[38;5;201m"
#define C_BLD   "\x1b[1m"
#define C_DIM   "\x1b[2m"

// ====================== Logging ======================
#define okay(msg, ...)  printf(C_GRN " [*] " C_RST msg "\n", ##__VA_ARGS__)
#define info(msg, ...)  printf(C_CYN " [>] " C_RST msg "\n", ##__VA_ARGS__)
#define warn(msg, ...)  printf(C_YLW " [~] " C_RST msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf(C_RED " [!] " C_RST msg "\n", ##__VA_ARGS__)

#define okayW(msg, ...)  wprintf(C_GRN L" [*] " C_RST msg L"\n", ##__VA_ARGS__)
#define infoW(msg, ...)  wprintf(C_CYN L" [>] " C_RST msg L"\n", ##__VA_ARGS__)
#define warnW(msg, ...)  wprintf(C_YLW L" [~] " C_RST msg L"\n", ##__VA_ARGS__)
#define errorW(msg, ...) wprintf(C_RED L" [!] " C_RST msg L"\n", ##__VA_ARGS__)

#define infoW_t(msg, ...) wprintf(L"     " msg L"\n", ##__VA_ARGS__)
#define info_t(msg, ...)  printf("     " msg "\n", ##__VA_ARGS__)

// ====================== NT Macros ======================
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif
#define NtCurrentProcess() ((HANDLE)-1)

// ====================== Protection Level Enums ======================
typedef enum _PLVL {
    PLvlNone  = 0,
    PLvlLight = 1,
    PLvlFull  = 2
} PLVL;

typedef enum _PSIG {
    PSigNone          = 0,
    PSigAuthenticode  = 1,
    PSigCodeGen       = 2,
    PSigAntimalware   = 3,
    PSigLsa           = 4,
    PSigWindows       = 5,
    PSigWinTcb        = 6,
    PSigWinSystem     = 7,
    PSigApp           = 8,
    PSigMax           = 9
} PSIG;

// ====================== Process Info ======================
typedef struct _PROC_SHIELD_ENTRY {
    DWORD64 KernelAddress;
    DWORD   Pid;
    UCHAR   ProtectionLevel;
    UCHAR   SignerType;
    UCHAR   SignatureLevel;
    UCHAR   SectionSignatureLevel;
    WCHAR   ProcessName[64];
} PROC_SHIELD_ENTRY, *PPROC_SHIELD_ENTRY;

typedef struct _PROC_SHIELD_LIST {
    DWORD          NumberOfEntries;
    PROC_SHIELD_ENTRY  Entries[1];
} PROC_SHIELD_LIST, *PPROC_SHIELD_LIST;

// ====================== Kernel Field Indices ======================
typedef enum _KSTRUCT_FIELD {
    KF_SYSTEM_INITIAL_PROC = 0,
    KF_UNIQUE_PID,
    KF_ACTIVE_LINKS,
    KF_PROTECTION,
    KF_SIG_LEVEL,
    KF_SEC_SIG_LEVEL,
    KF_IMAGE_FILE_NAME,
    KF_MAX
} KSTRUCT_FIELD;

