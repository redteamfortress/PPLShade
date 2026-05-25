/*
 *  PPLShade - memory.h
 *  Kernel memory access primitives (multi-driver).
 */

#pragma once
#include "common.h"

// ====================== Supported Drivers ======================
typedef enum _DRIVER_ID {
    DRV_LECOMA64  = 0,
    DRV_IPCTYPE   = 1,
    DRV_MTXVXD    = 2,
    DRV_COUNT     = 3,
    DRV_INVALID   = -1
} DRIVER_ID;

// Initialize the selected driver backend
BOOL MemoryInit(DRIVER_ID drvId);

// Get currently active driver
DRIVER_ID MemoryGetDriver(void);

// Open the device handle for the active driver
HANDLE MemoryOpenDevice(void);

// Auto-detect: try all drivers, return handle to first one found
// Sets g_ActiveDriver internally on success
HANDLE MemoryAutoDetect(void);

// Get the display name of a driver
const char* MemoryDriverName(DRIVER_ID id);

// Parse a driver name string to DRIVER_ID
DRIVER_ID MemoryParseDriver(const char* name);

// ====================== Read/Write Primitives ======================
BYTE    KRead8(IN HANDLE hDevice, IN DWORD64 Address);
WORD    KRead16(IN HANDLE hDevice, IN DWORD64 Address);
DWORD   KRead32(IN HANDLE hDevice, IN DWORD64 Address);
DWORD64 KRead64(IN HANDLE hDevice, IN DWORD64 Address);

BOOL KWrite8(IN HANDLE hDevice, IN DWORD64 Address, IN BYTE Value);
BOOL KWrite16(IN HANDLE hDevice, IN DWORD64 Address, IN WORD Value);
BOOL KWrite32(IN HANDLE hDevice, IN DWORD64 Address, IN DWORD Value);
BOOL KWrite64(IN HANDLE hDevice, IN DWORD64 Address, IN DWORD64 Value);

// From memory_translation
extern DWORD64 VirtualToPhysical(IN DWORD64 VirtualAddress);
