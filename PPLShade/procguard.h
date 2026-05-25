/*
 *  PPLShade - procguard.h
 *  Process protection manipulation via kernel memory read/write
 */

#pragma once
#include "common.h"

// List all protected processes on the system
BOOL EnumShieldedProcs(HANDLE hDevice, DWORD offsets[KF_MAX]);

// Query protection status of a specific process
BOOL QueryProcShield(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid);

// Set protection level + signer on a process
BOOL WriteProcShield(HANDLE hDevice, DWORD offsets[KF_MAX],
                          DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType);

// Full protect: set protection + appropriate signature levels
BOOL ApplyProcShield(HANDLE hDevice, DWORD offsets[KF_MAX],
                    DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType);

// Full unprotect: zero protection + signature levels
BOOL StripProcShield(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid);
BOOL KillProc(HANDLE hDevice, DWORD offsets[KF_MAX], DWORD Pid);
