/*
 *  PPLShade - kstruct_resolve.h
 *  Dynamic kernel structure field resolution.
 */

#pragma once
#include "common.h"

BOOL ResolveKernelStructs(DWORD offsets[KF_MAX]);
DWORD64 QueryNtBase(void);
