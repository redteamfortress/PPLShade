/*
 *  PPLShade - prot_fmt.c
 *  
 */

#include "prot_fmt.h"

// ─── Protection byte layout: [Signer:4][Type:3][Audit:1] ───

UCHAR ExtractPLevel(UCHAR Protection) {
    return Protection & 0x07;
}

UCHAR ExtractSType(UCHAR Protection) {
    return (Protection & 0xF0) >> 4;
}

UCHAR EncodeProt(UCHAR ProtectionLevel, UCHAR SignerType) {
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

// ─── Protection Level strings ───

LPCWSTR PLevelStr(UCHAR Level) {
    switch (Level) {
        case PLvlNone:           return L"None";
        case PLvlLight: return L"PPL";
        case PLvlFull:      return L"PP";
        default:                            return L"Unknown";
    }
}

// ─── Signer Type strings ───

LPCWSTR STypeStr(UCHAR Signer) {
    switch (Signer) {
        case PSigNone:          return L"None";
        case PSigAuthenticode:  return L"Authenticode";
        case PSigCodeGen:       return L"CodeGen";
        case PSigAntimalware:   return L"Antimalware";
        case PSigLsa:           return L"Lsa";
        case PSigWindows:       return L"Windows";
        case PSigWinTcb:        return L"WinTcb";
        case PSigWinSystem:     return L"WinSystem";
        case PSigApp:           return L"App";
        default:                             return L"Unknown";
    }
}

// ─── Signature Level strings ───

LPCWSTR SigLevelStr(UCHAR SigLevel) {
    UCHAR level = SigLevel & 0x0F;
    switch (level) {
        case 0x00: return L"Unchecked";
        case 0x01: return L"Unsigned";
        case 0x02: return L"Enterprise";
        case 0x03: return L"Developer";
        case 0x04: return L"Authenticode";
        case 0x05: return L"Custom2";
        case 0x06: return L"Store";
        case 0x07: return L"Antimalware";
        case 0x08: return L"Microsoft";
        case 0x09: return L"Custom4";
        case 0x0A: return L"Custom5";
        case 0x0B: return L"DynamicCodegen";
        case 0x0C: return L"Windows";
        case 0x0D: return L"Custom7";
        case 0x0E: return L"WindowsTcb";
        case 0x0F: return L"Custom6";
        default:   return L"Unknown";
    }
}

// ─── String -> Enum parsers ───

UCHAR ParsePLevel(LPCWSTR str) {
    if (!str) return 0;
    if (!_wcsicmp(str, L"PP"))  return PLvlFull;
    if (!_wcsicmp(str, L"PPL")) return PLvlLight;
    errorW(L"Unknown protection level: \"%s\"", str);
    return 0;
}

UCHAR ParseSType(LPCWSTR str) {
    if (!str) return 0;
    if (!_wcsicmp(str, L"Authenticode")) return PSigAuthenticode;
    if (!_wcsicmp(str, L"CodeGen"))      return PSigCodeGen;
    if (!_wcsicmp(str, L"Antimalware"))  return PSigAntimalware;
    if (!_wcsicmp(str, L"Lsa"))          return PSigLsa;
    if (!_wcsicmp(str, L"Windows"))      return PSigWindows;
    if (!_wcsicmp(str, L"WinTcb"))       return PSigWinTcb;
    if (!_wcsicmp(str, L"WinSystem"))    return PSigWinSystem;
    if (!_wcsicmp(str, L"App"))          return PSigApp;
    errorW(L"Unknown signer type: \"%s\"", str);
    return 0;
}

// ─── Infer correct SE_SIGNING_LEVEL from Signer Type ───
// Based on Alex Ionescu's research: https://www.alex-ionescu.com/?p=146

UCHAR DeriveSigLevel(UCHAR SignerType) {
    switch (SignerType) {
        case PSigNone:          return 0x00; // Unchecked
        case PSigAuthenticode:  return 0x04; // Authenticode
        case PSigCodeGen:       return 0x0B; // DynamicCodegen
        case PSigAntimalware:   return 0x07; // Antimalware
        case PSigLsa:           return 0x0C; // Windows
        case PSigWindows:       return 0x0C; // Windows
        case PSigWinTcb:        return 0x0E; // WindowsTcb
        default:
            error("Cannot infer EXE sig for type %d", SignerType);
            return 0xFF;
    }
}

UCHAR DeriveSectionSigLevel(UCHAR SignerType) {
    switch (SignerType) {
        case PSigNone:          return 0x00; // Unchecked
        case PSigAuthenticode:  return 0x04; // Authenticode
        case PSigCodeGen:       return 0x06; // Store
        case PSigAntimalware:   return 0x07; // Antimalware
        case PSigLsa:           return 0x08; // Microsoft
        case PSigWindows:       return 0x0C; // Windows
        case PSigWinTcb:        return 0x0C; // Windows (not WindowsTcb for sections)
        default:
            error("Cannot infer DLL sig for type %d", SignerType);
            return 0xFF;
    }
}
