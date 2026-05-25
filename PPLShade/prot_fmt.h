/*
 *  PPLShade - prot_fmt.h
 *  Protection level and signer type string conversion utilities
 *  
 */

#pragma once
#include "common.h"

// ─── Protection byte field manipulation ───
UCHAR ExtractPLevel(UCHAR Protection);
UCHAR ExtractSType(UCHAR Protection);
UCHAR EncodeProt(UCHAR ProtectionLevel, UCHAR SignerType);

// ─── String conversions ───
LPCWSTR PLevelStr(UCHAR Level);
LPCWSTR STypeStr(UCHAR Signer);
LPCWSTR SigLevelStr(UCHAR SigLevel);

UCHAR ParsePLevel(LPCWSTR str);
UCHAR ParseSType(LPCWSTR str);

// ─── Signature level inference from signer type ───
UCHAR DeriveSigLevel(UCHAR SignerType);
UCHAR DeriveSectionSigLevel(UCHAR SignerType);
