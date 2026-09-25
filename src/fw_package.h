#pragma once
#include <windows.h>
#include <stddef.h>

typedef struct {
    BOOL packageHashOk;
    BOOL upgHashOk;
    BOOL upgHeaderOk;
    DWORD packageSize;
    DWORD upgSize;
    WCHAR extractedPath[MAX_PATH];
    WCHAR packageSha256[65];
    WCHAR upgSha256[65];
} FirmwarePackageResult;

BOOL VerifyAndExtractSonyFirmwarePackage(
    const WCHAR *packagePath,
    const WCHAR *baseOutputDir,
    FirmwarePackageResult *result,
    WCHAR *errorText,
    size_t errorCch);
