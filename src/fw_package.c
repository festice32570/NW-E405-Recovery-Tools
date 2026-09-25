#include "fw_package.h"
#include <windows.h>
#include <wincrypt.h>
#include <wchar.h>
#include <stdint.h>
#include <string.h>
#include "../third_party/miniz/miniz.h"

#define EXPECTED_PACKAGE_SIZE 2291724u
#define EXPECTED_UPG_SIZE 2131380u
static const WCHAR EXPECTED_PACKAGE_SHA256[] = L"8b68cf41d193464439e8139aa593ebcf887d2dd0a2220a6135039b3ebf7a7eb7";
static const WCHAR EXPECTED_UPG_SHA256[] = L"82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691";
static const char UPG_ENTRY[] = "NW-E40X_V2_0J/MSFWUPGR_NW-E40X_201J.UPG";

static void SetError(WCHAR *out, size_t cch, const WCHAR *msg) {
    if (!out || !cch) return;
    lstrcpynW(out, msg ? msg : L"Unknown error", (int)cch);
}

static BOOL ReadWholeFile(const WCHAR *path, BYTE **dataOut, DWORD *sizeOut) {
    *dataOut = NULL; *sizeOut = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(h); return FALSE;
    }
    DWORD n = (DWORD)li.QuadPart;
    BYTE *p = (BYTE*)HeapAlloc(GetProcessHeap(), 0, n);
    if (!p) { CloseHandle(h); return FALSE; }
    DWORD total = 0;
    while (total < n) {
        DWORD got = 0;
        if (!ReadFile(h, p + total, n - total, &got, NULL) || !got) {
            HeapFree(GetProcessHeap(), 0, p); CloseHandle(h); return FALSE;
        }
        total += got;
    }
    CloseHandle(h);
    *dataOut = p; *sizeOut = n;
    return TRUE;
}

static BOOL Sha256Buffer(const BYTE *data, DWORD len, BYTE out[32]) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BOOL ok = FALSE;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return FALSE;
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash) &&
        CryptHashData(hash, data, len, 0)) {
        DWORD cb = 32;
        if (CryptGetHashParam(hash, HP_HASHVAL, out, &cb, 0) && cb == 32)
            ok = TRUE;
    }
    if (hash) CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return ok;
}

static void HashToHex(const BYTE hash[32], WCHAR out[65]) {
    static const WCHAR h[] = L"0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i*2] = h[(hash[i] >> 4) & 0xF];
        out[i*2+1] = h[hash[i] & 0xF];
    }
    out[64] = 0;
}

static BOOL WriteWholeFile(const WCHAR *path, const BYTE *data, DWORD len) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD total = 0;
    BOOL ok = TRUE;
    while (total < len) {
        DWORD wrote = 0;
        if (!WriteFile(h, data + total, len - total, &wrote, NULL) || !wrote) {
            ok = FALSE; break;
        }
        total += wrote;
    }
    if (ok) ok = FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) DeleteFileW(path);
    return ok;
}

BOOL VerifyAndExtractSonyFirmwarePackage(
    const WCHAR *packagePath,
    const WCHAR *baseOutputDir,
    FirmwarePackageResult *result,
    WCHAR *errorText,
    size_t errorCch) {

    if (result) ZeroMemory(result, sizeof(*result));
    if (!packagePath || !baseOutputDir || !result) {
        SetError(errorText, errorCch, L"Invalid arguments"); return FALSE;
    }

    BYTE *package = NULL;
    DWORD packageSize = 0;
    if (!ReadWholeFile(packagePath, &package, &packageSize)) {
        SetError(errorText, errorCch, L"Could not read the selected Sony updater file.");
        return FALSE;
    }
    result->packageSize = packageSize;

    BYTE hash[32];
    if (!Sha256Buffer(package, packageSize, hash)) {
        HeapFree(GetProcessHeap(), 0, package);
        SetError(errorText, errorCch, L"SHA-256 calculation failed."); return FALSE;
    }
    HashToHex(hash, result->packageSha256);
    result->packageHashOk = (packageSize == EXPECTED_PACKAGE_SIZE &&
        _wcsicmp(result->packageSha256, EXPECTED_PACKAGE_SHA256) == 0);
    if (!result->packageHashOk) {
        HeapFree(GetProcessHeap(), 0, package);
        SetError(errorText, errorCch, L"This is not the verified Japanese NW-E405/E407 v2.0 Sony updater.");
        return FALSE;
    }

    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, package, packageSize, 0)) {
        HeapFree(GetProcessHeap(), 0, package);
        SetError(errorText, errorCch, L"The verified updater could not be opened as a ZIP archive.");
        return FALSE;
    }

    int idx = mz_zip_reader_locate_file(&zip, UPG_ENTRY, NULL, 0);
    if (idx < 0) {
        mz_zip_reader_end(&zip); HeapFree(GetProcessHeap(), 0, package);
        SetError(errorText, errorCch, L"MSFWUPGR_NW-E40X_201J.UPG was not found in the Sony package.");
        return FALSE;
    }

    size_t upgSizeZ = 0;
    BYTE *upg = (BYTE*)mz_zip_reader_extract_to_heap(&zip, idx, &upgSizeZ, 0);
    mz_zip_reader_end(&zip);
    HeapFree(GetProcessHeap(), 0, package);
    if (!upg || upgSizeZ > 0xFFFFFFFFu) {
        if (upg) mz_free(upg);
        SetError(errorText, errorCch, L"UPG extraction failed."); return FALSE;
    }
    DWORD upgSize = (DWORD)upgSizeZ;
    result->upgSize = upgSize;

    result->upgHeaderOk = (upgSize >= 0x70 &&
        memcmp(upg, "UPGR_FMT", 8) == 0 &&
        memcmp(upg + 0x10, "SONY", 4) == 0 &&
        memcmp(upg + 0x20, "00100000", 8) == 0);

    if (!Sha256Buffer(upg, upgSize, hash)) {
        mz_free(upg);
        SetError(errorText, errorCch, L"UPG SHA-256 calculation failed."); return FALSE;
    }
    HashToHex(hash, result->upgSha256);
    result->upgHashOk = (upgSize == EXPECTED_UPG_SIZE &&
        _wcsicmp(result->upgSha256, EXPECTED_UPG_SHA256) == 0);

    if (!result->upgHashOk || !result->upgHeaderOk) {
        mz_free(upg);
        SetError(errorText, errorCch, L"The firmware payload failed integrity validation.");
        return FALSE;
    }

    WCHAR dir[MAX_PATH];
    _snwprintf(dir, MAX_PATH - 1, L"%s\\verified_firmware", baseOutputDir);
    dir[MAX_PATH - 1] = 0;
    if (!CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        mz_free(upg);
        SetError(errorText, errorCch, L"Could not create verified_firmware folder."); return FALSE;
    }

    _snwprintf(result->extractedPath, MAX_PATH - 1,
        L"%s\\MSFWUPGR_NW-E40X_201J.UPG", dir);
    result->extractedPath[MAX_PATH - 1] = 0;
    if (!WriteWholeFile(result->extractedPath, upg, upgSize)) {
        mz_free(upg);
        SetError(errorText, errorCch, L"Could not save the verified UPG file."); return FALSE;
    }
    mz_free(upg);
    SetError(errorText, errorCch, L"");
    return TRUE;
}
