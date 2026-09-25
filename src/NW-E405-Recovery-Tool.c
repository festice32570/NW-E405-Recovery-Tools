#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <shellapi.h>

#define APP_TITLE L"NW-E405 Recovery Tool v0.3.1-dev"
#define SONY_VIDPID L"VID_054C&PID_01FB"
#define ID_SCAN 1001
#define ID_COPY 1002
#define ID_FOLDER 1003
#define ID_GITHUB 1004
#define ID_OUTPUT 1101
#define ID_STATUS 1102

static HWND g_hwnd = NULL;
static HWND g_output = NULL;
static HWND g_status = NULL;
static HWND g_scan = NULL;
static WCHAR g_logPath[MAX_PATH] = {0};
static WCHAR g_exeDir[MAX_PATH] = {0};
static BOOL g_exactUsbPresent = FALSE;

typedef struct {
    SCSI_PASS_THROUGH_DIRECT sptd;
    ULONG filler;
    UCHAR sense[32];
} SPTDWB;

typedef struct {
    BOOL opened;
    BOOL ioctlOk;
    DWORD winErr;
    UCHAR scsiStatus;
    BYTE data[128];
    DWORD dataLen;
    BYTE sense[32];
} ScsiResult;

static void PumpMessages(void) {
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static void Append(const WCHAR *text) {
    if (!g_output) return;
    int len = GetWindowTextLengthW(g_output);
    SendMessageW(g_output, EM_SETSEL, len, len);
    SendMessageW(g_output, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageW(g_output, EM_SCROLLCARET, 0, 0);
    PumpMessages();
}

static void LogF(const WCHAR *fmt, ...) {
    WCHAR buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap);
    va_end(ap);
    buf[2047] = 0;
    Append(buf);
    Append(L"\r\n");
}

static void SetStatus(const WCHAR *s) {
    SetWindowTextW(g_status, s);
    PumpMessages();
}

static void BytesToHex(const BYTE *p, DWORD n, WCHAR *out, size_t cchOut) {
    size_t pos = 0;
    if (!out || cchOut == 0) return;
    out[0] = 0;
    for (DWORD i = 0; i < n && pos + 4 < cchOut; ++i) {
        int w = _snwprintf(out + pos, cchOut - pos, L"%02X%s", p[i], (i + 1 == n) ? L"" : L" ");
        if (w < 0) break;
        pos += (size_t)w;
    }
}

static void BytesToAscii(const BYTE *p, DWORD off, DWORD n, WCHAR *out, size_t cchOut) {
    if (!out || cchOut == 0) return;
    size_t j = 0;
    for (DWORD i = 0; i < n && j + 1 < cchOut; ++i) {
        BYTE b = p[off + i];
        out[j++] = (b >= 32 && b < 127) ? (WCHAR)b : L'.';
    }
    while (j > 0 && (out[j-1] == L' ' || out[j-1] == L'.')) j--;
    out[j] = 0;
}

static const WCHAR* SenseName(BYTE key) {
    switch (key & 0x0F) {
        case 0: return L"NO SENSE";
        case 1: return L"RECOVERED ERROR";
        case 2: return L"NOT READY";
        case 3: return L"MEDIUM ERROR";
        case 4: return L"HARDWARE ERROR";
        case 5: return L"ILLEGAL REQUEST";
        case 6: return L"UNIT ATTENTION";
        case 7: return L"DATA PROTECT";
        default: return L"OTHER";
    }
}

static HANDLE OpenDeviceRW(const WCHAR *path, DWORD *err) {
    HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE && err) *err = GetLastError();
    return h;
}

static ScsiResult SendCdbEx(HANDLE h, const BYTE *cdb, BYTE cdbLen, DWORD dataLen, BYTE targetId) {
    ScsiResult r;
    ZeroMemory(&r, sizeof(r));
    if (h == INVALID_HANDLE_VALUE) return r;
    r.opened = TRUE;

    BYTE *data = NULL;
    if (dataLen > sizeof(r.data)) dataLen = sizeof(r.data);
    if (dataLen) {
        data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataLen);
        if (!data) {
            r.winErr = ERROR_NOT_ENOUGH_MEMORY;
            return r;
        }
    }

    SPTDWB pkt;
    ZeroMemory(&pkt, sizeof(pkt));
    pkt.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    pkt.sptd.PathId = 0;
    pkt.sptd.TargetId = targetId;
    pkt.sptd.Lun = 0;
    pkt.sptd.CdbLength = cdbLen;
    pkt.sptd.SenseInfoLength = 18;
    pkt.sptd.DataIn = dataLen ? SCSI_IOCTL_DATA_IN : SCSI_IOCTL_DATA_UNSPECIFIED;
    pkt.sptd.DataTransferLength = dataLen;
    pkt.sptd.TimeOutValue = 5;
    pkt.sptd.DataBuffer = data;
    pkt.sptd.SenseInfoOffset = offsetof(SPTDWB, sense);
    CopyMemory(pkt.sptd.Cdb, cdb, cdbLen);

    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &pkt, sizeof(pkt), &pkt, sizeof(pkt), &ret, NULL);
    r.ioctlOk = ok;
    r.winErr = ok ? ERROR_SUCCESS : GetLastError();
    r.scsiStatus = pkt.sptd.ScsiStatus;
    CopyMemory(r.sense, pkt.sense, sizeof(r.sense));
    if (data && dataLen) {
        CopyMemory(r.data, data, dataLen);
        r.dataLen = dataLen;
    }
    if (data) HeapFree(GetProcessHeap(), 0, data);
    return r;
}

static ScsiResult SendCdb(HANDLE h, const BYTE *cdb, BYTE cdbLen, DWORD dataLen) {
    return SendCdbEx(h, cdb, cdbLen, dataLen, 0);
}

static void ShowScsiResult(const WCHAR *name, const ScsiResult *r) {
    WCHAR hex[512];
    BytesToHex(r->sense, 18, hex, 512);
    LogF(L"--- %s ---", name);
    LogF(L"IOCTL=%s  SCSI Status=0x%02X  Win32=%lu",
        r->ioctlOk ? L"OK" : L"FAIL", r->scsiStatus, r->winErr);
    LogF(L"Sense: %s  ASC/ASCQ=%02X/%02X",
        SenseName(r->sense[2]), r->sense[12], r->sense[13]);
    LogF(L"SenseHex: %s", hex);
    if (r->dataLen) {
        BytesToHex(r->data, r->dataLen > 64 ? 64 : r->dataLen, hex, 512);
        LogF(L"Data: %s", hex);
    }
    LogF(L"");
}

static BOOL ContainsI(const WCHAR *hay, const WCHAR *needle) {
    if (!hay || !needle) return FALSE;
    size_t n = wcslen(needle);
    for (const WCHAR *p = hay; *p; ++p) {
        if (_wcsnicmp(p, needle, n) == 0) return TRUE;
    }
    return FALSE;
}

static void GetDevProp(HDEVINFO set, SP_DEVINFO_DATA *dev, DWORD prop, WCHAR *out, DWORD cch) {
    DWORD type = 0, req = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(set, dev, prop, &type, (PBYTE)out, cch * sizeof(WCHAR), &req))
        out[0] = 0;
}

static BOOL ScanSonyUsbDevices(void) {
    BOOL exact = FALSE;
    BOOL anySony = FALSE;
    HDEVINFO set = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (set == INVALID_HANDLE_VALUE) return FALSE;

    SP_DEVINFO_DATA dev;
    dev.cbSize = sizeof(dev);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &dev); ++i) {
        WCHAR ids[2048] = {0};
        DWORD type = 0, req = 0;
        if (SetupDiGetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID, &type,
            (PBYTE)ids, sizeof(ids), &req)) {
            if (ContainsI(ids, L"VID_054C")) {
                WCHAR name[512] = {0};
                GetDevProp(set, &dev, SPDRP_FRIENDLYNAME, name, 512);
                if (!name[0]) GetDevProp(set, &dev, SPDRP_DEVICEDESC, name, 512);
                LogF(L"SONY USB: %s", name[0] ? name : L"(unnamed device)");
                LogF(L"  Hardware ID: %s", ids);
                anySony = TRUE;
                if (ContainsI(ids, SONY_VIDPID)) {
                    exact = TRUE;
                    LogF(L"  >>> Exact NW-E405 USB ID match (054C:01FB)");
                }
            }
        }
        dev.cbSize = sizeof(dev);
    }
    SetupDiDestroyDeviceInfoList(set);
    if (!anySony) LogF(L"No present Sony USB device (VID_054C) was found.");
    if (!exact) LogF(L"Exact NW-E405 ID VID_054C&PID_01FB was not found.");
    g_exactUsbPresent = exact;
    return exact;
}

static BOOL DevNodeHasExactNwE405Ancestor(DEVINST devInst) {
    DEVINST cur = devInst;
    for (int depth = 0; depth < 12; ++depth) {
        WCHAR id[MAX_DEVICE_ID_LEN] = {0};
        if (CM_Get_Device_IDW(cur, id, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
            if (ContainsI(id, SONY_VIDPID))
                return TRUE;
        }
        DEVINST parent = 0;
        if (CM_Get_Parent(&parent, cur, 0) != CR_SUCCESS)
            break;
        cur = parent;
    }
    return FALSE;
}

static BOOL ProbeDriveLetterReadOnly(WCHAR letter) {
    WCHAR root[4] = { letter, L':', L'\\', 0 };
    if (GetDriveTypeW(root) != DRIVE_REMOVABLE)
        return FALSE;

    WCHAR path[8];
    _snwprintf(path, 8, L"\\\\.\\%c:", letter);

    DWORD err = 0;
    HANDLE h = OpenDeviceRW(path, &err);
    LogF(L"Drive-letter fallback: %c:", letter);
    if (h == INVALID_HANDLE_VALUE) {
        LogF(L"  Open failed: Win32=%lu", err);
        LogF(L"");
        return FALSE;
    }

    BYTE cdb[16] = {0};
    cdb[0] = 0x12;
    cdb[4] = 96;
    ScsiResult inq = SendCdb(h, cdb, 6, 96);

    WCHAR vendor[32] = {0}, product[64] = {0}, rev[16] = {0};
    if (inq.ioctlOk && inq.scsiStatus == 0 && inq.dataLen >= 36) {
        BytesToAscii(inq.data, 8, 8, vendor, 32);
        BytesToAscii(inq.data, 16, 16, product, 64);
        BytesToAscii(inq.data, 32, 4, rev, 16);
        LogF(L"  INQUIRY: Vendor=[%s] Product=[%s] Rev=[%s]", vendor, product, rev);
    } else {
        LogF(L"  INQUIRY failed (IOCTL=%d, Status=0x%02X, Win32=%lu)",
            inq.ioctlOk, inq.scsiStatus, inq.winErr);
        CloseHandle(h);
        LogF(L"");
        return FALSE;
    }

    BOOL expectedInquiry =
        ContainsI(vendor, L"SONY") &&
        ContainsI(product, L"NWWM MEM AAD2");

    if (!expectedInquiry) {
        LogF(L"  Not the expected SONY / NWWM MEM AAD2 identity; skipped.");
        CloseHandle(h);
        LogF(L"");
        return FALSE;
    }

    LogF(L"  Expected SCSI identity found via drive letter.");
    ShowScsiResult(L"SCSI INQUIRY (drive-letter fallback)", &inq);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x00;
    ScsiResult tur = SendCdb(h, cdb, 6, 0);
    ShowScsiResult(L"TEST UNIT READY (drive-letter fallback)", &tur);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x03;
    cdb[4] = 64;
    ScsiResult rs = SendCdb(h, cdb, 6, 64);
    ShowScsiResult(L"REQUEST SENSE (drive-letter fallback)", &rs);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x25;
    ScsiResult cap = SendCdb(h, cdb, 10, 8);
    ShowScsiResult(L"READ CAPACITY(10) (drive-letter fallback)", &cap);

    LogF(L"SAFETY: Sony vendor command is NOT sent through the drive-letter fallback");
    LogF(L"because this path cannot be bound conclusively to USB VID_054C&PID_01FB.");
    LogF(L"");

    CloseHandle(h);
    return TRUE;
}

static int ProbeRemovableDriveLetters(void) {
    DWORD mask = GetLogicalDrives();
    int found = 0;
    for (WCHAR c = L'A'; c <= L'Z'; ++c) {
        if (mask & (1u << (c - L'A'))) {
            if (ProbeDriveLetterReadOnly(c))
                found++;
        }
    }
    return found;
}

static int ProbeSonyScsiPaths(void) {
    int matches = 0;
    int openCount = 0;
    int inquiryOkCount = 0;
    int fileNotFoundCount = 0;
    int accessDeniedCount = 0;
    int otherOpenErrors = 0;
    int mapperSupportedCount = 0;
    int mapperMatchCount = 0;
    LogF(L"");
    LogF(L"=== Sony/NT scsipath probe ===");
    LogF(L"Checking \\\\.\\scsipath0 ... \\\\.\\scsipath25 (read-only commands only)");

    for (int i = 0; i < 26; ++i) {
        WCHAR path[64];
        _snwprintf(path, 64, L"\\\\.\\scsipath%d", i);

        DWORD err = 0;
        HANDLE h = OpenDeviceRW(path, &err);
        if (h == INVALID_HANDLE_VALUE) {
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                fileNotFoundCount++;
            else if (err == ERROR_ACCESS_DENIED)
                accessDeniedCount++;
            else
                otherOpenErrors++;
            continue;
        }

        openCount++;
        LogF(L"scsipath%d: OPEN", i);

        // Mirror the original updater's NT path mapping:
        // QueryDosDeviceA("X:") -> DeviceIoControl(0x7048C) on scsipathN.
        for (char drive = 'A'; drive <= 'Z'; ++drive) {
            char dosName[3] = { drive, ':', 0 };
            char ntTarget[512] = {0};
            DWORD q = QueryDosDeviceA(dosName, ntTarget, sizeof(ntTarget));
            if (!q)
                continue;

            DWORD mapped = 0, bytesReturned = 0;
            BOOL mapOk = DeviceIoControl(
                h, 0x0007048C,
                ntTarget, (DWORD)strlen(ntTarget),
                &mapped, sizeof(mapped),
                &bytesReturned, NULL);

            if (mapOk) {
                mapperSupportedCount++;
                if (mapped != 0) {
                    mapperMatchCount++;
                    LogF(L"  Original-updater mapping: %c: -> scsipath%d (NT target=%S)",
                        (WCHAR)drive, i, ntTarget);
                }
            }
        }

        BYTE cdb[16] = {0};
        cdb[0] = 0x12;
        cdb[4] = 96;
        ScsiResult inq = SendCdbEx(h, cdb, 6, 96, 1);

        WCHAR vendor[32] = {0}, product[64] = {0}, rev[16] = {0};
        if (inq.ioctlOk && inq.scsiStatus == 0 && inq.dataLen >= 36) {
            inquiryOkCount++;
            BytesToAscii(inq.data, 8, 8, vendor, 32);
            BytesToAscii(inq.data, 16, 16, product, 64);
            BytesToAscii(inq.data, 32, 4, rev, 16);
            LogF(L"  INQUIRY: Vendor=[%s] Product=[%s] Rev=[%s]",
                vendor, product, rev);
        } else {
            LogF(L"  INQUIRY failed: IOCTL=%d Status=0x%02X Win32=%lu Sense=%s %02X/%02X",
                inq.ioctlOk, inq.scsiStatus, inq.winErr,
                SenseName(inq.sense[2]), inq.sense[12], inq.sense[13]);
            CloseHandle(h);
            continue;
        }

        BOOL expected =
            ContainsI(vendor, L"SONY") &&
            ContainsI(product, L"NWWM MEM AAD2");

        if (!expected) {
            LogF(L"  Not NW-E40X SCSI identity; no Sony vendor command sent.");
            CloseHandle(h);
            continue;
        }

        matches++;
        LogF(L"  >>> NW-E405/NW-E40X candidate on scsipath%d", i);

        if (!g_exactUsbPresent) {
            LogF(L"  SAFETY: exact USB VID_054C&PID_01FB is absent; FC/03 skipped.");
            CloseHandle(h);
            continue;
        }

        ZeroMemory(cdb, sizeof(cdb));
        cdb[0] = 0xFC;
        cdb[2] = 0x03;
        cdb[7] = 0x00;
        cdb[8] = 0x08;

        ScsiResult sonyInfo = SendCdbEx(h, cdb, 12, 8, 1);
        ShowScsiResult(L"SONY 0xFC/0x03 via scsipath (read-only)", &sonyInfo);

        if (sonyInfo.ioctlOk && sonyInfo.scsiStatus == 0) {
            WCHAR ascii[129] = {0};
            BytesToAscii(sonyInfo.data, 0, sonyInfo.dataLen, ascii, 129);
            LogF(L"scsipath%d RESULT: FC/03 SUCCESS", i);
            LogF(L"Response ASCII: %s", ascii);
        } else {
            LogF(L"scsipath%d RESULT: FC/03 failed: %s ASC/ASCQ=%02X/%02X",
                i, SenseName(sonyInfo.sense[2]), sonyInfo.sense[12], sonyInfo.sense[13]);
        }

        CloseHandle(h);
    }

    if (openCount == 0) {
        LogF(L"No scsipath device could be opened.");
        LogF(L"Open errors: not-found=%d access-denied=%d other=%d",
            fileNotFoundCount, accessDeniedCount, otherOpenErrors);
        LogF(L"This usually means the legacy Sony/PCD scsipath layer is not present.");
    } else if (matches == 0) {
        LogF(L"scsipath handles exist, but no SONY / NWWM MEM AAD2 device was found.");
    }

    LogF(L"scsipath summary: opened=%d inquiry-ok=%d identity-match=%d",
        openCount, inquiryOkCount, matches);
    LogF(L"original-updater mapper: supported-calls=%d drive-matches=%d",
        mapperSupportedCount, mapperMatchCount);
    LogF(L"");
    return matches;
}

static BOOL ProbeDiskInterface(const WCHAR *path, const WCHAR *friendly, int index, BOOL exactMapped) {
    DWORD err = 0;
    HANDLE h = OpenDeviceRW(path, &err);
    LogF(L"Disk interface #%d: %s", index, friendly && friendly[0] ? friendly : L"(no friendly name)");
    if (h == INVALID_HANDLE_VALUE) {
        LogF(L"  Open failed: Win32=%lu. Try Run as administrator.", err);
        LogF(L"");
        return FALSE;
    }

    BYTE cdb[16] = {0};
    cdb[0] = 0x12;
    cdb[4] = 96;
    ScsiResult inq = SendCdb(h, cdb, 6, 96);

    WCHAR vendor[32] = {0}, product[64] = {0}, rev[16] = {0};
    if (inq.ioctlOk && inq.scsiStatus == 0 && inq.dataLen >= 36) {
        BytesToAscii(inq.data, 8, 8, vendor, 32);
        BytesToAscii(inq.data, 16, 16, product, 64);
        BytesToAscii(inq.data, 32, 4, rev, 16);
        LogF(L"  INQUIRY: Vendor=[%s] Product=[%s] Rev=[%s]", vendor, product, rev);
    } else {
        LogF(L"  INQUIRY failed (IOCTL=%d, Status=0x%02X, Win32=%lu)",
            inq.ioctlOk, inq.scsiStatus, inq.winErr);
    }

    BOOL expectedInquiry =
        ContainsI(vendor, L"SONY") &&
        ContainsI(product, L"NWWM MEM AAD2");

    if (!expectedInquiry) {
        LogF(L"  Not the expected SONY / NWWM MEM AAD2 SCSI identity; skipped.");
        LogF(L"");
        CloseHandle(h);
        return FALSE;
    }

    LogF(L"  Expected SCSI identity found.");
    LogF(L"  USB parent mapping to VID_054C&PID_01FB: %s", exactMapped ? L"YES" : L"NO");
    LogF(L"");

    ShowScsiResult(L"SCSI INQUIRY", &inq);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x00;
    ScsiResult tur = SendCdb(h, cdb, 6, 0);
    ShowScsiResult(L"TEST UNIT READY", &tur);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x03;
    cdb[4] = 64;
    ScsiResult rs = SendCdb(h, cdb, 6, 64);
    ShowScsiResult(L"REQUEST SENSE", &rs);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x25;
    ScsiResult cap = SendCdb(h, cdb, 10, 8);
    ShowScsiResult(L"READ CAPACITY(10)", &cap);
    if (cap.ioctlOk && cap.scsiStatus == 0 && cap.dataLen >= 8) {
        uint32_t last = ((uint32_t)cap.data[0] << 24) | ((uint32_t)cap.data[1] << 16) |
                        ((uint32_t)cap.data[2] << 8) | cap.data[3];
        uint32_t blen = ((uint32_t)cap.data[4] << 24) | ((uint32_t)cap.data[5] << 16) |
                        ((uint32_t)cap.data[6] << 8) | cap.data[7];
        uint64_t bytes = ((uint64_t)last + 1ULL) * blen;
        LogF(L"Capacity: %I64u bytes  BlockSize=%lu", bytes, blen);
        LogF(L"");
    }

    if (exactMapped) {
        ZeroMemory(cdb, sizeof(cdb));
        cdb[0] = 0xFC;
        cdb[2] = 0x03;
        cdb[7] = 0x00;
        cdb[8] = 0x08;
        ScsiResult sonyInfo = SendCdb(h, cdb, 12, 8);
        ShowScsiResult(L"SONY 0xFC/0x03 (read-only vendor query)", &sonyInfo);

        if (sonyInfo.ioctlOk && sonyInfo.scsiStatus == 0)
            LogF(L"RESULT: Sony vendor-command processor responded. Stage-2 software recovery may be possible.");
        else
            LogF(L"RESULT: Sony vendor read command did not complete successfully.");
    } else {
        LogF(L"SAFETY: Sony vendor command skipped because this disk interface was not");
        LogF(L"mapped through the PnP tree to USB VID_054C&PID_01FB.");
    }

    LogF(L"");
    CloseHandle(h);
    return TRUE;
}

static int EnumerateDisks(void) {
    HDEVINFO set = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) {
        LogF(L"Disk enumeration failed: %lu", GetLastError());
        return 0;
    }

    int sonyCount = 0;
    for (DWORD i = 0;; ++i) {
        SP_DEVICE_INTERFACE_DATA ifc;
        ZeroMemory(&ifc, sizeof(ifc));
        ifc.cbSize = sizeof(ifc);
        if (!SetupDiEnumDeviceInterfaces(set, NULL, &GUID_DEVINTERFACE_DISK, i, &ifc)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            continue;
        }

        DWORD need = 0;
        SetupDiGetDeviceInterfaceDetailW(set, &ifc, NULL, 0, &need, NULL);
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail =
            (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
        if (!detail) continue;
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        SP_DEVINFO_DATA dev;
        ZeroMemory(&dev, sizeof(dev));
        dev.cbSize = sizeof(dev);

        if (SetupDiGetDeviceInterfaceDetailW(set, &ifc, detail, need, NULL, &dev)) {
            WCHAR friendly[512] = {0};
            GetDevProp(set, &dev, SPDRP_FRIENDLYNAME, friendly, 512);
            if (!friendly[0]) GetDevProp(set, &dev, SPDRP_DEVICEDESC, friendly, 512);
            BOOL exactMapped = DevNodeHasExactNwE405Ancestor(dev.DevInst);
            if (ProbeDiskInterface(detail->DevicePath, friendly, (int)i, exactMapped))
                sonyCount++;
        }
        HeapFree(GetProcessHeap(), 0, detail);
    }

    SetupDiDestroyDeviceInfoList(set);
    return sonyCount;
}

static BOOL SaveLog(void) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snwprintf(g_logPath, MAX_PATH - 1, L"%s\\NW-E405_diag_%04u%02u%02u_%02u%02u%02u.txt",
        g_exeDir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    int len = GetWindowTextLengthW(g_output);
    WCHAR *w = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len + 2) * sizeof(WCHAR));
    if (!w) return FALSE;
    GetWindowTextW(g_output, w, len + 1);

    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *u8 = (char*)HeapAlloc(GetProcessHeap(), 0, n);
    if (!u8) { HeapFree(GetProcessHeap(), 0, w); return FALSE; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, u8, n, NULL, NULL);

    HANDLE f = CreateFileW(g_logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL ok = FALSE;
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        BYTE bom[3] = {0xEF,0xBB,0xBF};
        WriteFile(f, bom, 3, &wr, NULL);
        WriteFile(f, u8, (DWORD)(n - 1), &wr, NULL);
        CloseHandle(f);
        ok = TRUE;
    }
    HeapFree(GetProcessHeap(), 0, u8);
    HeapFree(GetProcessHeap(), 0, w);
    return ok;
}

static void RunDiagnostics(void) {
    EnableWindow(g_scan, FALSE);
    SetWindowTextW(g_output, L"");
    SetStatus(L"診断中... USBを抜かないでください");

    LogF(L"%s", APP_TITLE);
    LogF(L"Stage 1: READ-ONLY diagnostic build");
    LogF(L"");
    LogF(L"このバージョンはフォーマット、セクタ書込み、FW書込み、");
    LogF(L"Sony update-start command (0xFC/0x04) を実行しません。");
    LogF(L"");

    BOOL usb = ScanSonyUsbDevices();
    LogF(L"");
    int sony = EnumerateDisks();
    int fallback = 0;
    if (sony == 0) {
        LogF(L"");
        LogF(L"No matching disk interface found. Trying read-only removable-drive fallback...");
        fallback = ProbeRemovableDriveLetters();
    }

    int scsiPathMatches = 0;
    if (usb)
        scsiPathMatches = ProbeSonyScsiPaths();

    LogF(L"=== SUMMARY ===");
    LogF(L"Exact USB VID/PID 054C:01FB found: %s", usb ? L"YES" : L"NO");
    LogF(L"Mapped SONY/NWWM disk candidates: %d", sony);
    LogF(L"Drive-letter fallback matches: %d", fallback);
    LogF(L"Sony scsipath matches: %d", scsiPathMatches);

    if (sony == 0 && fallback > 0 && usb) {
        LogF(L"");
        LogF(L"NW-E405-like SCSI identity is reachable via a drive letter, but the");
        LogF(L"disk-interface mapping was unavailable. Vendor commands were skipped for safety.");
    } else if (sony == 0 && fallback == 0 && usb) {
        LogF(L"");
        LogF(L"USB VID/PID is present, but no usable SCSI path was found.");
        LogF(L"Next target: Sony's original SONYSPTI/scsipath access path.");
    } else if (sony == 0 && fallback == 0) {
        LogF(L"");
        LogF(L"NW-E405 could not be identified. Check cable, USB port and driver state.");
    }

    LogF(L"");
    LogF(L"診断完了。ログを開発者へ送ってください。");

    if (SaveLog()) {
        LogF(L"Log saved: %s", g_logPath);
        SetStatus(L"診断完了 — ログを保存しました");
    } else {
        SetStatus(L"診断完了 — ログ保存に失敗しました（画面結果はコピーできます）");
    }

    EnableWindow(g_scan, TRUE);
}

static void CopyOutput(void) {
    int len = GetWindowTextLengthW(g_output);
    if (len <= 0) return;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(WCHAR));
    if (!h) return;
    WCHAR *p = (WCHAR*)GlobalLock(h);
    GetWindowTextW(g_output, p, len + 1);
    GlobalUnlock(h);
    if (OpenClipboard(g_hwnd)) {
        EmptyClipboard();
        SetClipboardData(CF_UNICODETEXT, h);
        CloseClipboard();
        SetStatus(L"診断結果をクリップボードへコピーしました");
    } else {
        GlobalFree(h);
    }
}

static void InitExeDir(void) {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    WCHAR *slash = wcsrchr(path, L'\\');
    if (slash) *slash = 0;
    lstrcpynW(g_exeDir, path, MAX_PATH);
}

static HFONT MakeFont(int pt, BOOL bold) {
    HDC dc = GetDC(NULL);
    int h = -MulDiv(pt, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(NULL, dc);
    return CreateFontW(h, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT fNormal, fTitle;
    switch (msg) {
        case WM_CREATE: {
            fNormal = MakeFont(9, FALSE);
            fTitle = MakeFont(15, TRUE);

            HWND title = CreateWindowW(L"STATIC", L"NW-E405 Recovery Tool",
                WS_CHILD | WS_VISIBLE, 18, 14, 420, 32, hwnd, NULL, NULL, NULL);
            SendMessageW(title, WM_SETFONT, (WPARAM)fTitle, TRUE);

            HWND sub = CreateWindowW(L"STATIC",
                L"開発中 / Stage 1は読み取り専用です。NW-E405をUSBへ接続して診断してください。",
                WS_CHILD | WS_VISIBLE, 20, 48, 720, 24, hwnd, NULL, NULL, NULL);
            SendMessageW(sub, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_scan = CreateWindowW(L"BUTTON", L"NW-E405を診断する",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                20, 80, 190, 38, hwnd, (HMENU)ID_SCAN, NULL, NULL);
            SendMessageW(g_scan, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND copy = CreateWindowW(L"BUTTON", L"結果をコピー",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                220, 80, 125, 38, hwnd, (HMENU)ID_COPY, NULL, NULL);
            SendMessageW(copy, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND folder = CreateWindowW(L"BUTTON", L"ログフォルダ",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                355, 80, 125, 38, hwnd, (HMENU)ID_FOLDER, NULL, NULL);
            SendMessageW(folder, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND github = CreateWindowW(L"BUTTON", L"GitHub",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                490, 80, 100, 38, hwnd, (HMENU)ID_GITHUB, NULL, NULL);
            SendMessageW(github, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
                20, 132, 744, 385, hwnd, (HMENU)ID_OUTPUT, NULL, NULL);
            SendMessageW(g_output, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_status = CreateWindowW(L"STATIC",
                L"待機中 — NW-E405を接続して「診断する」を押してください",
                WS_CHILD | WS_VISIBLE, 20, 530, 744, 24, hwnd, (HMENU)ID_STATUS, NULL, NULL);
            SendMessageW(g_status, WM_SETFONT, (WPARAM)fNormal, TRUE);
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_SCAN: RunDiagnostics(); return 0;
                case ID_COPY: CopyOutput(); return 0;
                case ID_FOLDER:
                    ShellExecuteW(hwnd, L"open", g_exeDir, NULL, NULL, SW_SHOWNORMAL);
                    return 0;
                case ID_GITHUB:
                    ShellExecuteW(hwnd, L"open",
                        L"https://github.com/festice32570/NW-E405-Recovery-Tools",
                        NULL, NULL, SW_SHOWNORMAL);
                    return 0;
            }
            break;
        case WM_DESTROY:
            if (fNormal) DeleteObject(fNormal);
            if (fTitle) DeleteObject(fTitle);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmd, int show) {
    (void)prev; (void)cmd;
    InitExeDir();
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"NWE405RecoveryWindow";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, wc.lpszClassName, APP_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, inst, NULL);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, show);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
