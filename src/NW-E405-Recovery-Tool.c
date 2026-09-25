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
#include <commdlg.h>
#include <wincrypt.h>
#include "fw_package.h"

#define APP_TITLE L"NW-E405 Recovery Lab v0.5-dev"
#define SONY_VIDPID L"VID_054C&PID_01FB"
#define ID_SCAN 1001
#define ID_COPY 1002
#define ID_FOLDER 1003
#define ID_GITHUB 1004
#define ID_BACKUP 1005
#define ID_VERIFY_FW 1006
#define ID_OUTPUT 1101
#define ID_STATUS 1102

static HWND g_hwnd = NULL;
static HWND g_output = NULL;
static HWND g_status = NULL;
static HWND g_scan = NULL;
static HWND g_backup = NULL;
static HANDLE g_liveLog = INVALID_HANDLE_VALUE;
static HANDLE g_jsonLog = INVALID_HANDLE_VALUE;
static WCHAR g_jsonLogPath[MAX_PATH] = {0};
static WCHAR g_sessionStem[96] = {0};
static WCHAR g_backupDevicePath[1024] = {0};
static uint64_t g_backupCapacityBytes = 0;
static DWORD g_backupBlockSize = 0;
static BOOL g_mediaBackupAvailable = FALSE;
static BYTE g_metaInquiry[96]; static DWORD g_metaInquiryLen = 0;
static BYTE g_metaFc03[8]; static DWORD g_metaFc03Len = 0;
static BYTE g_metaFc05[16]; static DWORD g_metaFc05Len = 0;
static BYTE g_metaFc09[24]; static DWORD g_metaFc09Len = 0;
static LONG g_cdbSequence = 0;
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
    BYTE cdb[16];
    BYTE cdbLen;
    BYTE targetId;
    DWORD requestedDataLen;
    DWORD elapsedMs;
} ScsiResult;

static void TraceCdbJson(const ScsiResult *r);
static BOOL StartSessionLogs(void);
static void CloseSessionLogs(void);
static void SaveMetadataBackup(void);

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

static void WriteUtf8Line(HANDLE h, const WCHAR *line) {
    if (h == INVALID_HANDLE_VALUE || !line) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, line, -1, NULL, 0, NULL, NULL);
    if (n <= 1) return;
    char *u8 = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n + 2);
    if (!u8) return;
    WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, n, NULL, NULL);
    u8[n-1] = '\r'; u8[n] = '\n';
    DWORD wr = 0;
    WriteFile(h, u8, (DWORD)n + 1, &wr, NULL);
    FlushFileBuffers(h);
    HeapFree(GetProcessHeap(), 0, u8);
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
    WriteUtf8Line(g_liveLog, buf);
}

static void CloseSessionLogs(void) {
    if (g_liveLog != INVALID_HANDLE_VALUE) { FlushFileBuffers(g_liveLog); CloseHandle(g_liveLog); g_liveLog = INVALID_HANDLE_VALUE; }
    if (g_jsonLog != INVALID_HANDLE_VALUE) { FlushFileBuffers(g_jsonLog); CloseHandle(g_jsonLog); g_jsonLog = INVALID_HANDLE_VALUE; }
}

static BOOL StartSessionLogs(void) {
    CloseSessionLogs();
    SYSTEMTIME st; GetLocalTime(&st);
    _snwprintf(g_sessionStem, 95, L"%04u%02u%02u_%02u%02u%02u", st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    g_sessionStem[95] = 0;
    _snwprintf(g_logPath, MAX_PATH-1, L"%s\\NW-E405_diag_%s.txt", g_exeDir, g_sessionStem);
    _snwprintf(g_jsonLogPath, MAX_PATH-1, L"%s\\NW-E405_trace_%s.jsonl", g_exeDir, g_sessionStem);
    g_liveLog = CreateFileW(g_logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    g_jsonLog = CreateFileW(g_jsonLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (g_liveLog != INVALID_HANDLE_VALUE) {
        DWORD wr=0; BYTE bom[3]={0xEF,0xBB,0xBF}; WriteFile(g_liveLog,bom,3,&wr,NULL); FlushFileBuffers(g_liveLog);
    }
    g_cdbSequence = 0;
    return g_liveLog != INVALID_HANDLE_VALUE && g_jsonLog != INVALID_HANDLE_VALUE;
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
    r.cdbLen = cdbLen; r.targetId = targetId; r.requestedDataLen = dataLen;
    CopyMemory(r.cdb, cdb, cdbLen > 16 ? 16 : cdbLen);

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
    DWORD started = GetTickCount();
    BOOL ok = DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &pkt, sizeof(pkt), &pkt, sizeof(pkt), &ret, NULL);
    r.elapsedMs = GetTickCount() - started;
    r.ioctlOk = ok;
    r.winErr = ok ? ERROR_SUCCESS : GetLastError();
    r.scsiStatus = pkt.sptd.ScsiStatus;
    CopyMemory(r.sense, pkt.sense, sizeof(r.sense));
    if (data && dataLen) {
        CopyMemory(r.data, data, dataLen);
        r.dataLen = dataLen;
    }
    if (data) HeapFree(GetProcessHeap(), 0, data);
    TraceCdbJson(&r);
    return r;
}

static ScsiResult SendCdb(HANDLE h, const BYTE *cdb, BYTE cdbLen, DWORD dataLen) {
    return SendCdbEx(h, cdb, cdbLen, dataLen, 0);
}

static void TraceCdbJson(const ScsiResult *r) {
    if (!r || g_jsonLog == INVALID_HANDLE_VALUE) return;
    WCHAR cdbHex[96]={0}, senseHex[160]={0}, dataHex[600]={0};
    BytesToHex(r->cdb, r->cdbLen, cdbHex, 96);
    BytesToHex(r->sense, 18, senseHex, 160);
    BytesToHex(r->data, r->dataLen > 128 ? 128 : r->dataLen, dataHex, 600);
    SYSTEMTIME st; GetLocalTime(&st);
    char line[4096];
    char cdbA[192]={0}, senseA[320]={0}, dataA[1200]={0};
    WideCharToMultiByte(CP_UTF8,0,cdbHex,-1,cdbA,sizeof(cdbA),NULL,NULL);
    WideCharToMultiByte(CP_UTF8,0,senseHex,-1,senseA,sizeof(senseA),NULL,NULL);
    WideCharToMultiByte(CP_UTF8,0,dataHex,-1,dataA,sizeof(dataA),NULL,NULL);
    LONG seq=InterlockedIncrement(&g_cdbSequence);
    int n=_snprintf(line,sizeof(line)-1,
        "{\"seq\":%ld,\"time\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03u\",\"target\":%u,\"cdb\":\"%s\",\"direction\":\"%s\",\"requested_data\":%lu,\"ioctl_ok\":%s,\"win32\":%lu,\"scsi_status\":%u,\"sense\":\"%s\",\"data\":\"%s\",\"elapsed_ms\":%lu}\r\n",
        seq,st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds,
        r->targetId,cdbA,r->requestedDataLen?"IN":"NONE",r->requestedDataLen,r->ioctlOk?"true":"false",r->winErr,r->scsiStatus,senseA,dataA,r->elapsedMs);
    if (n>0) { DWORD wr=0; WriteFile(g_jsonLog,line,(DWORD)n,&wr,NULL); FlushFileBuffers(g_jsonLog); }
}

static void ShowScsiResult(const WCHAR *name, const ScsiResult *r) {
    WCHAR hex[512];
    BytesToHex(r->sense, 18, hex, 512);
    LogF(L"--- %s ---", name);
    WCHAR cdbhex[96]; BytesToHex(r->cdb, r->cdbLen, cdbhex, 96);
    LogF(L"CDB: %s  TargetId=%u  DataLen=%lu  Elapsed=%lu ms", cdbhex, r->targetId, r->requestedDataLen, r->elapsedMs);
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

static void LogHostEnvironment(void) {
    SYSTEM_INFO si; ZeroMemory(&si,sizeof(si)); GetNativeSystemInfo(&si);
    BOOL wow=FALSE; IsWow64Process(GetCurrentProcess(), &wow);
    const WCHAR *arch=L"unknown";
    if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64) arch=L"x64";
    else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL) arch=L"x86";
    else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64) arch=L"ARM64";
    LogF(L"Host architecture: %s  Tool process: x86%s", arch, wow?L" (WoW64)":L"");

    typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionFn fn=ntdll?(RtlGetVersionFn)GetProcAddress(ntdll,"RtlGetVersion"):NULL;
    RTL_OSVERSIONINFOW vi; ZeroMemory(&vi,sizeof(vi)); vi.dwOSVersionInfoSize=sizeof(vi);
    if (fn && fn(&vi)==0) LogF(L"Windows version: %lu.%lu build %lu",vi.dwMajorVersion,vi.dwMinorVersion,vi.dwBuildNumber);
    BOOL isAdmin=FALSE; SID_IDENTIFIER_AUTHORITY ntAuth=SECURITY_NT_AUTHORITY; PSID adminSid=NULL;
    if(AllocateAndInitializeSid(&ntAuth,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&adminSid)){
        CheckTokenMembership(NULL,adminSid,&isAdmin); FreeSid(adminSid);
    }
    LogF(L"Administrator token membership: %s",isAdmin?L"YES":L"NO");
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
    if (exactMapped) { g_metaInquiryLen = inq.dataLen > 96 ? 96 : inq.dataLen; CopyMemory(g_metaInquiry, inq.data, g_metaInquiryLen); }
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
        if (exactMapped && blen >= 256 && blen <= 4096 && bytes > 0 && bytes <= (2ULL*1024*1024*1024)) {
            lstrcpynW(g_backupDevicePath, path, 1024);
            g_backupCapacityBytes = bytes; g_backupBlockSize = blen; g_mediaBackupAvailable = TRUE;
        }
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

        if (sonyInfo.ioctlOk && sonyInfo.scsiStatus == 0) {
            LogF(L"RESULT: Sony vendor-command processor responded. Read-only recovery research can continue.");
            g_metaFc03Len = sonyInfo.dataLen > 8 ? 8 : sonyInfo.dataLen;
            CopyMemory(g_metaFc03, sonyInfo.data, g_metaFc03Len);
        } else {
            LogF(L"RESULT: Sony vendor read command did not complete successfully.");
        }

        // Original GetDeviceId path for ClassifyType=3: FC/05, allocation 16.
        ZeroMemory(cdb, sizeof(cdb));
        cdb[0] = 0xFC; cdb[2] = 0x05; cdb[9] = 0x10;
        ScsiResult devId = SendCdb(h, cdb, 12, 16);
        ShowScsiResult(L"SONY 0xFC/0x05 GetDeviceId (read-only)", &devId);
        if (devId.ioctlOk && devId.scsiStatus == 0) {
            g_metaFc05Len = devId.dataLen > 16 ? 16 : devId.dataLen;
            CopyMemory(g_metaFc05, devId.data, g_metaFc05Len);
        }

        // Original GetProductInfo vendor-read shape. The INI signature is ASCII "roga".
        ZeroMemory(cdb, sizeof(cdb));
        cdb[0] = 0xFC; cdb[2] = 0x09;
        cdb[3] = 'r'; cdb[4] = 'o'; cdb[5] = 'g'; cdb[6] = 'a';
        ScsiResult prod = SendCdb(h, cdb, 12, 24);
        ShowScsiResult(L"SONY 0xFC/0x09 GetProductInfo probe (read-only)", &prod);
        if (prod.ioctlOk && prod.scsiStatus == 0) {
            g_metaFc09Len = prod.dataLen > 24 ? 24 : prod.dataLen;
            CopyMemory(g_metaFc09, prod.data, g_metaFc09Len);
        }
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

static void WriteTlv(HANDLE h, DWORD tag, const BYTE *data, DWORD len) {
    DWORD wr=0; WriteFile(h,&tag,4,&wr,NULL); WriteFile(h,&len,4,&wr,NULL);
    if (len) WriteFile(h,data,len,&wr,NULL);
}

static void SaveMetadataBackup(void) {
    if (!g_sessionStem[0]) return;
    WCHAR path[MAX_PATH];
    _snwprintf(path,MAX_PATH-1,L"%s\\NW-E405_metadata_%s.bin",g_exeDir,g_sessionStem);
    HANDLE h=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
    if (h==INVALID_HANDLE_VALUE) { LogF(L"Metadata backup: could not create file (%lu)",GetLastError()); return; }
    DWORD wr=0; const char magic[]="NWE405META1"; WriteFile(h,magic,sizeof(magic),&wr,NULL);
    WriteTlv(h,1,g_metaInquiry,g_metaInquiryLen);
    WriteTlv(h,3,g_metaFc03,g_metaFc03Len);
    WriteTlv(h,5,g_metaFc05,g_metaFc05Len);
    WriteTlv(h,9,g_metaFc09,g_metaFc09Len);
    FlushFileBuffers(h); CloseHandle(h);
    LogF(L"Metadata backup saved: %s",path);
    LogF(L"IMPORTANT: this is NOT a NOR/NAND firmware image backup; it stores read-only device metadata/responses.");
}

static BOOL Read10Chunk(HANDLE h, DWORD lba, WORD blocks, BYTE *buf, DWORD bytes, ScsiResult *summary) {
    SPTDWB pkt; ZeroMemory(&pkt,sizeof(pkt));
    pkt.sptd.Length=sizeof(SCSI_PASS_THROUGH_DIRECT); pkt.sptd.PathId=0; pkt.sptd.TargetId=0; pkt.sptd.Lun=0;
    pkt.sptd.CdbLength=10; pkt.sptd.SenseInfoLength=18; pkt.sptd.DataIn=SCSI_IOCTL_DATA_IN;
    pkt.sptd.DataTransferLength=bytes; pkt.sptd.TimeOutValue=15; pkt.sptd.DataBuffer=buf;
    pkt.sptd.SenseInfoOffset=offsetof(SPTDWB,sense);
    BYTE *cdb=pkt.sptd.Cdb; cdb[0]=0x28;
    cdb[2]=(BYTE)(lba>>24); cdb[3]=(BYTE)(lba>>16); cdb[4]=(BYTE)(lba>>8); cdb[5]=(BYTE)lba;
    cdb[7]=(BYTE)(blocks>>8); cdb[8]=(BYTE)blocks;
    DWORD ret=0,started=GetTickCount();
    BOOL ok=DeviceIoControl(h,IOCTL_SCSI_PASS_THROUGH_DIRECT,&pkt,sizeof(pkt),&pkt,sizeof(pkt),&ret,NULL);
    if (summary) { ZeroMemory(summary,sizeof(*summary)); summary->opened=TRUE; summary->ioctlOk=ok; summary->winErr=ok?0:GetLastError(); summary->scsiStatus=pkt.sptd.ScsiStatus; summary->elapsedMs=GetTickCount()-started; summary->cdbLen=10; summary->targetId=0; summary->requestedDataLen=bytes; CopyMemory(summary->cdb,cdb,10); CopyMemory(summary->sense,pkt.sense,18); }
    return ok && pkt.sptd.ScsiStatus==0;
}

static void BackupLogicalMedia(void) {
    if (!g_mediaBackupAvailable || !g_backupDevicePath[0]) {
        MessageBoxW(g_hwnd,L"この個体はREAD CAPACITYが通っていないため、論理ストレージをバックアップできません。\n\n現在のNo Media状態ではNANDの通常読み出し経路がありません。",L"Backup unavailable",MB_OK|MB_ICONINFORMATION);
        return;
    }
    WCHAR partial[MAX_PATH],final[MAX_PATH];
    _snwprintf(partial,MAX_PATH-1,L"%s\\NW-E405_storage_%s.img.partial",g_exeDir,g_sessionStem);
    _snwprintf(final,MAX_PATH-1,L"%s\\NW-E405_storage_%s.img",g_exeDir,g_sessionStem);
    int ans=MessageBoxW(g_hwnd,L"内蔵ストレージをREAD(10)だけで丸ごと読み出します。\n本体への書き込みは行いません。開始しますか？",L"Logical storage backup",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2);
    if(ans!=IDYES)return;
    HANDLE dev=OpenDeviceRW(g_backupDevicePath,NULL);
    if(dev==INVALID_HANDLE_VALUE){LogF(L"Storage backup: device open failed %lu",GetLastError());return;}
    HANDLE out=CreateFileW(partial,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
    if(out==INVALID_HANDLE_VALUE){CloseHandle(dev);LogF(L"Storage backup: host output open failed %lu",GetLastError());return;}
    const DWORD maxBytes=64*1024; BYTE *buf=(BYTE*)VirtualAlloc(NULL,maxBytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!buf){CloseHandle(out);CloseHandle(dev);return;}
    uint64_t totalBlocks=g_backupCapacityBytes/g_backupBlockSize,done=0; int lastPct=-1; BOOL okAll=TRUE;
    while(done<totalBlocks){
        DWORD remain=(DWORD)((totalBlocks-done)>0xFFFFFFFFULL?0xFFFFFFFFULL:(totalBlocks-done));
        DWORD maxBlocks=maxBytes/g_backupBlockSize; WORD n=(WORD)((remain<maxBlocks)?remain:maxBlocks);
        DWORD bytes=n*g_backupBlockSize; ScsiResult tr;
        if(!Read10Chunk(dev,(DWORD)done,n,buf,bytes,&tr)){ TraceCdbJson(&tr); LogF(L"READ(10) failed at LBA %lu: status=%02X sense=%02X/%02X",(DWORD)done,tr.scsiStatus,tr.sense[12],tr.sense[13]);okAll=FALSE;break; }
        TraceCdbJson(&tr);
        DWORD wr=0;if(!WriteFile(out,buf,bytes,&wr,NULL)||wr!=bytes){LogF(L"Host image write failed at LBA %lu",(DWORD)done);okAll=FALSE;break;}
        done+=n; int pct=(int)((done*100ULL)/totalBlocks); if(pct!=lastPct){lastPct=pct;SetStatus(L"論理ストレージをバックアップ中...");LogF(L"Storage backup progress: %d%%",pct);FlushFileBuffers(out);}
        PumpMessages();
    }
    FlushFileBuffers(out);CloseHandle(out);CloseHandle(dev);VirtualFree(buf,0,MEM_RELEASE);
    if(okAll&&done==totalBlocks){MoveFileExW(partial,final,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);LogF(L"Logical storage image complete: %s",final);SetStatus(L"ストレージバックアップ完了");}
    else {LogF(L"Partial image retained for analysis: %s",partial);SetStatus(L"バックアップ途中で停止 — partialを保持しました");}
}

static BOOL SaveLog(void) {
    BOOL ok=TRUE;
    if(g_liveLog!=INVALID_HANDLE_VALUE) ok=FlushFileBuffers(g_liveLog)&&ok;
    if(g_jsonLog!=INVALID_HANDLE_VALUE) ok=FlushFileBuffers(g_jsonLog)&&ok;
    return ok;
}

static void VerifyFirmwareGui(void) {
    if (g_liveLog == INVALID_HANDLE_VALUE) StartSessionLogs();
    OPENFILENAMEW ofn; ZeroMemory(&ofn,sizeof(ofn));
    WCHAR path[MAX_PATH]={0};
    ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=g_hwnd; ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH;
    ofn.lpstrFilter=L"Sony Japanese updater (NW-E40X_V2_0J.exe)\0NW-E40X_V2_0J.exe\0All files\0*.*\0\0";
    ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_HIDEREADONLY;
    if(!GetOpenFileNameW(&ofn))return;
    FirmwarePackageResult r; WCHAR err[512]={0};
    LogF(L"");LogF(L"=== OFFICIAL FIRMWARE PACKAGE VERIFICATION ===");
    LogF(L"Selected: %s",path);
    if(VerifyAndExtractSonyFirmwarePackage(path,g_exeDir,&r,err,512)){
        LogF(L"Sony updater SHA-256: %s",r.packageSha256);
        LogF(L"UPG SHA-256: %s",r.upgSha256);
        LogF(L"Package size=%lu  UPG size=%lu",r.packageSize,r.upgSize);
        LogF(L"VERIFIED: exact Japanese NW-E405/E407 v2.0 package.");
        LogF(L"Verified UPG extracted to: %s",r.extractedPath);
        LogF(L"This operation writes only to the PC. Nothing was sent to the Walkman.");
        MessageBoxW(g_hwnd,L"Sony日本版NW-E405/E407 v2.0アップデータと完全一致しました。\n\nUPGをPC側の verified_firmware フォルダへ抽出しました。\n本体への書き込みは行っていません。",L"Firmware verified",MB_OK|MB_ICONINFORMATION);
    }else{
        LogF(L"REJECTED: %s",err);
        if(r.packageSha256[0])LogF(L"Selected file SHA-256: %s",r.packageSha256);
        MessageBoxW(g_hwnd,err,L"Firmware rejected",MB_OK|MB_ICONERROR);
    }
}

static void RunDiagnostics(void) {
    EnableWindow(g_scan, FALSE);
    if(g_backup)EnableWindow(g_backup,FALSE);
    SetWindowTextW(g_output, L"");
    g_mediaBackupAvailable=FALSE; g_backupDevicePath[0]=0; g_backupCapacityBytes=0; g_backupBlockSize=0;
    g_metaInquiryLen=g_metaFc03Len=g_metaFc05Len=g_metaFc09Len=0;
    if (!StartSessionLogs()) {
        SetStatus(L"診断中止 — TXT/JSONLログを作成できません");
        MessageBoxW(g_hwnd, L"安全ログ（TXT/JSONL）を作成できないため診断を開始しません。\n\n書き込み可能なフォルダへEXEを移して再実行してください。", L"Logging required", MB_OK | MB_ICONERROR);
        EnableWindow(g_scan, TRUE);
        return;
    }
    SetStatus(L"診断中... USBを抜かないでください");

    LogF(L"%s", APP_TITLE);
    LogF(L"Safety mode: READ-ONLY device diagnostics / backup research. FC/04 is not present.");
    LogHostEnvironment();
    LogF(L"");
    LogF(L"本体へのフォーマット、セクタ書込み、FW書込み、FC/04更新開始は実行しません。");
    LogF(L"FC/03, FC/05, FC/09 are Sony read/query commands reconstructed from the original updater DLL.");
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
    SaveMetadataBackup();
    LogF(L"TXT journal: %s",g_logPath);
    LogF(L"JSONL CDB trace: %s",g_jsonLogPath);
    LogF(L"診断完了。Issue #1へTXTとJSONLを添付してください。");
    SaveLog();
    if(g_mediaBackupAvailable){SetStatus(L"診断完了 — 論理ストレージのREAD(10)バックアップが可能です");EnableWindow(g_backup,TRUE);}
    else {SetStatus(L"診断完了 — No Mediaのため論理ストレージの丸ごとバックアップは不可");EnableWindow(g_backup,TRUE);}
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
                L"Recovery Lab / 本体側は読み取り専用。診断・バックアップ・純正FW検証を行います。",
                WS_CHILD | WS_VISIBLE, 20, 48, 720, 24, hwnd, NULL, NULL, NULL);
            SendMessageW(sub, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_scan = CreateWindowW(L"BUTTON", L"診断する",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                20, 80, 105, 38, hwnd, (HMENU)ID_SCAN, NULL, NULL);
            SendMessageW(g_scan, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_backup = CreateWindowW(L"BUTTON", L"ストレージ保存",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                135, 80, 125, 38, hwnd, (HMENU)ID_BACKUP, NULL, NULL);
            SendMessageW(g_backup, WM_SETFONT, (WPARAM)fNormal, TRUE);
            EnableWindow(g_backup, FALSE);

            HWND verify = CreateWindowW(L"BUTTON", L"純正FWを検証",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                270, 80, 125, 38, hwnd, (HMENU)ID_VERIFY_FW, NULL, NULL);
            SendMessageW(verify, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND copy = CreateWindowW(L"BUTTON", L"結果をコピー",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                405, 80, 105, 38, hwnd, (HMENU)ID_COPY, NULL, NULL);
            SendMessageW(copy, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND folder = CreateWindowW(L"BUTTON", L"ログフォルダ",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                520, 80, 105, 38, hwnd, (HMENU)ID_FOLDER, NULL, NULL);
            SendMessageW(folder, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND github = CreateWindowW(L"BUTTON", L"GitHub",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                635, 80, 80, 38, hwnd, (HMENU)ID_GITHUB, NULL, NULL);
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
                case ID_BACKUP: BackupLogicalMedia(); return 0;
                case ID_VERIFY_FW: VerifyFirmwareGui(); return 0;
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
            CloseSessionLogs();
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
