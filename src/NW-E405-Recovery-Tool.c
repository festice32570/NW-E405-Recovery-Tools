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

#define APP_TITLE L"NW-E405 Recovery Tool v0.8.2-dev"
#define SONY_VIDPID L"VID_054C&PID_01FB"
#define ID_SCAN 1001
#define ID_COPY 1002
#define ID_FOLDER 1003
#define ID_GITHUB 1004
#define ID_BACKUP 1005
#define ID_VERIFY_FW 1006
#define ID_RESCUE 1007
#define ID_OUTPUT 1101
#define ID_STATUS 1102

static HWND g_hwnd = NULL;
static HWND g_output = NULL;
static HWND g_status = NULL;
static HWND g_scan = NULL;
static HWND g_backup = NULL;
static HWND g_rescue = NULL;
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
static BOOL g_issue1TurNoMedia = FALSE;
static BOOL g_issue1CapNoMedia = FALSE;
static BOOL g_issue1FwInfoMatch = FALSE;
static BOOL g_officialFirmwareVerified = FALSE;
static WCHAR g_verifiedUpgPath[MAX_PATH] = {0};
static WCHAR g_exactDevicePath[1024] = {0};
static BOOL g_noMediaRescueAvailable = FALSE;
static BOOL g_lba0Unreadable = FALSE;
static BOOL g_rootPackageIntact = FALSE;
static BOOL g_resumeEligible = FALSE;
static BOOL g_vendorDvIdRead = FALSE;
static BYTE g_vendorDvId[16] = {0};
static WCHAR g_vendorDvIdSha256[65] = {0};
typedef enum { PROBE_NOT_ATTEMPTED=0, PROBE_DECLINED=1, PROBE_FAILED=2, PROBE_SUCCESS=3 } ProbeState;
typedef enum { A3A4_NOT_ATTEMPTED=0, A3A4_DECLINED=1, A3A4_FAILED=2, A3A4_SUCCESS=3, A3A4_BLOCKED_PREFLIGHT=4 } A3A4State;
typedef struct {
    BOOL attempted;
    BOOL ioctlOk;
    DWORD winErr;
    UCHAR scsiStatus;
    BYTE senseKey;
    BYTE asc;
    BYTE ascq;
    DWORD elapsedMs;
} PublicScsiSummary;
typedef struct {
    BOOL attempted;
    BOOL identityOk;
    BOOL tur3a00;
    BOOL cap3a00;
    BOOL fc03Known;
} PublicPreflightSummary;
static ProbeState g_fbPwStatState = PROBE_NOT_ATTEMPTED;
static ProbeState g_fbDevInfoState = PROBE_NOT_ATTEMPTED;
static A3A4State g_a3a4State = A3A4_NOT_ATTEMPTED;
static ProbeState g_stage2aPreflightState = PROBE_NOT_ATTEMPTED;
static ProbeState g_stage2bPreflightState = PROBE_NOT_ATTEMPTED;
static ProbeState g_stage2cPreflightState = PROBE_NOT_ATTEMPTED;
static ProbeState g_sonyIcdTargetState = PROBE_NOT_ATTEMPTED;
static PublicScsiSummary g_pubLba0 = {0};
static PublicScsiSummary g_pubFbPwStat = {0};
static PublicScsiSummary g_pubFbDevInfo = {0};
static PublicScsiSummary g_pubA3 = {0};
static PublicScsiSummary g_pubA4 = {0};
static PublicScsiSummary g_pubSonyIcdTarget = {0};
static PublicPreflightSummary g_pubStage2aPreflight = {0};
static PublicPreflightSummary g_pubStage2bPreflight = {0};
static PublicPreflightSummary g_pubStage2cPreflight = {0};
static BOOL g_fbPwStatOk = FALSE;
static BOOL g_fbDevInfoOk = FALSE;
static WCHAR g_fbPwStatSha256[65] = {0};
static WCHAR g_fbDevInfoSha256[65] = {0};
static BOOL g_sonyIcdResponseRead = FALSE;
static BOOL g_sonyIcdStatusValid = FALSE;
static BYTE g_sonyIcdStatus = 0;
static WCHAR g_sonyIcdTargetSha256[65] = {0};
static uint64_t g_rescueFreeBytes = 0;
static BOOL g_rescueFreeKnown = FALSE;
static WCHAR g_publicReportPath[MAX_PATH] = {0};

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
    LONG traceSeq;
    int direction; /* 0=none, 1=in, 2=out */
} ScsiResult;

static void CapturePublicScsiSummary(PublicScsiSummary *dst, const ScsiResult *src) {
    if(!dst || !src) return;
    ZeroMemory(dst,sizeof(*dst));
    dst->attempted=TRUE;
    dst->ioctlOk=src->ioctlOk;
    dst->winErr=src->winErr;
    dst->scsiStatus=src->scsiStatus;
    dst->senseKey=(BYTE)(src->sense[2]&0x0F);
    dst->asc=src->sense[12];
    dst->ascq=src->sense[13];
    dst->elapsedMs=src->elapsedMs;
}

typedef struct {
    BOOL valid;
    DWORD volumeStartLba;
    DWORD bytesPerSector;
    DWORD sectorsPerCluster;
    DWORD reservedSectors;
    DWORD fatCount;
    DWORD rootEntryCount;
    DWORD totalSectors;
    DWORD sectorsPerFat;
    DWORD rootDirSectors;
    DWORD firstDataSector;
    DWORD rootCluster;
    int fatType;
} FatLayout;

static void TraceCdbIntentJson(const ScsiResult *r);
static void TraceCdbJson(const ScsiResult *r);
static BOOL StartSessionLogs(void);
static void CloseSessionLogs(void);
static void SaveMetadataBackup(void);
static BOOL SaveLog(void);
static void SavePublicReport(void);
static void RunRecoveryLadder(void);

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
    if (g_liveLog == INVALID_HANDLE_VALUE || g_jsonLog == INVALID_HANDLE_VALUE) {
        CloseSessionLogs();
        return FALSE;
    }
    { DWORD wr=0; BYTE bom[3]={0xEF,0xBB,0xBF}; WriteFile(g_liveLog,bom,3,&wr,NULL); FlushFileBuffers(g_liveLog); }
    g_cdbSequence = 0;
    return TRUE;
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
    r.cdbLen = cdbLen; r.targetId = targetId; r.requestedDataLen = dataLen; r.direction = dataLen ? 1 : 0;
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

    r.traceSeq = InterlockedIncrement(&g_cdbSequence);
    TraceCdbIntentJson(&r);
    DWORD ret = 0;
    DWORD started = GetTickCount();
    BOOL ok = DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &pkt, sizeof(pkt), &pkt, sizeof(pkt), &ret, NULL);
    r.elapsedMs = GetTickCount() - started;
    r.ioctlOk = ok;
    r.winErr = ok ? ERROR_SUCCESS : GetLastError();
    r.scsiStatus = pkt.sptd.ScsiStatus;
    CopyMemory(r.sense, pkt.sense, sizeof(r.sense));
    if (data && dataLen && ok) {
        DWORD actualLen = pkt.sptd.DataTransferLength;
        if (actualLen > dataLen) actualLen = dataLen;
        CopyMemory(r.data, data, actualLen);
        r.dataLen = actualLen;
    }
    if (data) HeapFree(GetProcessHeap(), 0, data);
    TraceCdbJson(&r);
    return r;
}

static ScsiResult SendCdb(HANDLE h, const BYTE *cdb, BYTE cdbLen, DWORD dataLen) {
    return SendCdbEx(h, cdb, cdbLen, dataLen, 0);
}


static void ShowScsiResult(const WCHAR *name, const ScsiResult *r);
static BOOL RevalidateIssue1State(HANDLE h, const WCHAR *label, PublicPreflightSummary *pub);

static ScsiResult SendFixedA3SelectDeviceId(HANDLE h) {
    ScsiResult r; ZeroMemory(&r,sizeof(r)); r.opened=TRUE;
    static const BYTE cdb[12]={0xA3,0,0,0,0,0,0,0xBC,0,0x14,0x30,0};
    BYTE payload[20]={0}; payload[1]=0x12;
    r.cdbLen=12; r.targetId=0; r.requestedDataLen=20; r.direction=2;
    CopyMemory(r.cdb,cdb,12); r.dataLen=20; CopyMemory(r.data,payload,20);
    r.traceSeq=InterlockedIncrement(&g_cdbSequence); TraceCdbIntentJson(&r);
    SPTDWB pkt; ZeroMemory(&pkt,sizeof(pkt));
    pkt.sptd.Length=sizeof(SCSI_PASS_THROUGH_DIRECT); pkt.sptd.PathId=0; pkt.sptd.TargetId=0; pkt.sptd.Lun=0;
    pkt.sptd.CdbLength=12; pkt.sptd.SenseInfoLength=18; pkt.sptd.DataIn=SCSI_IOCTL_DATA_OUT;
    pkt.sptd.DataTransferLength=20; pkt.sptd.TimeOutValue=5; pkt.sptd.DataBuffer=payload;
    pkt.sptd.SenseInfoOffset=offsetof(SPTDWB,sense); CopyMemory(pkt.sptd.Cdb,cdb,12);
    DWORD ret=0,started=GetTickCount();
    BOOL ok=DeviceIoControl(h,IOCTL_SCSI_PASS_THROUGH_DIRECT,&pkt,sizeof(pkt),&pkt,sizeof(pkt),&ret,NULL);
    r.elapsedMs=GetTickCount()-started; r.ioctlOk=ok; r.winErr=ok?ERROR_SUCCESS:GetLastError(); r.scsiStatus=pkt.sptd.ScsiStatus;
    CopyMemory(r.sense,pkt.sense,18); TraceCdbJson(&r); return r;
}

static BOOL Sha256BytesHex(const BYTE *data, DWORD len, WCHAR out[65]) {
    out[0]=0; HCRYPTPROV prov=0; HCRYPTHASH hash=0; BOOL ok=FALSE;
    if(!CryptAcquireContextW(&prov,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)) return FALSE;
    if(CryptCreateHash(prov,CALG_SHA_256,0,0,&hash) && CryptHashData(hash,data,len,0)){
        BYTE hv[32]; DWORD cb=32; if(CryptGetHashParam(hash,HP_HASHVAL,hv,&cb,0)&&cb==32){
            static const WCHAR hx[]=L"0123456789abcdef"; for(int i=0;i<32;i++){out[i*2]=hx[hv[i]>>4];out[i*2+1]=hx[hv[i]&15];}out[64]=0;ok=TRUE;
        }
    }
    if(hash)CryptDestroyHash(hash);CryptReleaseContext(prov,0);return ok;
}

static BOOL SavePrivateBlob(const WCHAR *tag, const BYTE *data, DWORD len, WCHAR hashOut[65]) {
    if(!data || !len || !hashOut) return FALSE;
    if(!Sha256BytesHex(data,len,hashOut)) return FALSE;
    WCHAR path[MAX_PATH];
    _snwprintf(path,MAX_PATH-1,L"%s\\NW-E405_%s_PRIVATE_%s.bin",g_exeDir,tag,g_sessionStem);
    HANDLE out=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
    if(out==INVALID_HANDLE_VALUE){LogF(L"PRIVATE %s evidence save failed: %lu",tag,GetLastError());return FALSE;}
    DWORD wr=0; BOOL ok=WriteFile(out,data,len,&wr,NULL)&&wr==len;
    if(ok)FlushFileBuffers(out);CloseHandle(out);
    if(ok)LogF(L"PRIVATE %s evidence saved: %s (SHA-256 %s)",tag,path,hashOut);
    return ok;
}

static void ProbeA600ReadOnlyVendorInfo(void) {
    g_fbPwStatOk=FALSE;g_fbDevInfoOk=FALSE;g_fbPwStatState=PROBE_NOT_ATTEMPTED;g_fbDevInfoState=PROBE_NOT_ATTEMPTED;g_stage2aPreflightState=PROBE_NOT_ATTEMPTED;
    ZeroMemory(&g_pubFbPwStat,sizeof(g_pubFbPwStat));ZeroMemory(&g_pubFbDevInfo,sizeof(g_pubFbDevInfo));ZeroMemory(&g_pubStage2aPreflight,sizeof(g_pubStage2aPreflight));
    g_fbPwStatSha256[0]=0;g_fbDevInfoSha256[0]=0;
    if(!g_exactDevicePath[0] || !(g_issue1TurNoMedia&&g_issue1CapNoMedia&&g_issue1FwInfoMatch)){
        LogF(L"FB vendor read probe locked: Issue #1 state is not currently established.");return;
    }
    g_stage2aPreflightState=PROBE_FAILED;
    HANDLE h=OpenDeviceRW(g_exactDevicePath,NULL);
    if(h==INVALID_HANDLE_VALUE){LogF(L"FB vendor read probe: device open failed %lu",GetLastError());return;}
    if(!RevalidateIssue1State(h,L"Stage 2A live preflight",&g_pubStage2aPreflight)){LogF(L"Stage 2A aborted: live Issue #1 state no longer matches.");CloseHandle(h);return;}
    g_stage2aPreflightState=PROBE_SUCCESS;
    LogF(L"");LogF(L"=== RECOVERY LADDER STAGE 2A: same-generation Sony read-only vendor probes ===");
    LogF(L"Experimental compatibility probe only: commands are proven from Sony NW-A600 FWUpdaterCom.dll, not from the NW-E405 updater.");
    LogF(L"Both commands are DATA IN only. No payload is sent to the player.");
    BYTE pwCdb[12]={0xFB,0,0,'P','W','_','S','T','A','T',0x20,0};
    g_fbPwStatState=PROBE_FAILED;
    ScsiResult pw=SendCdb(h,pwCdb,12,32);
    CapturePublicScsiSummary(&g_pubFbPwStat,&pw);
    ShowScsiResult(L"SONY FB/PW_STAT (A600 read-only compatibility probe)",&pw);
    if(pw.ioctlOk&&pw.scsiStatus==0&&pw.dataLen>=32){
        g_fbPwStatOk=TRUE;g_fbPwStatState=PROBE_SUCCESS;SavePrivateBlob(L"FB_PWSTAT",pw.data,32,g_fbPwStatSha256);
    }else LogF(L"FB/PW_STAT unsupported or failed on this device; no retry/write action follows.");
    BYTE diCdb[12]={0xFB,0,0,'D','E','V','I','N','F','O',0x80,0};
    g_fbDevInfoState=PROBE_FAILED;
    ScsiResult di=SendCdb(h,diCdb,12,128);
    CapturePublicScsiSummary(&g_pubFbDevInfo,&di);
    ShowScsiResult(L"SONY FB/DEVINFO (A600 read-only compatibility probe)",&di);
    if(di.ioctlOk&&di.scsiStatus==0&&di.dataLen>=128){
        g_fbDevInfoOk=TRUE;g_fbDevInfoState=PROBE_SUCCESS;SavePrivateBlob(L"FB_DEVINFO",di.data,128,g_fbDevInfoSha256);
    }else LogF(L"FB/DEVINFO unsupported or failed on this device; no retry/write action follows.");
    CloseHandle(h);
    LogF(L"FB compatibility result: PW_STAT=%s DEVINFO=%s",g_fbPwStatOk?L"GOOD":L"NO",g_fbDevInfoOk?L"GOOD":L"NO");
}

static BOOL QueryVendorDvId(void) {
    g_a3a4State=A3A4_BLOCKED_PREFLIGHT;g_stage2bPreflightState=PROBE_NOT_ATTEMPTED;
    ZeroMemory(&g_pubA3,sizeof(g_pubA3));ZeroMemory(&g_pubA4,sizeof(g_pubA4));ZeroMemory(&g_pubStage2bPreflight,sizeof(g_pubStage2bPreflight));
    if(!g_exactDevicePath[0] || !(g_issue1TurNoMedia&&g_issue1CapNoMedia&&g_issue1FwInfoMatch)){
        LogF(L"A3/A4 vendor query locked: Issue #1 state is not currently established."); return FALSE;
    }
    g_stage2bPreflightState=PROBE_FAILED;
    HANDLE h=OpenDeviceRW(g_exactDevicePath,NULL); if(h==INVALID_HANDLE_VALUE){LogF(L"A3/A4: device open failed %lu",GetLastError());return FALSE;}
    if(!RevalidateIssue1State(h,L"Stage 2B live preflight",&g_pubStage2bPreflight)){LogF(L"Stage 2B aborted: live Issue #1 state no longer matches.");CloseHandle(h);return FALSE;}
    g_stage2bPreflightState=PROBE_SUCCESS;g_a3a4State=A3A4_FAILED;
    LogF(L"");LogF(L"=== RECOVERY LADDER STAGE 2B: Sony MP3FM A3/A4 Device-ID query ===");
    LogF(L"A3/A4 sequence is fixed to the NW-E405 capture: A3 selects the 18-byte record; A4 reads it.");
    LogF(L"A3 is the only DATA OUT command in this build; payload is fixed to 00 12 followed by zeros.");
    ScsiResult sel=SendFixedA3SelectDeviceId(h);
    CapturePublicScsiSummary(&g_pubA3,&sel);
    LogF(L"A3 select: IOCTL=%s SCSI=0x%02X Sense=%02X/%02X",sel.ioctlOk?L"OK":L"FAIL",sel.scsiStatus,sel.sense[12],sel.sense[13]);
    if(!sel.ioctlOk || sel.scsiStatus!=0){CloseHandle(h);LogF(L"A3 select failed; A4 was NOT sent.");return FALSE;}
    BYTE cdb[12]={0xA4,0,0,0,0,0,0,0xBC,0,0x12,0x3F,0};
    ScsiResult rd=SendCdb(h,cdb,12,18); CapturePublicScsiSummary(&g_pubA4,&rd); CloseHandle(h);
    LogF(L"A4 read: IOCTL=%s SCSI=0x%02X Sense=%02X/%02X DataLen=%lu",rd.ioctlOk?L"OK":L"FAIL",rd.scsiStatus,rd.sense[12],rd.sense[13],rd.dataLen);
    if(!rd.ioctlOk || rd.scsiStatus!=0 || rd.dataLen<18 || rd.data[0]!=0x00 || rd.data[1]!=0x10){LogF(L"A4 response did not match the expected 00 10 + 16-byte record shape.");return FALSE;}
    BOOL nz=FALSE;for(int i=2;i<18;i++)if(rd.data[i])nz=TRUE;if(!nz){LogF(L"A4 returned an all-zero Device-ID record.");return FALSE;}
    CopyMemory(g_vendorDvId,rd.data+2,16);g_vendorDvIdRead=TRUE;g_a3a4State=A3A4_SUCCESS;Sha256BytesHex(g_vendorDvId,16,g_vendorDvIdSha256);
    WCHAR path[MAX_PATH];_snwprintf(path,MAX_PATH-1,L"%s\\NW-E405_DvID_PRIVATE_%s.bin",g_exeDir,g_sessionStem);
    HANDLE out=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
    if(out!=INVALID_HANDLE_VALUE){DWORD wr=0;WriteFile(out,g_vendorDvId,16,&wr,NULL);FlushFileBuffers(out);CloseHandle(out);}
    LogF(L"A3/A4 Device-ID query SUCCESS. Device-ID SHA-256: %s",g_vendorDvIdSha256);
    LogF(L"PRIVATE evidence saved: %s",path);
    LogF(L"Do NOT post the private DvID file or raw JSONL trace to a public GitHub issue.");
    return TRUE;
}

static void ProbeSonyIcdTargetIdentifier(void) {
    g_sonyIcdTargetState=PROBE_NOT_ATTEMPTED;g_stage2cPreflightState=PROBE_NOT_ATTEMPTED;
    g_sonyIcdResponseRead=FALSE;g_sonyIcdStatusValid=FALSE;g_sonyIcdStatus=0;g_sonyIcdTargetSha256[0]=0;
    ZeroMemory(&g_pubSonyIcdTarget,sizeof(g_pubSonyIcdTarget));ZeroMemory(&g_pubStage2cPreflight,sizeof(g_pubStage2cPreflight));
    if(!g_exactDevicePath[0] || !(g_issue1TurNoMedia&&g_issue1CapNoMedia&&g_issue1FwInfoMatch)){
        LogF(L"SONYICD 0x01 probe locked: Issue #1 state is not currently established.");return;
    }
    g_stage2cPreflightState=PROBE_FAILED;
    HANDLE h=OpenDeviceRW(g_exactDevicePath,NULL);
    if(h==INVALID_HANDLE_VALUE){LogF(L"SONYICD 0x01: device open failed %lu",GetLastError());return;}
    if(!RevalidateIssue1State(h,L"Stage 2C live preflight",&g_pubStage2cPreflight)){LogF(L"Stage 2C aborted: live Issue #1 state no longer matches.");CloseHandle(h);return;}
    g_stage2cPreflightState=PROBE_SUCCESS;g_sonyIcdTargetState=PROBE_FAILED;
    LogF(L"");LogF(L"=== RECOVERY LADDER STAGE 2C: E405-native SONYICD GetTargetIdentifier ===");
    LogF(L"Fixed CDB from Sony MP3 File Manager IcdMSCom.dll; DATA IN 0x74 bytes only. No payload is sent to the player.");
    LogF(L"Raw response is PRIVATE. No identifier strings or decoded fields are written to the public report.");
    BYTE cdb[12]={0xFC,0,0x01,'S','O','N','Y','I','C','D',0x00,0x74};
    ScsiResult rd=SendCdb(h,cdb,12,0x74);CapturePublicScsiSummary(&g_pubSonyIcdTarget,&rd);CloseHandle(h);
    ShowScsiResult(L"SONYICD 0x01 GetTargetIdentifier (E405-native read-only probe)",&rd);
    if(!rd.ioctlOk || rd.scsiStatus!=0 || rd.dataLen!=0x74){
        LogF(L"SONYICD 0x01 did not return a complete 0x74-byte SCSI-GOOD response; no response fields are interpreted and no retry/write action follows.");return;
    }
    g_sonyIcdResponseRead=TRUE;g_sonyIcdStatusValid=TRUE;g_sonyIcdStatus=rd.data[0x0F];
    SavePrivateBlob(L"SONYICD_TARGETID",rd.data,0x74,g_sonyIcdTargetSha256);
    LogF(L"SONYICD 0x01 complete response received. Device status byte[0x0F]=0x%02X; response SHA-256=%s",g_sonyIcdStatus,g_sonyIcdTargetSha256);
    if(g_sonyIcdStatus==0){
        g_sonyIcdTargetState=PROBE_SUCCESS;
        LogF(L"SONYICD application status is zero. Raw/decoded identifier fields remain private and are not displayed.");
    }else{
        LogF(L"SONYICD application status is nonzero; Sony's original code returns this status without parsing identifier fields.");
    }
}

static void TraceCdbIntentJson(const ScsiResult *r) {
    if (!r || g_jsonLog == INVALID_HANDLE_VALUE) return;
    WCHAR cdbHex[96]={0}; char cdbA[192]={0}, line[1024];
    BytesToHex(r->cdb, r->cdbLen, cdbHex, 96);
    WideCharToMultiByte(CP_UTF8,0,cdbHex,-1,cdbA,sizeof(cdbA),NULL,NULL);
    SYSTEMTIME st; GetLocalTime(&st);
    int n=_snprintf(line,sizeof(line)-1,
        "{\"seq\":%ld,\"phase\":\"intent\",\"time\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03u\",\"target\":%u,\"cdb\":\"%s\",\"direction\":\"%s\",\"requested_data\":%lu}\r\n",
        r->traceSeq,st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds,
        r->targetId,cdbA,r->direction==2?"OUT":(r->direction==1?"IN":"NONE"),r->requestedDataLen);
    if (n>0) { DWORD wr=0; WriteFile(g_jsonLog,line,(DWORD)n,&wr,NULL); FlushFileBuffers(g_jsonLog); }
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
    int n=_snprintf(line,sizeof(line)-1,
        "{\"seq\":%ld,\"phase\":\"result\",\"time\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03u\",\"target\":%u,\"cdb\":\"%s\",\"direction\":\"%s\",\"requested_data\":%lu,\"ioctl_ok\":%s,\"win32\":%lu,\"scsi_status\":%u,\"sense\":\"%s\",\"data\":\"%s\",\"elapsed_ms\":%lu}\r\n",
        r->traceSeq,st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds,
        r->targetId,cdbA,r->direction==2?"OUT":(r->direction==1?"IN":"NONE"),r->requestedDataLen,r->ioctlOk?"true":"false",r->winErr,r->scsiStatus,senseA,dataA,r->elapsedMs);
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

static BOOL IsSense3A00(const ScsiResult *r) {
    return r && r->ioctlOk && r->scsiStatus == 0x02 &&
           ((r->sense[2] & 0x0F) == 0x02) && r->sense[12] == 0x3A && r->sense[13] == 0x00;
}

static BOOL IsKnownIssue1FwInfo(const ScsiResult *r) {
    static const BYTE known[8] = {0x01,0x00,0x0D,0x00,0x20,0x02,0x00,0x00};
    return r && r->ioctlOk && r->scsiStatus == 0x00 && r->dataLen >= 8 &&
           memcmp(r->data, known, sizeof(known)) == 0;
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

static BOOL IsExactUsbPresentSilent(void) {
    HDEVINFO set=SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_PRESENT|DIGCF_ALLCLASSES); if(set==INVALID_HANDLE_VALUE)return FALSE;
    BOOL exact=FALSE; SP_DEVINFO_DATA dev;dev.cbSize=sizeof(dev);
    for(DWORD i=0;SetupDiEnumDeviceInfo(set,i,&dev);++i){WCHAR ids[2048]={0};DWORD type=0,req=0;
        if(SetupDiGetDeviceRegistryPropertyW(set,&dev,SPDRP_HARDWAREID,&type,(PBYTE)ids,sizeof(ids),&req)&&ContainsI(ids,SONY_VIDPID)){exact=TRUE;break;}dev.cbSize=sizeof(dev);}
    SetupDiDestroyDeviceInfoList(set);return exact;
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
    if (exactMapped) {
        g_metaInquiryLen = inq.dataLen > 96 ? 96 : inq.dataLen;
        CopyMemory(g_metaInquiry, inq.data, g_metaInquiryLen);
        lstrcpynW(g_exactDevicePath, path, 1024);
    }
    LogF(L"");

    ShowScsiResult(L"SCSI INQUIRY", &inq);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x00;
    ScsiResult tur = SendCdb(h, cdb, 6, 0);
    ShowScsiResult(L"TEST UNIT READY", &tur);
    if (exactMapped && IsSense3A00(&tur)) g_issue1TurNoMedia = TRUE;

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x03;
    cdb[4] = 64;
    ScsiResult rs = SendCdb(h, cdb, 6, 64);
    ShowScsiResult(L"REQUEST SENSE", &rs);

    ZeroMemory(cdb, sizeof(cdb));
    cdb[0] = 0x25;
    ScsiResult cap = SendCdb(h, cdb, 10, 8);
    ShowScsiResult(L"READ CAPACITY(10)", &cap);
    if (exactMapped && IsSense3A00(&cap)) g_issue1CapNoMedia = TRUE;
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
            if (IsKnownIssue1FwInfo(&sonyInfo)) g_issue1FwInfoMatch = TRUE;
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
    if (summary) {
        ZeroMemory(summary,sizeof(*summary)); summary->opened=TRUE; summary->cdbLen=10; summary->targetId=0;
        summary->requestedDataLen=bytes; summary->direction=1; CopyMemory(summary->cdb,cdb,10);
        summary->traceSeq=InterlockedIncrement(&g_cdbSequence); TraceCdbIntentJson(summary);
    }
    DWORD ret=0,started=GetTickCount();
    BOOL ok=DeviceIoControl(h,IOCTL_SCSI_PASS_THROUGH_DIRECT,&pkt,sizeof(pkt),&pkt,sizeof(pkt),&ret,NULL);
    if (summary) { summary->ioctlOk=ok; summary->winErr=ok?0:GetLastError(); summary->scsiStatus=pkt.sptd.ScsiStatus; summary->elapsedMs=GetTickCount()-started; CopyMemory(summary->sense,pkt.sense,18); }
    return ok && pkt.sptd.ScsiStatus==0;
}


static WORD Le16(const BYTE *p) { return (WORD)(p[0] | ((WORD)p[1] << 8)); }
static DWORD Le32(const BYTE *p) { return (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24); }
static BOOL IsPowerOfTwoDword(DWORD v) { return v && ((v & (v - 1)) == 0); }

static BOOL ParseFatBootSector(const BYTE sec[512], DWORD volumeStartLba, FatLayout *out) {
    if (!sec || !out) return FALSE;
    ZeroMemory(out, sizeof(*out));
    if (sec[510] != 0x55 || sec[511] != 0xAA) return FALSE;
    DWORD bps = Le16(sec + 11);
    DWORD spc = sec[13];
    DWORD reserved = Le16(sec + 14);
    DWORD fats = sec[16];
    DWORD rootEntries = Le16(sec + 17);
    DWORD total = Le16(sec + 19); if (!total) total = Le32(sec + 32);
    DWORD spf = Le16(sec + 22); if (!spf) spf = Le32(sec + 36);
    if (bps != 512 || !IsPowerOfTwoDword(spc) || spc > 128 || reserved == 0 ||
        fats == 0 || fats > 2 || total < 32 || spf == 0) return FALSE;
    DWORD rootDirSectors = ((rootEntries * 32u) + (bps - 1u)) / bps;
    uint64_t firstData64 = (uint64_t)reserved + (uint64_t)fats * spf + rootDirSectors;
    if (firstData64 >= total || firstData64 > 0xFFFFFFFFu) return FALSE;
    DWORD firstData = (DWORD)firstData64;
    DWORD dataSectors = total - firstData;
    DWORD clusters = dataSectors / spc;
    int type = (clusters < 4085) ? 12 : ((clusters < 65525) ? 16 : 32);
    DWORD rootCluster = (type == 32) ? Le32(sec + 44) : 0;
    if (type == 32 && rootCluster < 2) return FALSE;
    out->valid = TRUE; out->volumeStartLba = volumeStartLba; out->bytesPerSector = bps;
    out->sectorsPerCluster = spc; out->reservedSectors = reserved; out->fatCount = fats;
    out->rootEntryCount = rootEntries; out->totalSectors = total; out->sectorsPerFat = spf;
    out->rootDirSectors = rootDirSectors; out->firstDataSector = firstData;
    out->rootCluster = rootCluster; out->fatType = type;
    return TRUE;
}

static BOOL ReadHostAt(HANDLE h, uint64_t offset, void *buf, DWORD len) {
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return FALSE;
    BYTE *p = (BYTE*)buf; DWORD total = 0;
    while (total < len) { DWORD got = 0; if (!ReadFile(h, p + total, len - total, &got, NULL) || !got) return FALSE; total += got; }
    return TRUE;
}

static BOOL Sha256FileHexLocal(const WCHAR *path, WCHAR out[65]) {
    out[0] = 0;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    HCRYPTPROV prov = 0; HCRYPTHASH hash = 0; BOOL ok = FALSE;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CloseHandle(f); return FALSE; }
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) { CryptReleaseContext(prov,0); CloseHandle(f); return FALSE; }
    BYTE *buf = (BYTE*)VirtualAlloc(NULL, 1024*1024, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (buf) {
        for (;;) { DWORD got=0; if (!ReadFile(f,buf,1024*1024,&got,NULL)) break; if (!got) { ok=TRUE; break; } if (!CryptHashData(hash,buf,got,0)) { ok=FALSE; break; } }
        VirtualFree(buf,0,MEM_RELEASE);
    }
    if (ok) {
        BYTE hv[32]; DWORD cb=32;
        if (!CryptGetHashParam(hash,HP_HASHVAL,hv,&cb,0) || cb!=32) ok=FALSE;
        else { static const WCHAR hx[]=L"0123456789abcdef"; for(int i=0;i<32;i++){out[i*2]=hx[hv[i]>>4];out[i*2+1]=hx[hv[i]&15];} out[64]=0; }
    }
    CryptDestroyHash(hash); CryptReleaseContext(prov,0); CloseHandle(f); return ok;
}

static BOOL FatReadNextCluster(HANDLE img, const FatLayout *f, DWORD cluster, DWORD *next) {
    uint64_t fatBase = ((uint64_t)f->volumeStartLba + f->reservedSectors) * 512ULL;
    BYTE b[4] = {0}; DWORD v = 0;
    if (f->fatType == 12) {
        uint64_t off = fatBase + cluster + cluster/2;
        if (!ReadHostAt(img, off, b, 2)) return FALSE;
        v = Le16(b); v = (cluster & 1) ? (v >> 4) : (v & 0x0FFF);
    } else if (f->fatType == 16) {
        if (!ReadHostAt(img, fatBase + (uint64_t)cluster*2, b, 2)) return FALSE;
        v = Le16(b);
    } else {
        if (!ReadHostAt(img, fatBase + (uint64_t)cluster*4, b, 4)) return FALSE;
        v = Le32(b) & 0x0FFFFFFF;
    }
    *next = v; return TRUE;
}

static BOOL FatCountFreeBytes(HANDLE img, const FatLayout *f, uint64_t *freeBytes) {
    if(!img || !f || !f->valid || !freeBytes) return FALSE;
    DWORD dataSectors=f->totalSectors-f->firstDataSector;
    DWORD clusters=dataSectors/f->sectorsPerCluster;
    uint64_t freeClusters=0;
    for(DWORD c=2;c<clusters+2;c++){DWORD v=0;if(!FatReadNextCluster(img,f,c,&v))return FALSE;if(v==0)freeClusters++;}
    *freeBytes=freeClusters*(uint64_t)f->sectorsPerCluster*512ULL;return TRUE;
}

static BOOL FatIsEoc(const FatLayout *f, DWORD c) {
    if (f->fatType == 12) return c >= 0x0FF8;
    if (f->fatType == 16) return c >= 0xFFF8;
    return c >= 0x0FFFFFF8;
}

static uint64_t FatClusterOffset(const FatLayout *f, DWORD cluster) {
    uint64_t lba = (uint64_t)f->volumeStartLba + f->firstDataSector +
        (uint64_t)(cluster - 2) * f->sectorsPerCluster;
    return lba * 512ULL;
}

static BOOL FindRootUpg(HANDLE img, const FatLayout *f, DWORD *firstCluster, DWORD *fileSize) {
    static const BYTE target[11] = {'M','S','F','W','U','P','G','R','U','P','G'};
    BYTE sec[512];
    if (f->fatType != 32) {
        DWORD rootStart = f->volumeStartLba + f->reservedSectors + f->fatCount * f->sectorsPerFat;
        for (DWORD s=0; s<f->rootDirSectors; ++s) {
            if (!ReadHostAt(img, (uint64_t)(rootStart+s)*512ULL, sec, 512)) return FALSE;
            for (int o=0;o<512;o+=32) {
                BYTE *e=sec+o; if(e[0]==0x00)return FALSE; if(e[0]==0xE5 || e[11]==0x0F)continue;
                if(!memcmp(e,target,11)){*firstCluster=Le16(e+26);*fileSize=Le32(e+28);return TRUE;}
            }
        }
        return FALSE;
    }
    DWORD cluster=f->rootCluster; DWORD guard=0; DWORD clusterBytes=f->sectorsPerCluster*512;
    BYTE *buf=(BYTE*)VirtualAlloc(NULL,clusterBytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(!buf)return FALSE;
    BOOL found=FALSE;
    while(cluster>=2 && !FatIsEoc(f,cluster) && guard++<131072){
        if(!ReadHostAt(img,FatClusterOffset(f,cluster),buf,clusterBytes))break;
        for(DWORD o=0;o<clusterBytes;o+=32){BYTE *e=buf+o;if(e[0]==0x00)goto done;if(e[0]==0xE5||e[11]==0x0F)continue;
            if(!memcmp(e,target,11)){*firstCluster=((DWORD)Le16(e+20)<<16)|Le16(e+26);*fileSize=Le32(e+28);found=TRUE;goto done;}}
        DWORD n=0;if(!FatReadNextCluster(img,f,cluster,&n))break;cluster=n;
    }
done: VirtualFree(buf,0,MEM_RELEASE);return found;
}

static BOOL ExtractRootUpgFromImage(const WCHAR *imagePath, const FatLayout *f, WCHAR outPath[MAX_PATH], WCHAR hashOut[65]) {
    HANDLE img=CreateFileW(imagePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(img==INVALID_HANDLE_VALUE)return FALSE;
    DWORD cluster=0,size=0;
    if(!FindRootUpg(img,f,&cluster,&size) || cluster<2 || size==0 || size>16*1024*1024){CloseHandle(img);return FALSE;}
    _snwprintf(outPath,MAX_PATH-1,L"%s\\NW-E405_recovered_MSFWUPGR_%s.UPG",g_exeDir,g_sessionStem);
    HANDLE out=CreateFileW(outPath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
    if(out==INVALID_HANDLE_VALUE){CloseHandle(img);return FALSE;}
    DWORD clusterBytes=f->sectorsPerCluster*512; BYTE *buf=(BYTE*)VirtualAlloc(NULL,clusterBytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    BOOL ok=buf!=NULL; DWORD remain=size,guard=0;
    while(ok && remain && cluster>=2 && !FatIsEoc(f,cluster) && guard++<131072){
        if(!ReadHostAt(img,FatClusterOffset(f,cluster),buf,clusterBytes)){ok=FALSE;break;}
        DWORD n=remain<clusterBytes?remain:clusterBytes,wr=0;if(!WriteFile(out,buf,n,&wr,NULL)||wr!=n){ok=FALSE;break;}remain-=n;
        if(!remain)break;DWORD next=0;if(!FatReadNextCluster(img,f,cluster,&next)){ok=FALSE;break;}cluster=next;
    }
    if(remain)ok=FALSE; if(buf)VirtualFree(buf,0,MEM_RELEASE); FlushFileBuffers(out);CloseHandle(out);CloseHandle(img);
    if(!ok){LogF(L"FAT extraction of MSFWUPGR.UPG failed; partial file retained: %s",outPath);return FALSE;}
    if(!Sha256FileHexLocal(outPath,hashOut))hashOut[0]=0;
    return TRUE;
}

static BOOL ExtractContiguousUpgCandidate(const WCHAR *imagePath, uint64_t offset, WCHAR outPath[MAX_PATH], WCHAR hashOut[65]) {
    const DWORD size=2131380u;
    HANDLE in=CreateFileW(imagePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(in==INVALID_HANDLE_VALUE)return FALSE;
    _snwprintf(outPath,MAX_PATH-1,L"%s\\NW-E405_raw_UPG_candidate_%s.UPG",g_exeDir,g_sessionStem);
    HANDLE out=CreateFileW(outPath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);if(out==INVALID_HANDLE_VALUE){CloseHandle(in);return FALSE;}
    BYTE *buf=(BYTE*)VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);BOOL ok=buf!=NULL;DWORD remain=size;uint64_t pos=offset;
    while(ok&&remain){DWORD n=remain>1024*1024?1024*1024:remain;if(!ReadHostAt(in,pos,buf,n)){ok=FALSE;break;}DWORD wr=0;if(!WriteFile(out,buf,n,&wr,NULL)||wr!=n){ok=FALSE;break;}pos+=n;remain-=n;}
    if(buf)VirtualFree(buf,0,MEM_RELEASE);FlushFileBuffers(out);CloseHandle(out);CloseHandle(in);if(!ok)return FALSE;
    if(!Sha256FileHexLocal(outPath,hashOut))hashOut[0]=0;return TRUE;
}

static BOOL ScanImageForUpg(const WCHAR *imagePath, WCHAR outPath[MAX_PATH], WCHAR hashOut[65], uint64_t *foundOffset) {
    HANDLE h=CreateFileW(imagePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);if(h==INVALID_HANDLE_VALUE)return FALSE;
    LARGE_INTEGER sz;if(!GetFileSizeEx(h,&sz)){CloseHandle(h);return FALSE;}
    const DWORD chunk=1024*1024,overlap=0x40;BYTE *buf=(BYTE*)VirtualAlloc(NULL,chunk+overlap,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!buf){CloseHandle(h);return FALSE;}
    uint64_t base=0;DWORD carry=0;BOOL found=FALSE;uint64_t off=0;
    while(base<(uint64_t)sz.QuadPart){LARGE_INTEGER li;li.QuadPart=(LONGLONG)base;SetFilePointerEx(h,li,NULL,FILE_BEGIN);DWORD got=0;if(!ReadFile(h,buf+carry,chunk,&got,NULL)||!got)break;DWORD total=carry+got;
        for(DWORD i=0;i+0x28<=total;i++){if(!memcmp(buf+i,"UPGR_FMT",8)&&!memcmp(buf+i+0x10,"SONY",4)&&!memcmp(buf+i+0x20,"00100000",8)){off=base-(uint64_t)carry+i;found=TRUE;break;}}
        if(found)break;carry=total<overlap?total:overlap;memmove(buf,buf+total-carry,carry);base+=got;}
    VirtualFree(buf,0,MEM_RELEASE);CloseHandle(h);if(!found)return FALSE;*foundOffset=off;return ExtractContiguousUpgCandidate(imagePath,off,outPath,hashOut);
}

static BOOL ImageDerivedLayout(HANDLE dev, const FatLayout *f, WCHAR finalPath[MAX_PATH]) {
    uint64_t totalSectors=(uint64_t)f->volumeStartLba+f->totalSectors;
    uint64_t totalBytes=totalSectors*512ULL;
    if(totalSectors==0 || totalSectors>0xFFFFFFFFULL || totalBytes>2ULL*1024*1024*1024){LogF(L"Derived image size rejected: %I64u bytes",totalBytes);return FALSE;}
    WCHAR partial[MAX_PATH];_snwprintf(partial,MAX_PATH-1,L"%s\\NW-E405_rescue_%s.img.partial",g_exeDir,g_sessionStem);_snwprintf(finalPath,MAX_PATH-1,L"%s\\NW-E405_rescue_%s.img",g_exeDir,g_sessionStem);
    HANDLE out=CreateFileW(partial,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);if(out==INVALID_HANDLE_VALUE)return FALSE;
    BYTE *buf=(BYTE*)VirtualAlloc(NULL,64*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!buf){CloseHandle(out);return FALSE;}
    uint64_t lba=0;BOOL ok=TRUE;int lastPct=-1;
    while(lba<totalSectors){DWORD remain=(DWORD)(totalSectors-lba);WORD blocks=(WORD)(remain>128?128:remain);DWORD bytes=(DWORD)blocks*512;ScsiResult tr;
        if(!Read10Chunk(dev,(DWORD)lba,blocks,buf,bytes,&tr)){TraceCdbJson(&tr);LogF(L"Rescue image READ(10) failed at LBA %lu blocks=%u status=%02X sense=%02X/%02X",(DWORD)lba,blocks,tr.scsiStatus,tr.sense[12],tr.sense[13]);ok=FALSE;break;}TraceCdbJson(&tr);
        DWORD wr=0;if(!WriteFile(out,buf,bytes,&wr,NULL)||wr!=bytes){LogF(L"Host image write failed at LBA %lu",(DWORD)lba);ok=FALSE;break;}lba+=blocks;
        int pct=(int)((lba*100ULL)/totalSectors);if(pct!=lastPct){lastPct=pct;if((pct%5)==0||pct==100){LogF(L"Rescue image progress: %d%%",pct);FlushFileBuffers(out);}SetStatus(L"No Media救出イメージを作成中...");}PumpMessages();}
    FlushFileBuffers(out);CloseHandle(out);VirtualFree(buf,0,MEM_RELEASE);
    if(ok&&lba==totalSectors){if(!MoveFileExW(partial,finalPath,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){LogF(L"Could not finalize rescue image: %lu",GetLastError());return FALSE;}LogF(L"Rescue image complete: %s",finalPath);return TRUE;}
    LogF(L"Partial rescue image retained: %s",partial);return FALSE;
}

static void RescueNoMedia(void) {
    g_lba0Unreadable=FALSE; g_rootPackageIntact=FALSE; g_resumeEligible=FALSE; g_rescueFreeKnown=FALSE; g_rescueFreeBytes=0;
    if(!g_noMediaRescueAvailable || !g_exactDevicePath[0]){MessageBoxW(g_hwnd,L"先に診断を実行し、Issue #1のNo Media状態を確認してください。",L"Rescue locked",MB_OK|MB_ICONWARNING);return;}
    int ans=MessageBoxW(g_hwnd,L"No Media状態でもLBA0をREAD(10)で512バイトだけ直接読みます。\n\n本体への書き込みコマンドは一切送信しません。\nLBA0が読めた場合だけFAT/MBRを解析し、続けてイメージ救出を提案します。\n\n開始しますか？",L"No Media read-only rescue",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2);if(ans!=IDYES)return;
    HANDLE dev=OpenDeviceRW(g_exactDevicePath,NULL);if(dev==INVALID_HANDLE_VALUE){LogF(L"No Media rescue: device open failed %lu",GetLastError());return;}
    BYTE sec0[512];ZeroMemory(sec0,sizeof(sec0));ScsiResult tr;BOOL ok=Read10Chunk(dev,0,1,sec0,512,&tr);CapturePublicScsiSummary(&g_pubLba0,&tr);TraceCdbJson(&tr);
    LogF(L"");LogF(L"=== NO MEDIA DIRECT READ(10) RESCUE ===");ShowScsiResult(L"READ(10) LBA=0 blocks=1",&tr);
    if(!ok){g_lba0Unreadable=TRUE;LogF(L"LBA0 could not be read. The normal logical-NAND SCSI read path is unavailable in this state.");LogF(L"RECOVERY STATE: LOGICAL_MEDIA_UNREADABLE — next research path is Sony vendor access (A3/A4 and other read commands), then XBOOT/service ROM if needed.");CloseHandle(dev);SetStatus(L"No Media救出: LBA0も読み出せませんでした");return;}
    { WCHAR hx[512]={0}; BytesToHex(sec0,64,hx,512); LogF(L"LBA0 first 64 bytes: %s",hx); }
    WCHAR sectorPath[MAX_PATH];_snwprintf(sectorPath,MAX_PATH-1,L"%s\\NW-E405_LBA0_%s.bin",g_exeDir,g_sessionStem);HANDLE sf=CreateFileW(sectorPath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);if(sf!=INVALID_HANDLE_VALUE){DWORD wr=0;WriteFile(sf,sec0,512,&wr,NULL);FlushFileBuffers(sf);CloseHandle(sf);LogF(L"LBA0 saved: %s",sectorPath);}
    FatLayout fat;BOOL parsed=ParseFatBootSector(sec0,0,&fat);
    if(!parsed && sec0[510]==0x55 && sec0[511]==0xAA){
        for(int i=0;i<4&&!parsed;i++){BYTE *pe=sec0+446+i*16;DWORD start=Le32(pe+8),count=Le32(pe+12);if(pe[4]&&start&&count&&((uint64_t)start+count)<0x400000ULL){BYTE boot[512];ScsiResult br;if(Read10Chunk(dev,start,1,boot,512,&br)){TraceCdbJson(&br);parsed=ParseFatBootSector(boot,start,&fat);if(parsed && fat.totalSectors>count){LogF(L"Rejecting partition %d: BPB total sectors %lu exceeds MBR partition size %lu",i,fat.totalSectors,count);parsed=FALSE;}if(parsed)LogF(L"MBR partition %d selected: type=%02X start=%lu sectors=%lu",i,pe[4],start,count);}else TraceCdbJson(&br);}}
    }
    if(!parsed){LogF(L"LBA0 is readable, but a supported FAT12/16/32 geometry could not be derived. No bulk read attempted.");CloseHandle(dev);SetStatus(L"LBA0読出し成功 — FAT/MBR解析はできませんでした");return;}
    uint64_t bytes=(uint64_t)fat.totalSectors*512ULL;LogF(L"Derived FAT%d: volumeStart=%lu totalSectors=%lu (~%I64u bytes) SPC=%lu FATs=%lu SPF=%lu",fat.fatType,fat.volumeStartLba,fat.totalSectors,bytes,fat.sectorsPerCluster,fat.fatCount,fat.sectorsPerFat);
    WCHAR msg[512];_snwprintf(msg,511,L"LBA0の直接読み出しに成功しました。FAT%dとして約%I64u MiBを推定しました。\n\nREAD(10)だけで論理ストレージの救出イメージを作成しますか？\n本体への書き込みは行いません。",fat.fatType,bytes/(1024*1024));msg[511]=0;
    if(MessageBoxW(g_hwnd,msg,L"Create rescue image?",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES){CloseHandle(dev);return;}
    WCHAR imagePath[MAX_PATH];BOOL imaged=ImageDerivedLayout(dev,&fat,imagePath);CloseHandle(dev);if(!imaged){SetStatus(L"救出イメージは途中で停止しました（partial保持）");return;}
    { HANDLE ih=CreateFileW(imagePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); if(ih!=INVALID_HANDLE_VALUE){uint64_t fb=0;if(FatCountFreeBytes(ih,&fat,&fb)){g_rescueFreeKnown=TRUE;g_rescueFreeBytes=fb;LogF(L"FAT free space in rescued image: %I64u bytes",fb);}CloseHandle(ih);} }
    WCHAR upgPath[MAX_PATH]={0},hash[65]={0};BOOL got=ExtractRootUpgFromImage(imagePath,&fat,upgPath,hash);
    if(got){LogF(L"Recovered root MSFWUPGR.UPG: %s",upgPath);LogF(L"Recovered UPG SHA-256: %s",hash);if(!_wcsicmp(hash,L"82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691")){
            g_rootPackageIntact=TRUE; LogF(L"UPG COMPARISON: EXACT MATCH with verified Japanese v2.0 official UPG.");
            uint64_t clusterBytes=(uint64_t)fat.sectorsPerCluster*512ULL; uint64_t allocated=((2131380ULL+clusterBytes-1)/clusterBytes)*clusterBytes;
            uint64_t estimatedBefore=g_rescueFreeKnown?(g_rescueFreeBytes+allocated):0;
            if(g_rescueFreeKnown)LogF(L"Estimated free space before UPG copy: %I64u bytes (current free + UPG allocated clusters)",estimatedBefore);
            if(g_rescueFreeKnown && estimatedBefore>=3000000ULL){g_resumeEligible=TRUE;LogF(L"RECOVERY STATE: PACKAGE_INTACT — package intact and estimated pre-copy free space meets Sony's ~3 MB requirement.");}
            else{g_resumeEligible=FALSE;LogF(L"RECOVERY STATE: PACKAGE_INTACT_BUT_SPACE_UNCERTAIN — FC/04 retry remains locked.");}
        }else{LogF(L"UPG COMPARISON: DOES NOT MATCH verified Japanese v2.0 UPG.");LogF(L"RECOVERY STATE: PACKAGE_MISMATCH — do NOT start firmware update from this on-device package.");}}
    else {uint64_t off=0;if(ScanImageForUpg(imagePath,upgPath,hash,&off)){LogF(L"FAT root extraction failed, but raw UPGR_FMT candidate was found at image offset 0x%I64X",off);LogF(L"Raw candidate: %s",upgPath);LogF(L"Raw candidate SHA-256: %s",hash);if(!_wcsicmp(hash,L"82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691")){LogF(L"UPG COMPARISON: EXACT MATCH with verified Japanese v2.0 official UPG.");LogF(L"RECOVERY STATE: PACKAGE_INTACT_RAW — official package bytes are present even though FAT extraction failed.");}else{LogF(L"UPG COMPARISON: candidate header matches but SHA-256 differs from official v2.0.");LogF(L"RECOVERY STATE: PACKAGE_MISMATCH_RAW — do NOT use this candidate for update-start.");}}else{LogF(L"No MSFWUPGR.UPG root entry or raw UPGR_FMT candidate was found in the rescued image.");LogF(L"RECOVERY STATE: PACKAGE_NOT_FOUND — repair needs a verified way to restore the package or a lower-level flash transport.");}}
    SaveLog();SetStatus(L"No Media救出解析完了 — ログとIMG/UPG候補を確認してください");
    MessageBoxW(g_hwnd,L"No Media救出解析が完了しました。\n\nログフォルダにIMGと、見つかった場合はMSFWUPGR.UPG候補を保存しました。\nGitHub Issue #1へ添付するのは NW-E405_PUBLIC_REPORT_*.txt だけにしてください。TXT/JSONL、IMG、UPG候補はPRIVATE扱いです。",L"Rescue analysis complete",MB_OK|MB_ICONINFORMATION);
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

static const WCHAR *ProbeStateLabel(ProbeState state) {
    if(state==PROBE_SUCCESS)return L"PASS";
    if(state==PROBE_FAILED)return L"FAIL";
    if(state==PROBE_DECLINED)return L"DECLINED";
    return L"NOT ATTEMPTED";
}

static void WritePublicPreflightSummary(HANDLE h, const WCHAR *label, ProbeState state, const PublicPreflightSummary *x) {
    WCHAR b[512];
    if(!x || !x->attempted){_snwprintf(b,511,L"%s: %s",label,ProbeStateLabel(state));WriteUtf8Line(h,b);return;}
    _snwprintf(b,511,L"%s: %s identity=%s TUR3A00=%s CAP3A00=%s FC03-known=%s",label,ProbeStateLabel(state),
        x->identityOk?L"YES":L"NO",x->tur3a00?L"YES":L"NO",x->cap3a00?L"YES":L"NO",x->fc03Known?L"YES":L"NO");
    WriteUtf8Line(h,b);
}

static void WritePublicScsiSummary(HANDLE h, const WCHAR *label, const PublicScsiSummary *x) {
    WCHAR b[512];
    if(!x || !x->attempted){_snwprintf(b,511,L"%s: NOT ATTEMPTED",label);WriteUtf8Line(h,b);return;}
    _snwprintf(b,511,L"%s: IOCTL=%s Win32=%lu SCSI=0x%02X Sense=%02X/%02X/%02X Elapsed=%lu ms",
        label,x->ioctlOk?L"OK":L"FAIL",x->winErr,x->scsiStatus,x->senseKey,x->asc,x->ascq,x->elapsedMs);
    WriteUtf8Line(h,b);
}

static void SavePublicReport(void) {
    if(!g_sessionStem[0])return;
    _snwprintf(g_publicReportPath,MAX_PATH-1,L"%s\\NW-E405_PUBLIC_REPORT_%s.txt",g_exeDir,g_sessionStem);
    HANDLE h=CreateFileW(g_publicReportPath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
    if(h==INVALID_HANDLE_VALUE)return;
    DWORD wr=0;BYTE bom[3]={0xEF,0xBB,0xBF};WriteFile(h,bom,3,&wr,NULL);
    WriteUtf8Line(h,L"NW-E405 Recovery Tool v0.8.2-dev - PUBLIC REPORT");
    WriteUtf8Line(h,L"Safe to attach to the public GitHub Issue: contains no raw DvID/SONYICD response, image sectors, music data, or full vendor responses.");
    WCHAR b[512];
    _snwprintf(b,511,L"Exact USB/SCSI identity: %s",g_exactDevicePath[0]?L"YES":L"NO");WriteUtf8Line(h,b);
    _snwprintf(b,511,L"TUR Medium Not Present 3A00: %s",g_issue1TurNoMedia?L"YES":L"NO");WriteUtf8Line(h,b);
    _snwprintf(b,511,L"READ CAPACITY Medium Not Present 3A00: %s",g_issue1CapNoMedia?L"YES":L"NO");WriteUtf8Line(h,b);
    _snwprintf(b,511,L"Known FC/03 1.x response: %s",g_issue1FwInfoMatch?L"YES":L"NO");WriteUtf8Line(h,b);
    _snwprintf(b,511,L"LBA0 unreadable: %s",g_lba0Unreadable?L"YES":L"NO");WriteUtf8Line(h,b);
    WritePublicScsiSummary(h,L"LBA0 READ(10) result",&g_pubLba0);
    if(g_lba0Unreadable) WriteUtf8Line(h,L"Recovery branch: LOGICAL_MEDIA_UNREADABLE");
    if(g_lba0Unreadable) WriteUtf8Line(h,L"Root MSFWUPGR.UPG exact official match: NOT CHECKED (LBA0 unreadable)");
    else {_snwprintf(b,511,L"Root MSFWUPGR.UPG exact official match: %s",g_rootPackageIntact?L"YES":L"NO");WriteUtf8Line(h,b);}
    if(g_rescueFreeKnown){_snwprintf(b,511,L"Rescued FAT current free bytes: %I64u",g_rescueFreeBytes);WriteUtf8Line(h,b);}
    if(g_lba0Unreadable) WriteUtf8Line(h,L"Recovery resume eligibility: NOT EVALUABLE (logical media unreadable)");
    else {_snwprintf(b,511,L"Recovery resume eligibility: %s",g_resumeEligible?L"YES":L"NO");WriteUtf8Line(h,b);}
    const WCHAR *pwState=(g_fbPwStatState==PROBE_SUCCESS)?L"SUCCESS":(g_fbPwStatState==PROBE_FAILED)?L"ATTEMPTED-FAILED":(g_fbPwStatState==PROBE_DECLINED)?L"DECLINED":L"NOT ATTEMPTED";
    const WCHAR *diState=(g_fbDevInfoState==PROBE_SUCCESS)?L"SUCCESS":(g_fbDevInfoState==PROBE_FAILED)?L"ATTEMPTED-FAILED":(g_fbDevInfoState==PROBE_DECLINED)?L"DECLINED":L"NOT ATTEMPTED";
    const WCHAR *a3State=(g_a3a4State==A3A4_SUCCESS)?L"SUCCESS":(g_a3a4State==A3A4_FAILED)?L"ATTEMPTED-FAILED":(g_a3a4State==A3A4_DECLINED)?L"DECLINED":(g_a3a4State==A3A4_BLOCKED_PREFLIGHT)?L"BLOCKED-PREFLIGHT":L"NOT ATTEMPTED";
    const WCHAR *icdState=(g_sonyIcdTargetState==PROBE_SUCCESS)?L"SUCCESS":(g_sonyIcdTargetState==PROBE_FAILED)?L"ATTEMPTED-FAILED":(g_sonyIcdTargetState==PROBE_DECLINED)?L"DECLINED":L"NOT ATTEMPTED";
    WritePublicPreflightSummary(h,L"Stage 2A live state preflight",g_stage2aPreflightState,&g_pubStage2aPreflight);
    _snwprintf(b,511,L"FB/PW_STAT read-only compatibility probe: %s",pwState);WriteUtf8Line(h,b);
    WritePublicScsiSummary(h,L"FB/PW_STAT SCSI result",&g_pubFbPwStat);
    if(g_fbPwStatOk){_snwprintf(b,511,L"FB/PW_STAT response SHA-256 only: %s",g_fbPwStatSha256);WriteUtf8Line(h,b);}
    _snwprintf(b,511,L"FB/DEVINFO read-only compatibility probe: %s",diState);WriteUtf8Line(h,b);
    WritePublicScsiSummary(h,L"FB/DEVINFO SCSI result",&g_pubFbDevInfo);
    if(g_fbDevInfoOk){_snwprintf(b,511,L"FB/DEVINFO response SHA-256 only: %s",g_fbDevInfoSha256);WriteUtf8Line(h,b);}
    WritePublicPreflightSummary(h,L"Stage 2B live state preflight",g_stage2bPreflightState,&g_pubStage2bPreflight);
    _snwprintf(b,511,L"A3/A4 Device-ID query: %s",a3State);WriteUtf8Line(h,b);
    WritePublicScsiSummary(h,L"A3 fixed select SCSI result",&g_pubA3);
    WritePublicScsiSummary(h,L"A4 Device-ID read SCSI result",&g_pubA4);
    if(g_vendorDvIdRead){_snwprintf(b,511,L"Device-ID SHA-256 only: %s",g_vendorDvIdSha256);WriteUtf8Line(h,b);}
    WritePublicPreflightSummary(h,L"Stage 2C live state preflight",g_stage2cPreflightState,&g_pubStage2cPreflight);
    _snwprintf(b,511,L"SONYICD 0x01 GetTargetIdentifier read-only probe: %s",icdState);WriteUtf8Line(h,b);
    WritePublicScsiSummary(h,L"SONYICD 0x01 SCSI result",&g_pubSonyIcdTarget);
    if(g_sonyIcdStatusValid){_snwprintf(b,511,L"SONYICD 0x01 application status byte: 0x%02X",g_sonyIcdStatus);WriteUtf8Line(h,b);}
    if(g_sonyIcdResponseRead&&g_sonyIcdTargetSha256[0]){_snwprintf(b,511,L"SONYICD 0x01 response SHA-256 only: %s",g_sonyIcdTargetSha256);WriteUtf8Line(h,b);}
    WriteUtf8Line(h,L"PUBLIC upload rule: attach only this NW-E405_PUBLIC_REPORT_*.txt to GitHub Issue #1.");
    WriteUtf8Line(h,L"PRIVATE: TXT journal, JSONL trace, metadata.bin, DvID/FB/SONYICD blobs, LBA/IMG, recovered UPG. Do NOT attach these to the public issue.");
    FlushFileBuffers(h);CloseHandle(h);
}

static BOOL SaveLog(void) {
    BOOL ok=TRUE;
    if(g_liveLog!=INVALID_HANDLE_VALUE) ok=FlushFileBuffers(g_liveLog)&&ok;
    if(g_jsonLog!=INVALID_HANDLE_VALUE) ok=FlushFileBuffers(g_jsonLog)&&ok;
    return ok;
}

static BOOL RevalidateIssue1State(HANDLE h, const WCHAR *label, PublicPreflightSummary *pub) {
    BYTE cdb[16]={0};
    cdb[0]=0x12;cdb[4]=96;ScsiResult inq=SendCdb(h,cdb,6,96);
    WCHAR vendor[32]={0},product[64]={0};
    if(inq.ioctlOk&&inq.scsiStatus==0&&inq.dataLen>=36){BytesToAscii(inq.data,8,8,vendor,32);BytesToAscii(inq.data,16,16,product,64);}
    BOOL ident=ContainsI(vendor,L"SONY")&&ContainsI(product,L"NWWM MEM AAD2");
    ZeroMemory(cdb,sizeof(cdb));cdb[0]=0x00;ScsiResult tur=SendCdb(h,cdb,6,0);
    ZeroMemory(cdb,sizeof(cdb));cdb[0]=0x25;ScsiResult cap=SendCdb(h,cdb,10,8);
    ZeroMemory(cdb,sizeof(cdb));cdb[0]=0xFC;cdb[2]=0x03;cdb[8]=0x08;ScsiResult fw=SendCdb(h,cdb,12,8);
    BOOL ok=ident&&IsSense3A00(&tur)&&IsSense3A00(&cap)&&IsKnownIssue1FwInfo(&fw);
    if(pub){pub->attempted=TRUE;pub->identityOk=ident;pub->tur3a00=IsSense3A00(&tur);pub->cap3a00=IsSense3A00(&cap);pub->fc03Known=IsKnownIssue1FwInfo(&fw);}
    LogF(L"%s: identity=%s TUR3A00=%s CAP3A00=%s FC03-known=%s => %s",
        label?label:L"Issue #1 live preflight",ident?L"YES":L"NO",IsSense3A00(&tur)?L"YES":L"NO",IsSense3A00(&cap)?L"YES":L"NO",IsKnownIssue1FwInfo(&fw)?L"YES":L"NO",ok?L"PASS":L"FAIL");
    return ok;
}

static BOOL RevalidateIssue1BeforeWrite(HANDLE h) {
    return RevalidateIssue1State(h,L"FC/04 immediate preflight",NULL);
}

static void ResumeVerifiedUpdate(void) {
    if(!(g_rootPackageIntact&&g_resumeEligible&&g_officialFirmwareVerified&&g_exactDevicePath[0])){
        LogF(L"FC/04 resume locked: root-package=%d resume-eligible=%d official-fw-verified=%d path=%d",
            g_rootPackageIntact,g_resumeEligible,g_officialFirmwareVerified,g_exactDevicePath[0]!=0);
        MessageBoxW(g_hwnd,L"更新再開の条件が揃っていません。\n\n必要条件:\n・本体内MSFWUPGR.UPGが公式v2.0と完全一致\n・容量条件に重大な矛盾がない\n・Sony公式NW-E40X_V2_0J.exeをこのセッションで検証済み\n・現在もIssue #1状態",L"Update resume locked",MB_OK|MB_ICONWARNING);return;
    }
    if(MessageBoxW(g_hwnd,L"本体内のMSFWUPGR.UPGがSony公式v2.0と完全一致し、復旧条件を満たしています。\n\n次はSony純正Updaterと同じFC/04更新開始コマンドを1回だけ再送します。\n元の更新は一度失敗しているため、状態が悪化する可能性は残ります。\n\n更新再開を試しますか？",L"Experimental update resume",MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2)!=IDYES)return;
    if(MessageBoxW(g_hwnd,L"最終確認です。\n\nFC/04送信後はUSBを抜かないでください。ツールは追加の書き込みコマンドを自動送信せず、USBの再認識だけを監視します。\n\n本当に実行しますか？",L"Final confirmation",MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2)!=IDYES)return;
    if(!IsExactUsbPresentSilent()){LogF(L"FC/04 ABORT: exact USB device disappeared before preflight.");return;}
    HANDLE h=OpenDeviceRW(g_exactDevicePath,NULL);if(h==INVALID_HANDLE_VALUE){LogF(L"FC/04 ABORT: device open failed %lu",GetLastError());return;}
    if(!RevalidateIssue1BeforeWrite(h)){CloseHandle(h);LogF(L"FC/04 ABORT: immediate preflight changed; command NOT sent.");MessageBoxW(g_hwnd,L"直前確認で状態が変化していたためFC/04は送信しませんでした。",L"Recovery aborted",MB_OK|MB_ICONWARNING);return;}
    LogF(L"");LogF(L"=== RECOVERY LADDER STAGE 3: VERIFIED FC/04 UPDATE RESUME ===");
    LogF(L"Safety gates passed. Sending exactly one no-data CDB: FC 00 04 00 00 00 00 00 00 00 00 00");
    BYTE cdb[12]={0};cdb[0]=0xFC;cdb[2]=0x04;ScsiResult r=SendCdb(h,cdb,12,0);CloseHandle(h);ShowScsiResult(L"SONY FC/04 UPDATE START (gated)",&r);
    if(!r.ioctlOk||r.scsiStatus!=0){LogF(L"FC/04 was NOT accepted. No further update command will be sent.");SetStatus(L"FC/04失敗 — 追加書き込みなし");SavePublicReport();return;}
    LogF(L"FC/04 accepted with SCSI GOOD. Monitoring only; no further write/update commands will be sent.");
    SetStatus(L"更新再開コマンド受理 — USBを抜かず再認識を待っています");
    BOOL disappeared=FALSE,reappeared=FALSE;DWORD start=GetTickCount(),lastLog=0;
    while(GetTickCount()-start<540000UL){DWORD elapsed=GetTickCount()-start;BOOL present=IsExactUsbPresentSilent();if(!present)disappeared=TRUE;if(disappeared&&present){reappeared=TRUE;break;}
        if(elapsed-lastLog>=30000UL){lastLog=elapsed;LogF(L"Post-FC04 monitor: %lu sec, USB present=%s, disappeared-once=%s",elapsed/1000,present?L"YES":L"NO",disappeared?L"YES":L"NO");SaveLog();}
        PumpMessages();Sleep(2000);}
    if(reappeared){LogF(L"POST-UPDATE EVENT: NW-E405 USB disappeared and reappeared after FC/04.");SetStatus(L"NW-E405再認識 — 『診断する』で更新後状態を確認してください");MessageBoxW(g_hwnd,L"NW-E405が更新開始後に切断・再認識しました。\n\n次に『診断する』を押して、FW情報とメディア状態を確認してください。",L"Device reappeared",MB_OK|MB_ICONINFORMATION);}
    else{LogF(L"POST-UPDATE TIMEOUT: no disappear/reappear cycle observed within the original updater timeout window (~9 min).");SetStatus(L"更新再開後タイムアウト — ログを保存しました");MessageBoxW(g_hwnd,L"約9分の監視中に正常な切断→再認識を確認できませんでした。\n追加コマンドは送っていません。公開レポートと非公開ログを確認してください。",L"Recovery timeout",MB_OK|MB_ICONWARNING);}
    SavePublicReport();SaveLog();
}

static void RunRecoveryLadder(void) {
    if(!(g_issue1TurNoMedia&&g_issue1CapNoMedia&&g_issue1FwInfoMatch&&g_exactDevicePath[0])){
        MessageBoxW(g_hwnd,L"先に『診断する』を実行してください。\nIssue #1の既知状態と一致した場合だけRecovery Ladderを開始できます。",L"Recovery locked",MB_OK|MB_ICONWARNING);return;
    }
    LogF(L"");LogF(L"=== RECOVERY LADDER START ===");
    if(g_rootPackageIntact){
        if(g_resumeEligible&&g_officialFirmwareVerified){ResumeVerifiedUpdate();return;}
        if(g_resumeEligible&&!g_officialFirmwareVerified){LogF(L"Stage 3 ready except official Sony EXE has not been verified this session.");MessageBoxW(g_hwnd,L"本体内UPGは公式ハッシュと一致しています。\nFC/04再開の前に『純正FWを検証』からSony公式NW-E40X_V2_0J.exeを選んでください。",L"Verify official firmware first",MB_OK|MB_ICONINFORMATION);SavePublicReport();return;}
        LogF(L"Root package is intact but the space/safety gate blocks FC/04 retry.");SavePublicReport();return;
    }
    if(!g_lba0Unreadable){RescueNoMedia();SavePublicReport();
        if(g_rootPackageIntact&&g_resumeEligible&&g_officialFirmwareVerified){if(MessageBoxW(g_hwnd,L"救出したMSFWUPGR.UPGが公式v2.0と完全一致し、更新再開条件も通りました。\n続けてFC/04更新再開を試しますか？",L"Recovery Stage 3 available",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDYES)ResumeVerifiedUpdate();return;}
    }
    if(g_lba0Unreadable){
        int fbans=MessageBoxW(g_hwnd,L"READ(10)でLBA0も読めませんでした。\n\n次に同世代Sony NW-A600公式Updaterで確認した読み取り専用vendor queryを2本だけ試せます。\n・FB/PW_STAT: DATA IN 32 bytes\n・FB/DEVINFO: DATA IN 128 bytes\n\nNW-E405純正Updaterにはこの拡張機能は無いため互換性は未確認です。PCから本体へdata payloadは送りません。\n\n試しますか？",L"Recovery Stage 2A - Sony FB read probes",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2);
        if(fbans==IDYES)ProbeA600ReadOnlyVendorInfo();
        else {g_fbPwStatState=PROBE_DECLINED;g_fbDevInfoState=PROBE_DECLINED;g_stage2aPreflightState=PROBE_NOT_ATTEMPTED;ZeroMemory(&g_pubStage2aPreflight,sizeof(g_pubStage2aPreflight));ZeroMemory(&g_pubFbPwStat,sizeof(g_pubFbPwStat));ZeroMemory(&g_pubFbDevInfo,sizeof(g_pubFbDevInfo));}
        SavePublicReport();
        int a3ans=MessageBoxW(g_hwnd,L"通常のREAD(10)経路ではLBA0も読めませんでした。\n\n同世代NW-A600純正Updater由来のread-only FB/PW_STAT・FB/DEVINFO互換性確認を実行しました。\n\n次にSony MP3 File ManagerのNW-E405純正実装由来A3/A4 Device-ID問い合わせを試します。\nA3は固定20バイトのselect DATA OUT、A4は18バイトのreadです。音楽領域やFWを書き換えるpayloadではありません。\n\n試しますか？",L"Recovery Stage 2 - A3/A4",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2);
        if(a3ans==IDYES)QueryVendorDvId(); else {g_a3a4State=A3A4_DECLINED;g_stage2bPreflightState=PROBE_NOT_ATTEMPTED;ZeroMemory(&g_pubStage2bPreflight,sizeof(g_pubStage2bPreflight));ZeroMemory(&g_pubA3,sizeof(g_pubA3));ZeroMemory(&g_pubA4,sizeof(g_pubA4));}
        SavePublicReport();
        int icdans=MessageBoxW(g_hwnd,L"次に、Sony MP3 File ManagerのNW-E405世代純正IcdMSCom.dll由来の読み取り専用SONYICD 0x01 GetTargetIdentifierを1回だけ試せます。\n\n固定CDBで116バイト(DATA IN)だけを要求し、本体へdata payloadは送りません。応答には個体情報が含まれる可能性があるため、生データはPRIVATE保存し、PUBLIC_REPORTにはSCSI結果・アプリstatus byte・SHA-256だけを記録します。\n\n試しますか？",L"Recovery Stage 2C - E405 SONYICD read probe",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2);
        if(icdans==IDYES)ProbeSonyIcdTargetIdentifier(); else {g_sonyIcdTargetState=PROBE_DECLINED;g_stage2cPreflightState=PROBE_NOT_ATTEMPTED;g_sonyIcdResponseRead=FALSE;g_sonyIcdStatusValid=FALSE;ZeroMemory(&g_pubStage2cPreflight,sizeof(g_pubStage2cPreflight));ZeroMemory(&g_pubSonyIcdTarget,sizeof(g_pubSonyIcdTarget));}
        SavePublicReport();return;
    }
    LogF(L"Recovery Ladder stopped after read-only rescue analysis. No safe next write action is currently unlocked.");SavePublicReport();
}

static void VerifyFirmwareGui(void) {
    if (g_liveLog == INVALID_HANDLE_VALUE && !StartSessionLogs()) {
        MessageBoxW(g_hwnd,L"安全ログ（TXT/JSONL）を作成できないためファームウェア検証を開始しません。",L"Logging required",MB_OK|MB_ICONERROR);
        return;
    }
    OPENFILENAMEW ofn; ZeroMemory(&ofn,sizeof(ofn));
    WCHAR path[MAX_PATH]={0};
    ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=g_hwnd; ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH;
    ofn.lpstrFilter=L"Sony Japanese updater (NW-E40X_V2_0J.exe)\0NW-E40X_V2_0J.exe\0All files\0*.*\0\0";
    ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_HIDEREADONLY;
    if(!GetOpenFileNameW(&ofn))return;
    FirmwarePackageResult r; WCHAR err[512]={0};
    g_officialFirmwareVerified = FALSE; g_verifiedUpgPath[0] = 0;
    LogF(L"");LogF(L"=== OFFICIAL FIRMWARE PACKAGE VERIFICATION ===");
    LogF(L"Selected: %s",path);
    if(VerifyAndExtractSonyFirmwarePackage(path,g_exeDir,&r,err,512)){
        LogF(L"Sony updater SHA-256: %s",r.packageSha256);
        LogF(L"UPG SHA-256: %s",r.upgSha256);
        LogF(L"Package size=%lu  UPG size=%lu",r.packageSize,r.upgSize);
        LogF(L"VERIFIED: exact Japanese NW-E405/E407 v2.0 package.");
        LogF(L"Verified UPG extracted to: %s",r.extractedPath);
        LogF(L"This operation writes only to the PC. Nothing was sent to the Walkman.");
        g_officialFirmwareVerified = TRUE;
        lstrcpynW(g_verifiedUpgPath, r.extractedPath, MAX_PATH);
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
    g_noMediaRescueAvailable=FALSE; g_exactDevicePath[0]=0;
    g_metaInquiryLen=g_metaFc03Len=g_metaFc05Len=g_metaFc09Len=0;
    g_issue1TurNoMedia=g_issue1CapNoMedia=g_issue1FwInfoMatch=FALSE;
    g_lba0Unreadable=FALSE; g_rootPackageIntact=FALSE; g_resumeEligible=FALSE; g_vendorDvIdRead=FALSE; g_vendorDvIdSha256[0]=0;
    g_fbPwStatOk=FALSE; g_fbDevInfoOk=FALSE; g_fbPwStatState=PROBE_NOT_ATTEMPTED; g_fbDevInfoState=PROBE_NOT_ATTEMPTED;
    g_stage2aPreflightState=PROBE_NOT_ATTEMPTED; g_stage2bPreflightState=PROBE_NOT_ATTEMPTED; g_stage2cPreflightState=PROBE_NOT_ATTEMPTED; g_a3a4State=A3A4_NOT_ATTEMPTED; g_sonyIcdTargetState=PROBE_NOT_ATTEMPTED;
    ZeroMemory(&g_pubLba0,sizeof(g_pubLba0)); ZeroMemory(&g_pubFbPwStat,sizeof(g_pubFbPwStat)); ZeroMemory(&g_pubFbDevInfo,sizeof(g_pubFbDevInfo));
    ZeroMemory(&g_pubA3,sizeof(g_pubA3)); ZeroMemory(&g_pubA4,sizeof(g_pubA4)); ZeroMemory(&g_pubSonyIcdTarget,sizeof(g_pubSonyIcdTarget)); ZeroMemory(&g_pubStage2aPreflight,sizeof(g_pubStage2aPreflight)); ZeroMemory(&g_pubStage2bPreflight,sizeof(g_pubStage2bPreflight)); ZeroMemory(&g_pubStage2cPreflight,sizeof(g_pubStage2cPreflight));
    g_fbPwStatSha256[0]=0; g_fbDevInfoSha256[0]=0; g_sonyIcdResponseRead=FALSE; g_sonyIcdStatusValid=FALSE; g_sonyIcdStatus=0; g_sonyIcdTargetSha256[0]=0; g_rescueFreeKnown=FALSE; g_rescueFreeBytes=0;
    if(g_rescue)EnableWindow(g_rescue,FALSE);
    if (!StartSessionLogs()) {
        SetStatus(L"診断中止 — TXT/JSONLログを作成できません");
        MessageBoxW(g_hwnd, L"安全ログ（TXT/JSONL）を作成できないため診断を開始しません。\n\n書き込み可能なフォルダへEXEを移して再実行してください。", L"Logging required", MB_OK | MB_ICONERROR);
        EnableWindow(g_scan, TRUE);
        return;
    }
    SetStatus(L"診断中... USBを抜かないでください");

    LogF(L"%s", APP_TITLE);
    LogF(L"Diagnostic stage is READ-ONLY. Recovery Ladder may later unlock read-only vendor probes, exactly one fixed A3 select, or a gated FC/04 resume after explicit confirmation.");
    LogHostEnvironment();
    LogF(L"");
    LogF(L"診断ボタン自体はフォーマット、セクタ書込み、FW書込み、FC/04更新開始を実行しません。");
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
    LogF(L"=== RECOVERY ASSESSMENT ===");
    if (usb && sony > 0 && g_issue1TurNoMedia && g_issue1CapNoMedia && g_issue1FwInfoMatch) {
        LogF(L"State signature: ISSUE #1 CURRENT-STATE MATCH");
        LogF(L"- Exact NW-E405 identity: YES");
        LogF(L"- User media: MEDIUM NOT PRESENT (3A00)");
        LogF(L"- Sony FC/03: valid known 1.x firmware-info response");
        LogF(L"Interpretation with the known 99%% history: POST-START UPDATE FAILURE CANDIDATE.");
        LogF(L"Do NOT blindly resend FC/04: the original updater had already entered its post-start wait.");
        LogF(L"A true force flash still needs a verified No-Media firmware transport or ROM/service protocol.");
        g_noMediaRescueAvailable = (g_exactDevicePath[0] != 0);
        if(g_noMediaRescueAvailable){
            LogF(L"Recovery Ladder is AVAILABLE: direct READ(10) rescue is the first action stage.");
            if(g_rescue)EnableWindow(g_rescue,TRUE);
        }
    } else {
        LogF(L"State signature: not the exact Issue #1 No-Media/FW-info combination.");
        LogF(L"Keep recovery actions locked; continue read-only analysis.");
    }
    LogF(L"Official Japanese v2.0 package verified this session: %s", g_officialFirmwareVerified ? L"YES" : L"NO");
    LogF(L"");
    SaveMetadataBackup();
    SavePublicReport();
    LogF(L"PUBLIC report: %s",g_publicReportPath);
    LogF(L"PRIVATE TXT journal: %s",g_logPath);
    LogF(L"PRIVATE JSONL CDB trace: %s",g_jsonLogPath);
    LogF(L"GitHub Issue #1へはPUBLIC_REPORTだけを添付してください。生ログ/metadata/IMG/DvIDは非公開で扱ってください。");
    SaveLog();
    if(g_mediaBackupAvailable){SetStatus(L"診断完了 — 通常ストレージ保存が可能です");EnableWindow(g_backup,TRUE);}
    else if(g_noMediaRescueAvailable){SetStatus(L"診断完了 — 『リカバリー実行』を試せます");EnableWindow(g_backup,FALSE);}
    else {SetStatus(L"診断完了 — 追加の読み取り経路はまだ利用できません");EnableWindow(g_backup,FALSE);}
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
                L"Windows 7向け Recovery Tool / 状態に応じて救出→vendor→更新再開を段階実行します。",
                WS_CHILD | WS_VISIBLE, 20, 48, 720, 24, hwnd, NULL, NULL, NULL);
            SendMessageW(sub, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_scan = CreateWindowW(L"BUTTON", L"診断する",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                20, 80, 110, 36, hwnd, (HMENU)ID_SCAN, NULL, NULL);
            SendMessageW(g_scan, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_rescue = CreateWindowW(L"BUTTON", L"リカバリー実行",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                140, 80, 125, 36, hwnd, (HMENU)ID_RESCUE, NULL, NULL);
            SendMessageW(g_rescue, WM_SETFONT, (WPARAM)fNormal, TRUE);
            EnableWindow(g_rescue, FALSE);

            g_backup = CreateWindowW(L"BUTTON", L"通常ストレージ保存",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                275, 80, 145, 36, hwnd, (HMENU)ID_BACKUP, NULL, NULL);
            SendMessageW(g_backup, WM_SETFONT, (WPARAM)fNormal, TRUE);
            EnableWindow(g_backup, FALSE);

            HWND verify = CreateWindowW(L"BUTTON", L"純正FWを検証",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                430, 80, 130, 36, hwnd, (HMENU)ID_VERIFY_FW, NULL, NULL);
            SendMessageW(verify, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND copy = CreateWindowW(L"BUTTON", L"結果をコピー",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                20, 124, 110, 32, hwnd, (HMENU)ID_COPY, NULL, NULL);
            SendMessageW(copy, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND folder = CreateWindowW(L"BUTTON", L"ログフォルダ",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                140, 124, 115, 32, hwnd, (HMENU)ID_FOLDER, NULL, NULL);
            SendMessageW(folder, WM_SETFONT, (WPARAM)fNormal, TRUE);

            HWND github = CreateWindowW(L"BUTTON", L"GitHub",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                265, 124, 90, 32, hwnd, (HMENU)ID_GITHUB, NULL, NULL);
            SendMessageW(github, WM_SETFONT, (WPARAM)fNormal, TRUE);

            g_output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
                20, 168, 744, 350, hwnd, (HMENU)ID_OUTPUT, NULL, NULL);
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
                case ID_RESCUE: RunRecoveryLadder(); return 0;
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
