param(
    [string]$DevicePath = ""
)

$ErrorActionPreference = "Stop"
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$LogPath = Join-Path $BaseDir ("NW-E405_diag_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Log([string]$s) {
    $s | Tee-Object -FilePath $LogPath -Append
}

Log "NW-E405 Recovery Probe v0.1"
Log ("Date: " + (Get-Date))
Log ("OS: " + [Environment]::OSVersion.VersionString)
Log ("PowerShell: " + $PSVersionTable.PSVersion.ToString())
Log ("Process bitness: " + ([IntPtr]::Size * 8) + "-bit")
Log ""

$src = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class NwScsi
{
    const uint GENERIC_READ  = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ  = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint OPEN_EXISTING = 3;
    const uint IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014;
    const byte SCSI_IOCTL_DATA_OUT = 0;
    const byte SCSI_IOCTL_DATA_IN = 1;
    const byte SCSI_IOCTL_DATA_UNSPECIFIED = 2;

    [StructLayout(LayoutKind.Sequential)]
    struct SCSI_PASS_THROUGH_DIRECT
    {
        public ushort Length;
        public byte ScsiStatus;
        public byte PathId;
        public byte TargetId;
        public byte Lun;
        public byte CdbLength;
        public byte SenseInfoLength;
        public byte DataIn;
        public uint DataTransferLength;
        public uint TimeOutValue;
        public IntPtr DataBuffer;
        public uint SenseInfoOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)]
        public byte[] Cdb;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SPTD_WITH_SENSE
    {
        public SCSI_PASS_THROUGH_DIRECT Sptd;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=32)]
        public byte[] Sense;
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr CreateFile(
        string name, uint access, uint share, IntPtr sec,
        uint creation, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(
        IntPtr h, uint code, IntPtr inBuf, uint inLen,
        IntPtr outBuf, uint outLen, out uint returned, IntPtr ov);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);

    public class Result
    {
        public bool OpenOk;
        public bool IoctlOk;
        public int Win32Error;
        public byte ScsiStatus;
        public byte[] Data;
        public byte[] Sense;
        public string ErrorText;
    }

    public static Result Send(string path, byte[] cdb, int dataLength, bool dataIn)
    {
        Result r = new Result();
        r.Data = new byte[Math.Max(0, dataLength)];
        r.Sense = new byte[32];

        IntPtr h = CreateFile(path, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
            OPEN_EXISTING, 0, IntPtr.Zero);

        if (h.ToInt64() == -1) {
            r.Win32Error = Marshal.GetLastWin32Error();
            r.ErrorText = new Win32Exception(r.Win32Error).Message;
            return r;
        }
        r.OpenOk = true;

        IntPtr data = IntPtr.Zero;
        IntPtr packet = IntPtr.Zero;
        try {
            if (dataLength > 0) {
                data = Marshal.AllocHGlobal(dataLength);
                for (int i=0; i<dataLength; i++) Marshal.WriteByte(data, i, 0);
            }

            SPTD_WITH_SENSE wb = new SPTD_WITH_SENSE();
            wb.Sptd = new SCSI_PASS_THROUGH_DIRECT();
            wb.Sptd.Length = (ushort)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT));
            wb.Sptd.CdbLength = (byte)cdb.Length;
            wb.Sptd.SenseInfoLength = 32;
            wb.Sptd.DataIn = dataLength == 0 ? SCSI_IOCTL_DATA_UNSPECIFIED :
                (dataIn ? SCSI_IOCTL_DATA_IN : SCSI_IOCTL_DATA_OUT);
            wb.Sptd.DataTransferLength = (uint)dataLength;
            wb.Sptd.TimeOutValue = 10;
            wb.Sptd.DataBuffer = data;
            wb.Sptd.SenseInfoOffset =
                (uint)Marshal.OffsetOf(typeof(SPTD_WITH_SENSE), "Sense").ToInt32();
            wb.Sptd.Cdb = new byte[16];
            Array.Copy(cdb, wb.Sptd.Cdb, cdb.Length);
            wb.Sense = new byte[32];

            int sz = Marshal.SizeOf(typeof(SPTD_WITH_SENSE));
            packet = Marshal.AllocHGlobal(sz);
            Marshal.StructureToPtr(wb, packet, false);

            uint returned;
            bool ok = DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                packet, (uint)sz, packet, (uint)sz, out returned, IntPtr.Zero);

            r.IoctlOk = ok;
            if (!ok) {
                r.Win32Error = Marshal.GetLastWin32Error();
                r.ErrorText = new Win32Exception(r.Win32Error).Message;
            }

            SPTD_WITH_SENSE after =
                (SPTD_WITH_SENSE)Marshal.PtrToStructure(packet, typeof(SPTD_WITH_SENSE));
            r.ScsiStatus = after.Sptd.ScsiStatus;
            r.Sense = after.Sense;

            if (dataLength > 0 && data != IntPtr.Zero)
                Marshal.Copy(data, r.Data, 0, dataLength);
        }
        finally {
            if (packet != IntPtr.Zero) Marshal.FreeHGlobal(packet);
            if (data != IntPtr.Zero) Marshal.FreeHGlobal(data);
            CloseHandle(h);
        }
        return r;
    }
}
"@

try {
    Add-Type -TypeDefinition $src -Language CSharp
} catch {
    Log ("ERROR: Add-Type failed: " + $_.Exception.Message)
    Log "This tool needs the .NET Framework/PowerShell compiler available in Windows 7."
    exit 10
}

function Hex([byte[]]$b, [int]$max=96) {
    if ($b -eq $null) { return "" }
    $n = [Math]::Min($b.Length, $max)
    $a = @()
    for ($i=0; $i -lt $n; $i++) { $a += ("{0:X2}" -f $b[$i]) }
    return ($a -join " ")
}

function Ascii([byte[]]$b, [int]$off, [int]$len) {
    if ($b -eq $null -or $b.Length -lt ($off+$len)) { return "" }
    return [Text.Encoding]::ASCII.GetString($b, $off, $len).Trim([char]0, [char]32)
}

function SenseText([byte[]]$s) {
    if ($s -eq $null -or $s.Length -lt 14) { return "n/a" }
    $key = $s[2] -band 0x0F
    $asc = $s[12]
    $ascq = $s[13]
    $name = switch ($key) {
        0 { "NO SENSE" }
        1 { "RECOVERED ERROR" }
        2 { "NOT READY" }
        3 { "MEDIUM ERROR" }
        4 { "HARDWARE ERROR" }
        5 { "ILLEGAL REQUEST" }
        6 { "UNIT ATTENTION" }
        7 { "DATA PROTECT" }
        default { "KEY " + $key }
    }
    return ("{0}; ASC/ASCQ={1:X2}/{2:X2}" -f $name,$asc,$ascq)
}

function ShowResult([string]$name, $r) {
    Log ("--- " + $name + " ---")
    Log ("OpenOk=" + $r.OpenOk + " IoctlOk=" + $r.IoctlOk +
         " Win32Error=" + $r.Win32Error + " ScsiStatus=0x" + ("{0:X2}" -f $r.ScsiStatus))
    if ($r.ErrorText) { Log ("Win32: " + $r.ErrorText) }
    Log ("Sense: " + (SenseText $r.Sense))
    Log ("SenseHex: " + (Hex $r.Sense 32))
    if ($r.Data -and $r.Data.Length -gt 0) { Log ("Data: " + (Hex $r.Data 96)) }
    Log ""
}

Log "PnP match for NW-E405 VID/PID (054C:01FB):"
try {
    $pnp = Get-WmiObject Win32_PnPEntity | Where-Object {
        $_.DeviceID -match "VID_054C&PID_01FB"
    }
    if ($pnp) {
        foreach ($x in $pnp) {
            Log ("  Name=" + $x.Name)
            Log ("  DeviceID=" + $x.DeviceID)
            Log ("  Status=" + $x.Status)
        }
    } else { Log "  (not found by VID/PID)" }
} catch { Log ("  WMI error: " + $_.Exception.Message) }
Log ""

Log "Disk devices:"
$disks = @()
try {
    $disks = @(Get-WmiObject Win32_DiskDrive)
    foreach ($d in $disks) {
        Log ("  " + $d.DeviceID + " | Model=" + $d.Model + " | Interface=" +
             $d.InterfaceType + " | Size=" + $d.Size + " | PNP=" + $d.PNPDeviceID)
    }
} catch { Log ("  WMI error: " + $_.Exception.Message) }
Log ""

if (-not $DevicePath) {
    $sony = @($disks | Where-Object {
        ($_.Model -match "NWWM\s*MEM\s*AAD2") -or
        ($_.Model -match "NW-E405") -or
        ($_.PNPDeviceID -match "NWWM") -or
        ($_.PNPDeviceID -match "SONY")
    })
    if ($sony.Count -eq 1) {
        $DevicePath = $sony[0].DeviceID
    } elseif ($sony.Count -gt 1) {
        $exact = @($sony | Where-Object { $_.Model -match "NWWM\s*MEM\s*AAD2|NW-E405" })
        if ($exact.Count -eq 1) { $DevicePath = $exact[0].DeviceID }
    }
}

if (-not $DevicePath) {
    Log "RESULT: USB may be enumerating, but no unique Sony/NWWM disk device could be selected."
    Log "Do NOT format anything. Send this log back for the next step."
    Write-Host ""
    Write-Host "Finished. Log:" $LogPath
    Read-Host "Press Enter to close"
    exit 20
}

Log ("Selected device: " + $DevicePath)
Log ""

# Standard SCSI INQUIRY (read-only)
$cdb = New-Object byte[] 6
$cdb[0] = 0x12
$cdb[4] = 96
$r = [NwScsi]::Send($DevicePath, $cdb, 96, $true)
ShowResult "SCSI INQUIRY" $r
if ($r.Data.Length -ge 36) {
    Log ("Inquiry Vendor:  " + (Ascii $r.Data 8 8))
    Log ("Inquiry Product: " + (Ascii $r.Data 16 16))
    Log ("Inquiry Rev:     " + (Ascii $r.Data 32 4))
    Log ""
}

# TEST UNIT READY (read-only)
$cdb = New-Object byte[] 6
$cdb[0] = 0x00
$r = [NwScsi]::Send($DevicePath, $cdb, 0, $true)
ShowResult "TEST UNIT READY" $r

# REQUEST SENSE (read-only)
$cdb = New-Object byte[] 6
$cdb[0] = 0x03
$cdb[4] = 64
$r = [NwScsi]::Send($DevicePath, $cdb, 64, $true)
ShowResult "REQUEST SENSE" $r

# READ CAPACITY(10) (read-only)
$cdb = New-Object byte[] 10
$cdb[0] = 0x25
$r = [NwScsi]::Send($DevicePath, $cdb, 8, $true)
ShowResult "READ CAPACITY(10)" $r
if ($r.IoctlOk -and $r.ScsiStatus -eq 0 -and $r.Data.Length -ge 8) {
    [uint64]$last = ([uint64]$r.Data[0] -shl 24) -bor ([uint64]$r.Data[1] -shl 16) -bor
                   ([uint64]$r.Data[2] -shl 8) -bor [uint64]$r.Data[3]
    [uint64]$blen = ([uint64]$r.Data[4] -shl 24) -bor ([uint64]$r.Data[5] -shl 16) -bor
                   ([uint64]$r.Data[6] -shl 8) -bor [uint64]$r.Data[7]
    [uint64]$bytes = ($last + 1) * $blen
    Log ("Capacity bytes: " + $bytes + " (block size " + $blen + ")")
    Log ""
}

# Sony updater read-only command discovered in official FWUpdaterCom.dll:
# CDB[0]=FC, CDB[2]=03, allocation length at CDB[7..8].
$cdb = New-Object byte[] 12
$cdb[0] = 0xFC
$cdb[2] = 0x03
$cdb[7] = 0x00
$cdb[8] = 0x40
$r = [NwScsi]::Send($DevicePath, $cdb, 64, $true)
ShowResult "SONY 0xFC/0x03 (firmware-info read)" $r
if ($r.IoctlOk -and $r.ScsiStatus -eq 0) {
    Log ("Vendor response ASCII: " + (Ascii $r.Data 0 $r.Data.Length))
    Log ""
}

Log "=== SUMMARY ==="
Log "This build performs READ-ONLY diagnostics only."
Log "It does NOT format the Walkman, write sectors, copy firmware, or send the Sony update-start command."
Log "Send this entire log back for analysis."
Write-Host ""
Write-Host "Finished. Log:" $LogPath
Read-Host "Press Enter to close"
