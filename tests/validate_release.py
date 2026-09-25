from pathlib import Path
import re,sys
root=Path(__file__).resolve().parents[1]
s=(root/'src/NW-E405-Recovery-Tool.c').read_text(encoding='utf-8')
fwp=(root/'src/fw_package.c').read_text(encoding='utf-8')
allc=s+'\n'+fwp
checks={
 'v0.5 lab build':'v0.5-dev' in s,
 'exact VID/PID':'VID_054C&PID_01FB' in s,
 'exact SCSI identity':'NWWM MEM AAD2' in s,
 'no FC04 CDB on main':re.search(r'cdb\s*\[\s*2\s*\]\s*=\s*0x04\b',s,re.I) is None,
 'no SCSI DATA OUT':'SCSI_IOCTL_DATA_OUT' not in allc,
 'FC03 read probe':re.search(r'cdb\s*\[\s*2\s*\]\s*=\s*0x03\b',s,re.I) is not None,
 'FC05 GetDeviceId read probe':'cdb[2] = 0x05' in s and 'cdb[9] = 0x10' in s,
 'FC09 ProductInfo read probe':'cdb[2] = 0x09' in s and "cdb[3] = 'r'" in s and "cdb[6] = 'a'" in s,
 'JSONL trace':'TraceCdbJson' in s and 'FlushFileBuffers(g_jsonLog)' in s,
 'JSONL format is real JSON':'{\\"seq\\":%ld' in s and '{\\\\\"seq' not in s,
 'live text log':'StartSessionLogs' in s and 'FlushFileBuffers(g_liveLog)' in s and 'FILE_FLAG_WRITE_THROUGH' in s,
 'diagnostics abort without logs':'if (!StartSessionLogs())' in s and 'Logging required' in s,
 'OS architecture logging':'IsWow64Process' in s and 'GetNativeSystemInfo' in s,
 'firmware SHA256':'CALG_SHA_256' in allc,
 'approved Sony EXE hash':'8b68cf41d193464439e8139aa593ebcf887d2dd0a2220a6135039b3ebf7a7eb7' in fwp,
 'approved E40X UPG hash':'82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691' in fwp,
 'verified EXE extracts UPG':'mz_zip_reader_extract_to_heap' in fwp and 'MSFWUPGR_NW-E40X_201J.UPG' in fwp,
 'storage backup is READ10 only':'cdb[0]=0x28' in s and 'SCSI_IOCTL_DATA_IN' in s,
 'partial image retained on failure':'.partial' in s,
 'raw metadata warning':'NOT a NOR/NAND firmware image backup' in s,
}
failed=False
for name,ok in checks.items(): print(('PASS' if ok else 'FAIL'),name);failed|=not ok
for op in (0x2A,0xAA,0x3B,0x3F):
 ok=re.search(rf'cdb\s*\[\s*0\s*\]\s*=\s*0x{op:02X}\b',s,re.I) is None
 print(('PASS' if ok else 'FAIL'),f'no write opcode {op:02X}');failed|=not ok
sys.exit(1 if failed else 0)
