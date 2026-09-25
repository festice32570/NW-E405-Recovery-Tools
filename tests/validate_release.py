from pathlib import Path
import re,sys
root=Path(__file__).resolve().parents[1]
s=(root/'src/NW-E405-Recovery-Tool.c').read_text(encoding='utf-8')
fwp=(root/'src/fw_package.c').read_text(encoding='utf-8')
allc=s+'\n'+fwp
checks={
 'v0.7 recovery build':'NW-E405 Recovery Tool v0.7-dev' in s,
 'exact VID/PID':'VID_054C&PID_01FB' in s,
 'exact SCSI identity':'NWWM MEM AAD2' in s,
 'exactly one DATA OUT implementation':allc.count('SCSI_IOCTL_DATA_OUT')==1 and 'SendFixedA3SelectDeviceId' in s,
 'fixed A3 CDB':'0xA3,0,0,0,0,0,0,0xBC,0,0x14,0x30,0' in s,
 'fixed A3 payload':'BYTE payload[20]={0}; payload[1]=0x12;' in s,
 'fixed A4 CDB':'0xA4,0,0,0,0,0,0,0xBC,0,0x12,0x3F,0' in s,
 'A4 record validation':'rd.data[0]!=0x00 || rd.data[1]!=0x10' in s,
 'exactly one FC04 builder':len(re.findall(r'cdb\s*\[\s*2\s*\]\s*=\s*0x04\b',s,re.I))==1,
 'FC04 no-data send':'SendCdb(h,cdb,12,0)' in s,
 'FC04 root package gate':'g_rootPackageIntact&&g_resumeEligible&&g_officialFirmwareVerified' in s,
 'FC04 immediate state revalidation':'RevalidateIssue1BeforeWrite' in s and 'FC/04 immediate preflight' in s,
 'FC04 double confirmation':'Experimental update resume' in s and 'Final confirmation' in s,
 'FC04 single-action monitor':'no further write/update commands will be sent' in s and '540000UL' in s,
 'FC03 read probe':re.search(r'cdb\s*\[\s*2\s*\]\s*=\s*0x03\b',s,re.I) is not None,
 'FC05 GetDeviceId read probe':'cdb[2] = 0x05' in s and 'cdb[9] = 0x10' in s,
 'FC09 ProductInfo read probe':'cdb[2] = 0x09' in s and "cdb[3] = 'r'" in s and "cdb[6] = 'a'" in s,
 'No Media LBA0 rescue':'RescueNoMedia' in s and 'Read10Chunk(dev,0,1,sec0,512' in s,
 'FAT free-space gate':'FatCountFreeBytes' in s and 'estimatedBefore>=3000000ULL' in s,
 'root UPG exact hash gate':'g_rootPackageIntact=TRUE' in s and '82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691' in s,
 'public/private report separation':'NW-E405_PUBLIC_REPORT_' in s and 'Do NOT post the private DvID' in s and 'PRIVATE JSONL' in s,
 'public report redacts raw DvID':'Device-ID SHA-256 only' in s,
 'JSONL intent/result trace':'TraceCdbIntentJson' in s and 'TraceCdbJson' in s and 'FlushFileBuffers(g_jsonLog)' in s,
 'live text log':'StartSessionLogs' in s and 'FlushFileBuffers(g_liveLog)' in s,
 'firmware SHA256':'CALG_SHA_256' in allc,
 'approved Sony EXE hash':'8b68cf41d193464439e8139aa593ebcf887d2dd0a2220a6135039b3ebf7a7eb7' in fwp,
 'approved E40X UPG hash':'82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691' in fwp,
 'Win7 diagnostic wording':'Windows 7' in s,
}
failed=False
for name,ok in checks.items(): print(('PASS' if ok else 'FAIL'),name);failed|=not ok
for op in (0x2A,0xAA,0x3B,0x3F):
    ok=re.search(rf'cdb\s*\[\s*0\s*\]\s*=\s*0x{op:02X}\b',s,re.I) is None
    print(('PASS' if ok else 'FAIL'),f'no standard write opcode {op:02X}');failed|=not ok
sys.exit(1 if failed else 0)
