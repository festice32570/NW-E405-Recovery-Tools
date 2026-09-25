#!/usr/bin/env python3
import hashlib, struct, sys, re, subprocess
from pathlib import Path

EXPECTED={
 'NW-A600_V2_0.exe':'3ea05d6601e0e1c7a039f1c88fcc9cca9a49682cd87ef5e604bbc570ec89d552',
 'FWUpdaterCom.dll':'56aa815bbe6e3441bd3e3168e9511dce94f2e0927167f1671f1a9a8c40ca58bf',
}

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def ck(ok,msg):
 print(('PASS' if ok else 'FAIL'),msg)
 if not ok: raise SystemExit(1)

def main(root):
 root=Path(root)
 exe=root/'NW-A600_V2_0.exe'; ext=root/'extracted'; dll=ext/'FWUpdaterCom.dll'
 ck(exe.exists() and sha(exe)==EXPECTED[exe.name],'exact Sony NW-A600_V2_0.exe')
 ck(dll.exists() and sha(dll)==EXPECTED[dll.name],'exact A600 FWUpdaterCom.dll')
 b=dll.read_bytes()
 for s in [b'CheckStorageFormatType',b'SendFWUpdateCommandExt',b'DeleteUpdateFileExt',b'GetDeviceIdExt']:
  ck(s in b,f'extended interface string {s.decode()}')
 for name,tot,hidden,spc in [('PBR512.dat',998357,43,32),('PBR1G.dat',1996745,55,32),('PBR2G.dat',3993545,55,64)]:
  p=ext/name; d=p.read_bytes(); ck(len(d)==512 and d[510:]==b'\x55\xaa',f'{name} is 512-byte boot sector template')
  ck(struct.unpack_from('<H',d,0x0b)[0]==512 and d[0x0d]==spc and d[0x10]==2 and d[0x36:0x3e]==b'FAT16   ',f'{name} FAT16 BPB identity')
  ck(struct.unpack_from('<I',d,0x1c)[0]==hidden and struct.unpack_from('<I',d,0x20)[0]==tot,f'{name} geometry')
 dis=subprocess.check_output(['objdump','-d','-Mintel',str(dll)],text=True,errors='ignore')
 ck('c6 45 e4 28' in dis,'CheckStorageFormatType builds READ(10) opcode 0x28')
 ck('be 00 02 00 00' in dis,'CheckStorageFormatType uses 512-byte transfer')
 # Known A600 build: second READ(10) takes DWORD from first-sector buffer +0x1C6 (MBR partition #1 start LBA).
 ck('ff 75 8e' in dis,'second READ(10) consumes MBR +0x1C6 start-LBA field')
 # Standard write opcodes: reject explicit byte-CDB builders for known write operations.
 for op in (0x2a,0xaa,0x3b,0x3f):
  pat=rf'mov\s+BYTE PTR .*0x{op:x}\b'
  ck(re.search(pat,dis,re.I) is None,f'no explicit standard SCSI write CDB builder 0x{op:02X}')
 ck('c6 45 08 fc' in dis and 'c6 45 0a 04' in dis,'extended update path contains Sony FC/04 builder')
 # Import evidence used by SendFWUpdateCommandExt: package/copy-file staging is via CopyFileA.
 try:
  import pefile
  pe=pefile.PE(str(dll)); names={i.name.decode(errors='ignore'):i.address for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name}
  ck(names.get('CopyFileA')==0x1000e08c,'CopyFileA IAT pinned at 0x1000E08C')
 except Exception as e:
  print('WARN pefile import check skipped',e)
 print('A600 extended updater audit complete.')

if __name__=='__main__':
 if len(sys.argv)!=2: raise SystemExit('usage: a600_ext_audit.py /path/to/a600')
 main(sys.argv[1])
