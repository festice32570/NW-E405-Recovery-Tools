#!/usr/bin/env python3
from pathlib import Path
import subprocess, re, sys
root=Path(__file__).resolve().parents[1]
exe=root/'NW-E405-Recovery-Tool.exe'
obj=root/'toolchain/llvm-mingw/bin/llvm-objdump'
if not exe.exists():
    print('FAIL built PE missing'); sys.exit(1)
fileout=subprocess.check_output(['file',str(exe)],text=True)
pe=subprocess.check_output([str(obj),'-p',str(exe)],text=True,errors='replace')
checks={
 'PE32 i386':'PE32 executable' in fileout and 'Intel 80386' in fileout,
 'GUI subsystem':'Subsystem               00000002' in pe,
 'subsystem <= Win7':int(re.search(r'MajorSubsystemVersion\s+(\d+)',pe).group(1)) <= 6,
 'no dotnet import':'mscoree.dll' not in pe.lower(),
 'no vcruntime import':'vcruntime' not in pe.lower(),
 'no ucrtbase import':'ucrtbase' not in pe.lower(),
}
allowed={'setupapi.dll','shell32.dll','gdi32.dll','user32.dll','kernel32.dll','comdlg32.dll','advapi32.dll','msvcrt.dll'}
dlls={x.lower() for x in re.findall(r'DLL Name:\s+([^\s]+)',pe)}
checks['only Win7-era system DLLs']=dlls <= allowed
for n,v in checks.items(): print(('PASS' if v else 'FAIL'),n)
print('Imported DLLs:',', '.join(sorted(dlls)))
sys.exit(0 if all(checks.values()) else 1)
