#!/usr/bin/env python3
from pathlib import Path
import hashlib, struct, sys

DLL_SHA='525e44f9eff91fb6c07a67f6c3d76363bc2e5f243d0e74a573d1120d747f8799'
EXE_SHA='df5d20736d7c99922ade9c682a1352311fa2776ba7bec34d99de07d68e242fd6'
IMAGE_BASE_DLL=0x10000000


def u32(b, off): return struct.unpack_from('<I', b, off)[0]
def raw_from_va(va):
    # In this PE the relevant .text/.rdata RVAs and raw offsets are aligned equally.
    return va - IMAGE_BASE_DLL


def audit_dll(path: Path):
    b=path.read_bytes(); sha=hashlib.sha256(b).hexdigest()
    funcinfo=0xcf30
    try_map=0xcf68
    handler_map=0xcf80
    checks={
        'exact FWUpdaterCom.dll': sha==DLL_SHA,
        'SendFWUpdateCommand installs MSVC EH frame': b[0x50c8:0x50d2]==bytes.fromhex('b88cba0010e806120000'),
        'CopyFileA call at known site': b[0x51dc:0x51e2]==bytes.fromhex('ff158cc00010'),
        'Copy failure checks ERROR_DISK_FULL': b[0x51e6:0x51ef]==bytes.fromhex('ff15d8c0001083f870'),
        'copy failure enters exception helper': b[0x520b:0x521f].find(bytes.fromhex('e8bb150000'))>=0,
        'FuncInfo magic': u32(b,funcinfo)==0x19930520,
        'FuncInfo maxState=3': u32(b,funcinfo+4)==3,
        'FuncInfo one try block': u32(b,funcinfo+12)==1,
        'FuncInfo try map pointer': u32(b,funcinfo+16)==IMAGE_BASE_DLL+try_map,
        'try map catches state 1': u32(b,try_map)==1 and u32(b,try_map+4)==1 and u32(b,try_map+8)==2,
        'try map one handler': u32(b,try_map+12)==1,
        'handler map pointer': u32(b,try_map+16)==IMAGE_BASE_DLL+handler_map,
        'catch handler is 0x10005287': u32(b,handler_map+12)==0x10005287,
        'catch handler returns continuation 0x1000529A': b[0x5287:0x529a]==bytes.fromhex('837dec007c07c745ec01800480b89a520010c3'),
        'FC04 constructed only on normal path before catch continuation': b[0x5222:0x522a]==bytes.fromhex('c6450cfcc6450e04'),
    }
    for k,v in checks.items(): print(('PASS' if v else 'FAIL'),k)
    print('dll sha256',sha)
    return all(checks.values())


def audit_exe(path: Path):
    b=path.read_bytes(); sha=hashlib.sha256(b).hexdigest()
    checks={
        'exact FWUpdater.exe': sha==EXE_SHA,
        'SendFWUpdateCommand called before wait loop': b[0x4ad9:0x4ade]==bytes.fromhex('ff521c3bc3'),
        'progress clamps at 99': b[0x4c00:0x4c0a]==bytes.fromhex('83f8647c05b863000000'),
        'completion explicitly posts 100': b[0x4cc0:0x4cca]==bytes.fromhex('6a646a00680504000053'),
        'Timer parser multiplies minutes by 60': b[0x25ac:0x25bf]==bytes.fromhex('8d044068b00041006a008d14808b45ecc1e202'),
        'missing TimeOut defaults to 1.5x Timer': b[0x2669:0x267c]==bytes.fromhex('8b4dec8b415485c076098bd0d1ea03d0895158'),
    }
    for k,v in checks.items(): print(('PASS' if v else 'FAIL'),k)
    print('exe sha256',sha)
    return all(checks.values())


def main(argv):
    if len(argv)!=3:
        print('usage: original_updater_audit.py <FWUpdaterCom.dll> <FWUpdater.exe>'); return 2
    return 0 if audit_dll(Path(argv[1])) and audit_exe(Path(argv[2])) else 1
if __name__=='__main__': raise SystemExit(main(sys.argv))
