#!/usr/bin/env python3
from pathlib import Path
import hashlib, sys

EXPECTED_SHA256='525e44f9eff91fb6c07a67f6c3d76363bc2e5f243d0e74a573d1120d747f8799'

def audit(path: Path):
    b=path.read_bytes(); sha=hashlib.sha256(b).hexdigest()
    checks={
        'exact FWUpdaterCom.dll': sha==EXPECTED_SHA256,
        'CopyFileA call at known site': b[0x51dc:0x51e2]==bytes.fromhex('ff158cc00010'),
        'copy result branches to join': b[0x51e2:0x51e6]==bytes.fromhex('3bc37539'),
        'ERROR_DISK_FULL (0x70) explicitly checked': b[0x51e6:0x51ef]==bytes.fromhex('ff15d8c0001083f870'),
        'FC04 constructed after copy-error join': b[0x5222:0x522a]==bytes.fromhex('c6450cfcc6450e04'),
        'MSFWUPGR destination template present': b'%c:\\MSFWUPGR.UPG\x00' in b,
    }
    for k,v in checks.items(): print(('PASS' if v else 'FAIL'),k)
    print('sha256',sha)
    # The success path jumps to 0x521f; the failure path falls through to the same 0x521f block.
    # That block immediately builds FC/04. This is the key low-free-space safety finding.
    return all(checks.values())

def main(argv):
    if len(argv)!=2:
        print('usage: original_updater_audit.py <FWUpdaterCom.dll>'); return 2
    return 0 if audit(Path(argv[1])) else 1
if __name__=='__main__': raise SystemExit(main(sys.argv))
