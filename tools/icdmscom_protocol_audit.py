#!/usr/bin/env python3
"""Pin read-only SONYICD command evidence from Sony MP3 File Manager IcdMSCom.dll.

Research aid only. Does not send commands to a device.
"""
from pathlib import Path
import argparse, hashlib, subprocess, re

def check(ok,msg):
    print(('PASS' if ok else 'FAIL'),msg)
    if not ok: raise SystemExit(1)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('dll',type=Path); a=ap.parse_args()
    b=a.dll.read_bytes(); print('sha256',hashlib.sha256(b).hexdigest())
    dis=subprocess.check_output(['objdump','-d','-Mintel',str(a.dll)],text=True,errors='ignore')
    # Generic builder signature: FC 00 <cmd> 'SONYICD' <len-be16>
    for addr,frag in [
      ('FC opcode','c6 44 24 04 fc'),('SONY','c6 44 24 07 53'),('O','c6 44 24 08 4f'),
      ('N','c6 44 24 09 4e'),('Y','c6 44 24 0a 59'),('I','c6 44 24 0b 49'),
      ('C','c6 44 24 0c 43'),('D','c6 44 24 0d 44')]: check(frag in dis,'builder '+addr)
    # Calls pinned from named API methods in the exact DLL. command top bits select transport:
    # 00=read/data-in, 40=write/data-out, 80=no-data reset.
    reads={
      'GetTargetIdentifier':(0x01,0x74),
      'GetPreferenceInfo':(0x02,0x48),
      'GetRevokeListST part0':(0x04,0x1f8),
      'GetRevokeListST part1':(0x05,0x1f8),
    }
    # Validate exact push sequences immediately before calls to 0x10002a30.
    needles={
      'GetTargetIdentifier':'6a 74',
      'GetPreferenceInfo':'6a 48',
      'GetRevokeListST part0':'68 f8 01 00 00',
      'GetRevokeListST part1':'6a 05',
    }
    for n,(cmd,ln) in reads.items():
      check(needles[n] in dis,f'{n} static evidence; cmd=0x{cmd:02X} len=0x{ln:X} DATA-IN family')
    check('68 80 00 00 00' in dis,'Reset command 0x80 no-data family evidence')
    for cmd in (0x41,0x42,0x43,0x44,0x45):
      check(re.search(rf'(?:6a {cmd:02x}|68 {cmd:02x} 00 00 00)',dis,re.I) is not None,f'Set command 0x{cmd:02X} exists in DATA-OUT family')
    print('NOTE: audit is static only; no device I/O is performed.')
if __name__=='__main__': main()
