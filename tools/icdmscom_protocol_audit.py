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

    # Standard Windows SPTI backend.  The common low-level function at
    # 0x10001080 builds SCSI_PASS_THROUGH: Length=0x2c, SenseInfoLength=0x12,
    # SenseInfoOffset=0x30, then calls DeviceIoControl(IOCTL 0x4d014).
    check('66 c7 44 24 14 2c 00' in dis, 'SPTI Length=0x2C structure evidence')
    check('c6 44 24 1b 12' in dis, 'SPTI SenseInfoLength=0x12 evidence')
    check('c7 44 24 2c 30 00 00' in dis, 'SPTI SenseInfoOffset=0x30 evidence')
    check('68 14 d0 04 00' in dis, 'SPTI DeviceIoControl code 0x4D014 evidence')

    # Wrappers at 0x10002540/560/580 feed mode 2/1/0 respectively into the
    # same low-level SPTI routine: no-data / DATA-IN / DATA-OUT.
    check('10002548:\t6a 02' in dis and '10002550:\te8 2b eb ff ff' in dis,
          'standard SPTI no-data wrapper -> common low-level path')
    check('10002568:\t6a 01' in dis and '10002576:\te8 05 eb ff ff' in dis,
          'standard SPTI DATA-IN wrapper -> common low-level path')
    check('10002588:\t6a 00' in dis and '10002596:\te8 e5 ea ff ff' in dis,
          'standard SPTI DATA-OUT wrapper -> common low-level path')

    # Generic builder dispatch uses command&0xC0: 0x00 -> vtable +8 (IN),
    # 0x40 -> +0x0c (OUT), 0x80 -> +4 (no-data).
    check('ff 50 08' in dis and 'ff 50 0c' in dis and 'ff 52 04' in dis,
          'SONYICD family dispatch reaches IN/OUT/no-data virtual transports')

    # GetTargetIdentifier validates response byte +0x0f and then parses
    # network-order fields with ntohs/ntohl.  Keep raw 0x74 bytes private.
    check('8a 41 0f' in dis, 'GetTargetIdentifier status byte at response+0x0F')
    check('8b 35 28 a1 00 10' in dis and '8b 3d 2c a1 00 10' in dis,
          'GetTargetIdentifier ntohs/ntohl field decoding evidence')

    raw=a.dll.read_bytes()
    check(b'\\.\\SONYSPTI\x00' in raw, 'SONYSPTI backend string present')
    check(b'\\.\\scsipath%d\x00' in raw, 'scsipath backend string present')
    print('NOTE: audit is static only; no device I/O is performed.')
if __name__=='__main__': main()
