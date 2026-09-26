#!/usr/bin/env python3
"""Static audit for FrankPACAPI A4/BC/0404/33 read-only device-behavior query.
No device I/O is performed.
"""
from pathlib import Path
import argparse,hashlib,subprocess,re

def ck(ok,msg):
    print(('PASS' if ok else 'FAIL'),msg)
    if not ok: raise SystemExit(1)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('dll',type=Path); a=ap.parse_args()
    b=a.dll.read_bytes(); sha=hashlib.sha256(b).hexdigest(); print('sha256',sha)
    dis=subprocess.check_output(['objdump','-d','-Mintel',str(a.dll)],text=True,errors='ignore')
    # Exact builder helpers and two uses in this Sony FrankPACAPI build.
    ck(dis.count('call   0x6c13579a')==2,'exactly two A4 opcode-setter call sites')
    ck(dis.count('call   0x6c1357c9')==2,'exactly two byte7/BC setter call sites')
    ck(dis.count('call   0x6c1357d3')==2,'exactly two transfer-length setter call sites')
    ck(dis.count('call   0x6c1357f9')==2,'exactly two subcommand setter call sites')
    for x,msg in [
      ('68 a4 00 00 00','A4 opcode'),('68 bc 00 00 00','BC selector'),
      ('be 04 04 00 00','0x0404 transfer length in direct path'),('6a 33','subcommand 0x33')]: ck(x in dis,msg)
    # Exact raw response flag extraction in direct path: [ebp-0x41c] == buffer base [ebp-0x428] + 0x0c.
    ck('0f b6 b5 e4 fb ff ff' in dis and 'c1 ee 07' in dis,'raw response offset 0x0C bit7 -> device mode')
    # Caller maps mode=1 to BehaviorType4, otherwise BehaviorType2.
    block=dis[dis.find('6c13664f:'):dis.find('6c136757:')]
    ck('e8 8c b7 ff ff' in block and '83 c0 04' in block and '24 fe' in block,'device mode mapped to BehaviorType 2/4')
    # Second path identifies this as ExecCommandIn / GetDeviceInfo behavior logic via embedded strings.
    raw=b
    ck(b'ExecCommandIn () hr = %08x' in raw,'ExecCommandIn error string present')
    ck(b'GetDeviceInfo () hr = %08x' in raw,'GetDeviceInfo error string present')
    ck(b'GetDeviceBehaviorType' in raw,'GetDeviceBehaviorType symbol/string present')
    # Generic SCSI wrapper terminal handling for packed sense 02/3A/00.
    ck(len(re.findall(r'cmp\s+[^\n]*0x23a00',dis,re.I))>=3,'packed 02/3A/00 terminal sense checks present')
    # Standard Windows transport support seen in this class.
    ck('bb 00 14 2d 00' in dis,'IOCTL_STORAGE_QUERY_PROPERTY 0x2D1400 present')
    ck('68 14 d0 04 00' in dis,'IOCTL_SCSI_PASS_THROUGH_DIRECT 0x4D014 present')
    ck(b'\\\\.\\SONYSPTI' in raw and b'\\\\.\\A:' in raw,'SONYSPTI and drive-letter transport paths present')
    print('NOTE: static analysis only; no command is sent to hardware.')

if __name__=='__main__': main()
