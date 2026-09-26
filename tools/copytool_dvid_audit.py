#!/usr/bin/env python3
"""Static audit of the Sony MP3 File Manager CopyTool A3/A4 Device-ID sequence.
No device I/O is performed.
"""
from pathlib import Path
import argparse,hashlib,subprocess,re

def ck(ok,msg):
    print(('PASS' if ok else 'FAIL'),msg)
    if not ok: raise SystemExit(1)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('exe',type=Path);a=ap.parse_args()
    b=a.exe.read_bytes();print('sha256',hashlib.sha256(b).hexdigest())
    d=subprocess.check_output(['objdump','-d','-Mintel',str(a.exe)],text=True,errors='ignore')
    # Fixed A3 select sequence.
    a3=d[d.find('402142:'):d.find('40221b:')]
    for pat,msg in [('68 a3 00 00 00','A3 opcode'),('68 bc 00 00 00','BC selector'),('6a 14','20-byte transfer'),('6a 30','subcommand 0x30'),('66 c7 44 24 18 00 12','fixed payload starts 00 12')]: ck(pat in a3,msg)
    ck('call   0x401b30' in a3,'A3 uses CopyTool outbound transport')
    # Fixed A4 read sequence.
    a4=d[d.find('4022ce:'):d.find('4023a1:')]
    for pat,msg in [('68 a4 00 00 00','A4 opcode'),('68 bc 00 00 00','BC selector'),('6a 12','18-byte transfer'),('6a 3f','subcommand 0x3F')]: ck(pat in a4,msg)
    ck(a4.count('call   0x401b00')>=2,'A4 uses inbound transport and retries once on failure')
    print('NOTE: static analysis only; no command is sent to hardware.')
if __name__=='__main__':main()
