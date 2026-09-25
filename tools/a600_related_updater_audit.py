#!/usr/bin/env python3
"""Audit Sony NW-A600 v2.0 updater as related-model recovery evidence.

This does NOT claim NW-E405 command compatibility.  It pins observations from
Sony's NW-A605/A607/A608 updater so they can be re-checked without relying on
manual reverse-engineering notes.
"""
from pathlib import Path
import argparse, hashlib, re, struct, subprocess, sys

EXPECTED = {
    'FWUpdater.exe': '62a642a0c331f42899fb55183e951469dfc5673bbc3cd94980ba9b78bf6cb78c',
    'FWUpdaterCom.dll': '56aa815bbe6e3441bd3e3168e9511dce94f2e0927167f1671f1a9a8c40ca58bf',
    'NW_A600_2.00.00J.UPG': '0ad8f764a4b3e0aad3ae1a6a70be7e68fa0686a5a3395ba061bbe071e566a963',
    'NW_A600_2.00.00J_BOOT21.UPG': '72a7e13686b7cf10ed0e43772f17e069bb30b20c43a90ef693441d6a76cfdbf5',
    'PBR512.dat': 'b5e170511435bc2290f5c963b5de4f4b0947ce7861c7d5fc3617783d449898da',
    'PBR1G.dat': 'd6fba4ddb8574be8e423211600a78db41fe422684be3d9006dc2146ba6f4fcca',
    'PBR2G.dat': '3744314f582fd0930147dbad7cb8889cebd443676a6f69c9a7264de363082be8',
}

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def check(name, ok):
    print(('PASS' if ok else 'FAIL'), name)
    return bool(ok)

def descriptors(p):
    b=p.read_bytes()
    assert b[:8] == b'UPGR_FMT'
    # Descriptor format is mixed-endian in these packages: type LE32, length BE32.
    d=[]
    for o in range(0x50,0x78,8):
        d.append((int.from_bytes(b[o:o+4],'little'), int.from_bytes(b[o+4:o+8],'big')))
    return d

def segments(p):
    b=p.read_bytes(); d=descriptors(p); off=0; out=[]
    for typ,ln in d:
        out.append((typ,b[off:off+ln])); off+=ln
    assert off == len(b)
    return out

def bpbinf(p):
    b=p.read_bytes(); assert len(b)==512
    return {
      'oem':b[3:11].decode('ascii','replace'), 'bps':struct.unpack_from('<H',b,11)[0],
      'spc':b[13], 'reserved':struct.unpack_from('<H',b,14)[0], 'fats':b[16],
      'root_entries':struct.unpack_from('<H',b,17)[0], 'media':b[21],
      'spf16':struct.unpack_from('<H',b,22)[0], 'hidden':struct.unpack_from('<I',b,28)[0],
      'total32':struct.unpack_from('<I',b,32)[0], 'fs':b[54:62].decode('ascii','replace'),
      'sig':b[510:512]
    }

def common_prefix(a,b):
    n=0
    for x,y in zip(a,b):
        if x!=y: break
        n+=1
    return n

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('extracted_dir', type=Path)
    ap.add_argument('--e405-dll', type=Path)
    args=ap.parse_args(); root=args.extracted_dir
    ok=True
    print('== hashes ==')
    for fn,h in EXPECTED.items():
        p=root/fn; ok &= check(f'exact {fn}', p.exists() and sha(p)==h)

    ini=(root/'AuraF100.ini').read_text(encoding='latin1',errors='replace')
    print('\n== updater configuration ==')
    for token in [
      'ProductInfo=NWWM MEM AAD2','BootstrapVersion=2.1','BootstrapVersion=2.0',
      'NW_A600_2.00.00J_BOOT21.UPG','FWPackageWritePathName=\\MSFWUPGR.UPG',
      'StorageMediaFormatType=0','PBR512.dat','PBR1G.dat','PBR2G.dat']:
        ok &= check('INI '+token, token in ini)

    normal=root/'NW_A600_2.00.00J.UPG'; boot=root/'NW_A600_2.00.00J_BOOT21.UPG'
    nd=descriptors(normal); bd=descriptors(boot)
    print('\n== UPG descriptors ==')
    print('normal:',[(t,hex(n)) for t,n in nd])
    print('boot21:',[(t,hex(n)) for t,n in bd])
    ok &= check('normal large record type 4 / 0x1f8018', nd[3]==(4,0x1f8018))
    ok &= check('BOOT21 large record type 6 / 0x200018', bd[3]==(6,0x200018))
    ok &= check('large-record delta exactly 0x8000', bd[3][1]-nd[3][1]==0x8000)
    ok &= check('record-3 delta exactly 0x10', bd[2][1]-nd[2][1]==0x10)
    ns,bs=segments(normal),segments(boot)
    print('segment3 common prefix:',hex(common_prefix(ns[2][1],bs[2][1])))
    print('segment4 common prefix:',hex(common_prefix(ns[3][1],bs[3][1])))
    ok &= check('segment 4 is not a simple common-prefix extension', common_prefix(ns[3][1],bs[3][1])==0)

    print('\n== PBR templates ==')
    expected_caps={'PBR512.dat':511158784,'PBR1G.dat':1022333440,'PBR2G.dat':2044695040}
    for fn in expected_caps:
        x=bpbinf(root/fn); print(fn,x)
        ok &= check(fn+' FAT16 template', x['oem']=='        ' and x['bps']==512 and x['fats']==2 and x['fs']=='FAT16   ' and x['sig']==b'\x55\xaa')
        ok &= check(fn+' exact logical bytes', x['total32']*x['bps']==expected_caps[fn])

    dll=(root/'FWUpdaterCom.dll').read_bytes()
    print('\n== extended COM / vendor-query evidence ==')
    for token in [b'IFWUpdaterComExt',b'GetPowerStatus',b'GetDeviceInfo',b'CheckStorageFormatType',b'SendFWUpdateCommandExt',b'DEVINFO',b'PW_STAT']:
        ok &= check('DLL contains '+token.decode(), token in dll)
    # Exact known-hash binary instruction fingerprints around CDB builders.
    # Exact command reconstruction from the known-hash DLL:
    # GetPowerStatus -> FB 00 00 'PW_STAT' 20 00, DATA IN 32
    # GetDeviceInfo  -> FB 00 00 'DEVINFO' 80 00, DATA IN 128
    pwstat=bytes.fromhex('FB 00 00 50 57 5F 53 54 41 54 20 00')
    devinfo=bytes.fromhex('FB 00 00 44 45 56 49 4E 46 4F 80 00')
    ok &= check('GetPowerStatus builds opcode FB', dll[0x550c:0x5510]==bytes.fromhex('c6 45 e0 fb'))
    ok &= check('GetPowerStatus uses PW_STAT pointer and 32-byte allocation',
                struct.unpack_from('<I',dll,0x10280)[0]==0x10010290 and dll[0x10290:0x10297]==b'PW_STAT' and dll[0x551f:0x5523]==bytes.fromhex('c6 45 ea 20'))
    ok &= check('GetDeviceInfo builds opcode FB', dll[0x563a:0x563e]==bytes.fromhex('c6 45 e0 fb'))
    ok &= check('GetDeviceInfo uses DEVINFO pointer and 128-byte allocation',
                struct.unpack_from('<I',dll,0x10284)[0]==0x10010288 and dll[0x10288:0x1028f]==b'DEVINFO' and dll[0x5618:0x561d]==bytes.fromhex('bb 80 00 00 00'))
    print('PW_STAT CDB:',pwstat.hex(' '),'DATA IN 32')
    print('DEVINFO CDB:',devinfo.hex(' '),'DATA IN 128')

    # Disassembly is used only to pin the Sony raw-media validation shape.
    objdump='objdump'
    try:
        dis=subprocess.check_output([objdump,'-d','-Mintel',str(root/'FWUpdaterCom.dll')],text=True,errors='replace')
        ok &= check('CheckStorage uses READ(10) opcode 0x28', 'mov    BYTE PTR [ebp-0x1c],0x28' in dis)
        # The first 512-byte READ buffer begins at [ebp-0x238].  [ebp-0x72] is
        # exactly +0x1c6, i.e. MBR partition-entry #0 start-LBA at 446+8.
        ok &= check('CheckStorage reads MBR partition start at offset 0x1c6', 'push   DWORD PTR [ebp-0x72]' in dis)
        ok &= check('CheckStorage compares BPB ranges 12 bytes then 8 bytes',
                    re.search(r'10005838:.*push   0xc',dis) is not None and
                    re.search(r'10005854:.*push   0x8',dis) is not None)
        ok &= check('SendFWUpdateCommandExt contains gated FC/04 builder', 'mov    BYTE PTR [ebp+0x8],0xfc' in dis and 'mov    BYTE PTR [ebp+0xa],0x4' in dis)
    except Exception as e:
        print('WARN objdump unavailable:',e)

    if args.e405_dll:
        e=args.e405_dll.read_bytes()
        print('\n== E405 boundary check ==')
        for token in [b'IFWUpdaterComExt',b'DEVINFO',b'PW_STAT',b'CheckStorageFormatType']:
            ok &= check('E405 does NOT contain '+token.decode(), token not in e)
        print('NOTE: absence from the E405 updater proves only that Sony did not expose these A600 extension routines there; it does not prove the E405 firmware rejects opcode FB.')

    print('\nConclusion: A600 is related-model protocol evidence only. Never use A600 UPG/PBR data on an NW-E405.')
    return 0 if ok else 1
if __name__=='__main__': raise SystemExit(main())
