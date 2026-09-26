#!/usr/bin/env python3
"""Compare UPGR_FMT records at aligned block granularity.

Research-only utility.  It does not attempt to decrypt payloads and deliberately
labels chaining/block-cipher interpretations as hypotheses rather than facts.
"""
from pathlib import Path
import argparse, hashlib


def parse(path: Path):
    b=path.read_bytes()
    if len(b)<0x80 or b[:8]!=b'UPGR_FMT' or b[0x10:0x14]!=b'SONY':
        raise ValueError(f'{path}: not the known UPGR_FMT layout')
    ds=[]
    for off in range(0x50,0x78,8):
        ds.append((int.from_bytes(b[off:off+4],'little'), int.from_bytes(b[off+4:off+8],'big')))
    if sum(n for _,n in ds)!=len(b):
        raise ValueError(f'{path}: descriptor lengths do not sum to file size')
    out=[]; off=0
    for typ,n in ds:
        out.append((typ,b[off:off+n])); off+=n
    return b,out


def common_prefix(a: bytes,b: bytes):
    for i,(x,y) in enumerate(zip(a,b)):
        if x!=y:return i
    return min(len(a),len(b))


def aligned_equal_stats(a: bytes,b: bytes,block=8):
    n=min(len(a),len(b)); same=[]
    for off in range(0,n-block+1,block):
        if a[off:off+block]==b[off:off+block]: same.append(off)
    first=common_prefix(a,b)
    later=[x for x in same if x >= ((first+block-1)//block)*block]
    return first,same,later


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('a',type=Path); ap.add_argument('b',type=Path); ap.add_argument('--block',type=int,default=8)
    ns=ap.parse_args(); A,ar=parse(ns.a); B,br=parse(ns.b)
    print('A',ns.a,'sha256',hashlib.sha256(A).hexdigest(),'model',A[0x20:0x28].decode('ascii','replace'))
    print('B',ns.b,'sha256',hashlib.sha256(B).hexdigest(),'model',B[0x20:0x28].decode('ascii','replace'))
    for i,((ta,a),(tb,b)) in enumerate(zip(ar,br),1):
        cp,same,later=aligned_equal_stats(a,b,ns.block)
        print(f'record {i}: type {ta}/{tb} len 0x{len(a):X}/0x{len(b):X} common_prefix=0x{cp:X} equal_aligned_{ns.block}B={len(same)} later_equal={len(later)}')
        if i in (3,4) and cp < min(len(a),len(b)) and cp % ns.block == 0 and not later:
            print('  observation: divergence begins on an aligned block and does not re-synchronize at the same block positions')
    print('NOTE: this pattern can be consistent with a chained block transform, but does not identify encryption, cipher, key, IV, compression, or physical flash mapping.')
if __name__=='__main__': main()
