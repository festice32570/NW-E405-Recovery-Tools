#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib, struct, sys

E40X_J_SIZE = 2131380
E40X_J_SHA256 = '82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691'
E40X_MODEL_ID = b'00100000'
E50X_MODEL_ID = b'00110000'
EXPECTED_SECTION_TYPES = (1, 2, 3, 4, 5)
EXPECTED_SECTION_LENGTHS = (0x50, 0x30, 0x10518, 0x1F8018, 0x04)

@dataclass(frozen=True)
class UpgInfo:
    size: int
    sha256: str
    magic_ok: bool
    sony_ok: bool
    model_id: bytes
    section_types: tuple[int, ...]
    section_lengths: tuple[int, ...]
    structure_ok: bool
    exact_japanese_e40x: bool
    reason: str


def parse_bytes(data: bytes) -> UpgInfo:
    size=len(data); sha=hashlib.sha256(data).hexdigest()
    magic_ok=size >= 0x80 and data[:8] == b'UPGR_FMT'
    sony_ok=size >= 0x20 and data[0x10:0x14] == b'SONY'
    model=data[0x20:0x28] if size >= 0x28 else b''
    types=[]; lengths=[]
    if size >= 0x78:
        for off in range(0x50,0x78,8):
            # Descriptor format observed across official E40X/E50X/A600 packages:
            # type is LE32, length is BE32. BOOT-aware A600 packages demonstrate
            # that type is semantic (normal large record=4, BOOT21 large record=6).
            types.append(int.from_bytes(data[off:off+4], 'little'))
            lengths.append(int.from_bytes(data[off+4:off+8], 'big'))
    types=tuple(types); lengths=tuple(lengths)
    structure_ok=(magic_ok and sony_ok and types == EXPECTED_SECTION_TYPES and lengths == EXPECTED_SECTION_LENGTHS and sum(lengths)==size)
    exact=(structure_ok and model==E40X_MODEL_ID and size==E40X_J_SIZE and sha==E40X_J_SHA256)
    if exact: reason='Exact Sony Japan NW-E40X v2.0 UPG'
    elif not magic_ok: reason='Invalid UPGR_FMT magic'
    elif not sony_ok: reason='Invalid vendor marker'
    elif model==E50X_MODEL_ID: reason='Wrong model family: E50X package'
    elif model!=E40X_MODEL_ID: reason='Unknown/wrong model identifier'
    elif types != EXPECTED_SECTION_TYPES: reason='Unexpected section types'
    elif lengths != EXPECTED_SECTION_LENGTHS: reason='Unexpected section table'
    elif sum(lengths) != size: reason='Truncated/extended package'
    else: reason='Structurally E40X-like but hash is not approved Japanese v2.0 image'
    return UpgInfo(size,sha,magic_ok,sony_ok,model,types,lengths,structure_ok,exact,reason)


def parse(path: Path) -> UpgInfo:
    return parse_bytes(path.read_bytes())


def main(argv):
    if len(argv)!=2:
        print('usage: upg_analyzer.py <MSFWUPGR*.UPG>'); return 2
    p=Path(argv[1]); info=parse(p)
    print('file:',p)
    print('size:',info.size)
    print('sha256:',info.sha256)
    print('magic:',info.magic_ok,'sony:',info.sony_ok)
    print('model_id:',info.model_id.decode('ascii','replace'))
    print('section_types:',','.join(str(x) for x in info.section_types))
    print('sections:',','.join(hex(x) for x in info.section_lengths))
    print('structure_ok:',info.structure_ok)
    print('APPROVED_E40X_J:',info.exact_japanese_e40x)
    print('reason:',info.reason)
    return 0 if info.exact_japanese_e40x else 1

if __name__=='__main__': raise SystemExit(main(sys.argv))
