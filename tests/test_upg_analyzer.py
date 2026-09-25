from pathlib import Path
import hashlib, random, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from upg_analyzer import *

def synthetic(model=E40X_MODEL_ID, total=True):
    size=sum(EXPECTED_SECTION_LENGTHS)
    b=bytearray(size)
    b[:8]=b'UPGR_FMT'; b[0x10:0x14]=b'SONY'; b[0x20:0x28]=model
    for i,(off,l) in enumerate(zip(range(0x50,0x78,8),EXPECTED_SECTION_LENGTHS),1):
        b[off]=i; b[off+4:off+8]=l.to_bytes(4,'big')
    return bytes(b)

def test_structure_e40():
    i=parse_bytes(synthetic()); assert i.structure_ok and not i.exact_japanese_e40x

def test_wrong_family():
    i=parse_bytes(synthetic(E50X_MODEL_ID)); assert not i.exact_japanese_e40x and 'E50X' in i.reason

def test_truncated():
    i=parse_bytes(synthetic()[:-1]); assert not i.structure_ok

def test_extended():
    i=parse_bytes(synthetic()+b'X'); assert not i.structure_ok

def test_bad_magic():
    b=bytearray(synthetic()); b[0]=0; assert not parse_bytes(bytes(b)).structure_ok

def test_bad_vendor():
    b=bytearray(synthetic()); b[0x10]=0; assert not parse_bytes(bytes(b)).structure_ok

def test_bad_table():
    b=bytearray(synthetic()); b[0x57]^=1; assert not parse_bytes(bytes(b)).structure_ok

def test_mutation_rejected_as_exact():
    b=bytearray(synthetic())
    rnd=random.Random(405)
    for _ in range(5000):
        c=bytearray(b); j=rnd.randrange(len(c)); c[j]^=1+rnd.randrange(255)
        assert not parse_bytes(bytes(c)).exact_japanese_e40x
