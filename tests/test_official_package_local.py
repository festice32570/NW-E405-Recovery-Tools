from pathlib import Path
import hashlib, zipfile, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from upg_analyzer import parse_bytes

PACKAGE=Path('/home/festice/nw_e405_recovery/NW-E40X_V2_0J.exe')
EXE_SHA='8b68cf41d193464439e8139aa593ebcf887d2dd0a2220a6135039b3ebf7a7eb7'
ENTRY='NW-E40X_V2_0J/MSFWUPGR_NW-E40X_201J.UPG'

def _available(): return PACKAGE.exists()

def test_official_exe_hash():
 if not _available(): return
 b=PACKAGE.read_bytes(); assert len(b)==2291724; assert hashlib.sha256(b).hexdigest()==EXE_SHA

def test_official_zip_payload_exact():
 if not _available(): return
 with zipfile.ZipFile(PACKAGE) as z:
  assert ENTRY in z.namelist()
  data=z.read(ENTRY)
 info=parse_bytes(data)
 assert info.exact_japanese_e40x
 assert info.size==2131380

def test_zip_crc_integrity():
 if not _available(): return
 with zipfile.ZipFile(PACKAGE) as z:
  assert z.testzip() is None
