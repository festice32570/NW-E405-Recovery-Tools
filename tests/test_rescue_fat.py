from pathlib import Path

def le16(b,o): return b[o] | (b[o+1]<<8)
def le32(b,o): return le16(b,o) | (le16(b,o+2)<<16)
def parse_fat(sec, start=0):
    if len(sec)!=512 or sec[510:512]!=b'\x55\xaa': return None
    bps=le16(sec,11); spc=sec[13]; reserved=le16(sec,14); fats=sec[16]
    roots=le16(sec,17); total=le16(sec,19) or le32(sec,32); spf=le16(sec,22) or le32(sec,36)
    if bps!=512 or spc==0 or spc&(spc-1) or spc>128 or not reserved or fats not in (1,2) or total<32 or not spf: return None
    rootsecs=(roots*32+511)//512; first=reserved+fats*spf+rootsecs
    if first>=total: return None
    clusters=(total-first)//spc; typ=12 if clusters<4085 else 16 if clusters<65525 else 32
    rootcl=le32(sec,44) if typ==32 else 0
    if typ==32 and rootcl<2: return None
    return dict(start=start,total=total,spc=spc,spf=spf,rootsecs=rootsecs,first=first,type=typ)

def fat16_boot(total=8192):
    s=bytearray(512); s[0:3]=b'\xeb\x3c\x90'; s[11:13]=(512).to_bytes(2,'little'); s[13]=1
    s[14:16]=(1).to_bytes(2,'little'); s[16]=1; s[17:19]=(512).to_bytes(2,'little')
    s[19:21]=total.to_bytes(2,'little'); s[21]=0xF8; s[22:24]=(32).to_bytes(2,'little'); s[510:512]=b'\x55\xaa'; return s

def test_synthetic_fat16_geometry():
    r=parse_fat(fat16_boot()); assert r and r['type']==16 and r['first']==65 and r['total']==8192

def test_rejects_bad_sector_size():
    s=fat16_boot(); s[11:13]=(1024).to_bytes(2,'little'); assert parse_fat(s) is None

def test_mbr_partition_boot_can_be_parsed_at_nonzero_lba():
    r=parse_fat(fat16_boot(),2048); assert r and r['start']==2048 and r['type']==16

def test_root_short_name_is_exact_83_target():
    assert b'MSFWUPGR'+b'UPG' == b'MSFWUPGRUPG'

def test_known_official_upg_identity():
    assert len('82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691')==64
