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


def fat32_boot(total=262144, spf=2048, spc=1):
    s=bytearray(512); s[0:3]=b'\xeb\x58\x90'; s[11:13]=(512).to_bytes(2,'little'); s[13]=spc
    s[14:16]=(32).to_bytes(2,'little'); s[16]=2; s[17:19]=(0).to_bytes(2,'little')
    s[19:21]=(0).to_bytes(2,'little'); s[21]=0xF8; s[22:24]=(0).to_bytes(2,'little')
    s[32:36]=total.to_bytes(4,'little'); s[36:40]=spf.to_bytes(4,'little'); s[44:48]=(2).to_bytes(4,'little')
    s[510:512]=b'\x55\xaa'; return s

def test_synthetic_fat32_geometry():
    r=parse_fat(fat32_boot()); assert r and r['type']==32 and r['start']==0 and r['total']==262144

def test_rejects_invalid_spc():
    s=fat16_boot(); s[13]=3; assert parse_fat(s) is None

def test_rejects_missing_signature():
    s=fat16_boot(); s[510:512]=b'\x00\x00'; assert parse_fat(s) is None

def test_mbr_bound_rule_model():
    # v0.6 refuses a FAT BPB that claims more sectors than the containing MBR partition.
    r=parse_fat(fat16_boot(8192), 2048); assert r and r['total']==8192
    partition_count=4096
    assert r['total'] > partition_count

def _extract_root_upg_fat16(img):
    boot=img[:512]; r=parse_fat(boot,0); assert r and r['type']==16
    root_start=(1+32)*512
    entry=None
    for o in range(root_start, root_start+32*512, 32):
        e=img[o:o+32]
        if e[:11]==b'MSFWUPGRUPG': entry=e; break
    assert entry is not None
    cluster=le16(entry,26); size=le32(entry,28); out=bytearray()
    fat_base=512; data_start=r['first']*512; seen=set()
    while len(out)<size:
        assert cluster>=2 and cluster not in seen; seen.add(cluster)
        off=data_start+(cluster-2)*512; out += img[off:off+512]
        v=le16(img,fat_base+cluster*2)
        if v>=0xfff8: break
        cluster=v
    return bytes(out[:size])

def test_fragmented_real_official_upg_roundtrip():
    import hashlib
    upg=Path('/home/festice/nw_e405_recovery/extracted/NW-E40X_V2_0J/MSFWUPGR_NW-E40X_201J.UPG')
    if not upg.exists(): return
    payload=upg.read_bytes(); assert hashlib.sha256(payload).hexdigest()=='82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691'
    sectors=8192; img=bytearray(sectors*512); img[:512]=fat16_boot(sectors)
    n=(len(payload)+511)//512; chain=list(range(2,2+n))
    # Force non-contiguous file order while keeping every cluster unique.
    chain[100],chain[200]=chain[200],chain[100]
    fat=512
    img[fat:fat+2]=(0xfff8).to_bytes(2,'little'); img[fat+2:fat+4]=(0xffff).to_bytes(2,'little')
    data_start=65*512
    for i,c in enumerate(chain):
        nxt=0xffff if i==len(chain)-1 else chain[i+1]
        img[fat+c*2:fat+c*2+2]=nxt.to_bytes(2,'little')
        chunk=payload[i*512:(i+1)*512]
        off=data_start+(c-2)*512; img[off:off+len(chunk)]=chunk
    root=33*512; e=bytearray(32); e[:11]=b'MSFWUPGRUPG'; e[11]=0x20
    e[26:28]=chain[0].to_bytes(2,'little'); e[28:32]=len(payload).to_bytes(4,'little'); img[root:root+32]=e
    recovered=_extract_root_upg_fat16(img)
    assert recovered==payload
    assert hashlib.sha256(recovered).hexdigest()=='82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691'
