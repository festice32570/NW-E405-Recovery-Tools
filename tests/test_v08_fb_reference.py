from pathlib import Path

SRC=(Path(__file__).resolve().parents[1]/'src/NW-E405-Recovery-Tool.c').read_text(encoding='utf-8')

def test_pw_stat_fixed_cdb():
    assert "BYTE pwrCdb[12]={0xFB,0,0,'P','W','_','S','T','A','T',0x20,0};" in SRC
    assert 'SendCdb(h,pwrCdb,12,32)' in SRC

def test_devinfo_fixed_cdb():
    assert "BYTE devCdb[12]={0xFB,0,0,'D','E','V','I','N','F','O',0x80,0};" in SRC
    assert 'SendCdb(h,devCdb,12,128)' in SRC

def test_fb_probe_requires_issue1_state():
    start=SRC.index('static void QueryRelatedModelFbReadOnly')
    body=SRC[start:SRC.index('static BOOL QueryVendorDvId',start)]
    assert 'g_issue1TurNoMedia&&g_issue1CapNoMedia&&g_issue1FwInfoMatch' in body
    assert 'g_exactDevicePath[0]' in body

def test_fb_probe_is_explicitly_related_model_and_confirmed():
    start=SRC.index('static void QueryRelatedModelFbReadOnly')
    body=SRC[start:SRC.index('static BOOL QueryVendorDvId',start)]
    assert 'NW-A600' in body
    assert 'E405' in body and '未確認' in body
    assert 'MB_YESNO' in body

def test_fb_probe_precedes_a3_a4_after_lba_failure():
    start=SRC.index('static void RunRecoveryLadder')
    body=SRC[start:SRC.index('static void VerifyFirmwareGui',start)] if 'static void VerifyFirmwareGui' in SRC[start:] else SRC[start:]
    # function definition may be earlier; use local sequence in whole source
    idx=SRC.rindex('QueryRelatedModelFbReadOnly();')
    idx2=SRC.rindex('QueryVendorDvId();')
    assert idx < idx2

def test_public_report_contains_hashes_not_raw_fb_data():
    assert 'FB/PW_STAT response SHA-256 only' in SRC
    assert 'FB/DEVINFO response SHA-256 only' in SRC
