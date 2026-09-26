from pathlib import Path

SRC=(Path(__file__).resolve().parents[1]/"src/NW-E405-Recovery-Tool.c").read_text(encoding="utf-8")

def test_fb_pwstat_exact_cdb_and_data_in_helper():
    assert "BYTE pwCdb[12]={0xFB,0,0,'P','W','_','S','T','A','T',0x20,0};" in SRC
    assert "SendCdb(h,pwCdb,12,32)" in SRC

def test_fb_devinfo_exact_cdb_and_data_in_helper():
    assert "BYTE diCdb[12]={0xFB,0,0,'D','E','V','I','N','F','O',0x80,0};" in SRC
    assert "SendCdb(h,diCdb,12,128)" in SRC

def test_related_model_probe_requires_issue1_state():
    assert "g_issue1TurNoMedia&&g_issue1CapNoMedia&&g_issue1FwInfoMatch" in SRC

def test_related_model_probe_has_explicit_confirmation():
    assert "Recovery Stage 2A - Sony FB read probes" in SRC
    assert "MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2" in SRC

def test_public_report_distinguishes_probe_outcomes():
    for token in ["NOT ATTEMPTED","DECLINED","ATTEMPTED-FAILED","SUCCESS"]:
        assert token in SRC

def test_a3_remains_only_explicit_data_out():
    assert SRC.count("SCSI_IOCTL_DATA_OUT")==1
    assert "SendFixedA3SelectDeviceId" in SRC


def test_public_report_does_not_call_unreadable_upg_mismatch():
    assert "Root MSFWUPGR.UPG exact official match: NOT CHECKED (LBA0 unreadable)" in SRC
    assert "Recovery resume eligibility: NOT EVALUABLE (logical media unreadable)" in SRC
