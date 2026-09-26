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


def test_public_report_includes_safe_scsi_failure_details():
    for token in [
        "LBA0 READ(10) result", "FB/PW_STAT SCSI result", "FB/DEVINFO SCSI result",
        "A3 fixed select SCSI result", "A4 Device-ID read SCSI result",
        "SCSI=0x%02X Sense=%02X/%02X/%02X"
    ]:
        assert token in SRC

def test_stage2_revalidates_live_issue1_state():
    assert 'RevalidateIssue1State(h,L"Stage 2A live preflight",&g_pubStage2aPreflight)' in SRC
    assert 'RevalidateIssue1State(h,L"Stage 2B live preflight",&g_pubStage2bPreflight)' in SRC
    assert "identity=%s TUR3A00=%s CAP3A00=%s FC03-known=%s" in SRC

def test_a3_and_a4_are_reported_separately():
    assert "A3 fixed select SCSI result" in SRC
    assert "A4 Device-ID read SCSI result" in SRC
    assert "BLOCKED-PREFLIGHT" in SRC

def test_public_issue_instruction_never_requests_private_logs():
    assert "TXT/JSONLと一緒にIssue #1へ添付してください" not in SRC
    assert "PUBLIC upload rule: attach only this NW-E405_PUBLIC_REPORT_*.txt" in SRC
    assert "Do NOT attach these to the public issue" in SRC
