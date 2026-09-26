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


def test_sonyicd_target_exact_read_only_cdb():
    assert "BYTE cdb[12]={0xFC,0,0x01,'S','O','N','Y','I','C','D',0x00,0x74};" in SRC
    assert "SendCdb(h,cdb,12,0x74)" in SRC
    assert "rd.returnedDataLen!=0x74 || rd.dataLen!=0x74" in SRC

def test_sonyicd_target_is_separately_gated_and_revalidated():
    assert "Recovery Stage 2C - E405 SONYICD read probe" in SRC
    assert 'RevalidateIssue1State(h,L"Stage 2C live preflight",&g_pubStage2cPreflight)' in SRC
    assert "MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2" in SRC

def test_sonyicd_public_report_keeps_raw_response_private():
    assert "SONYICD 0x01 application status byte" in SRC
    assert "SONYICD 0x01 response SHA-256 only" in SRC
    assert "No identifier strings or decoded fields are written to the public report." in SRC
    assert 'SavePrivateBlob(L"SONYICD_TARGETID"' in SRC

def test_sonyicd_set_and_reset_commands_are_not_live_probes():
    for cmd in ("0x41","0x42","0x43","0x44","0x45","0x80"):
        assert f"{{0xFC,0,{cmd},'S','O','N','Y','I','C','D'" not in SRC

def test_data_in_result_uses_actual_sptd_transfer_length():
    assert "r.returnedDataLen = (ok && dataLen) ? pkt.sptd.DataTransferLength : 0;" in SRC
    assert "DWORD actualLen = r.returnedDataLen;" in SRC
    assert "r.dataLen = actualLen;" in SRC
