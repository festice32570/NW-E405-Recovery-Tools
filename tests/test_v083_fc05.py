from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SRC=(ROOT/"src/NW-E405-Recovery-Tool.c").read_text(encoding="utf-8")
README=(ROOT/"README.md").read_text(encoding="utf-8")
BUILD=(ROOT/"BUILD.md").read_text(encoding="utf-8")
RESEARCH=(ROOT/"docs/RESEARCH.md").read_text(encoding="utf-8")

def func(name):
    marker=f"static void {name}("
    start=SRC.rindex(marker)
    end=SRC.find("\nstatic ", start+len(marker))
    return SRC[start:] if end<0 else SRC[start:end]

FC05=func("ProbeE40xFc05DeviceId")
DIAG=SRC[SRC.index("static BOOL ProbeDiskInterface("):SRC.index("\nstatic int EnumerateDisks(")]
REPORT=func("SavePublicReport")
RUN=func("RunRecoveryLadder")

def test_fc05_exact_12_byte_cdb_and_data_in_16():
    exact="static const BYTE cdb[12]={0xFC,0x00,0x05,0x72,0x6F,0x67,0x61,0x00,0x00,0x10,0x00,0x00};"
    assert exact in FC05
    assert "SendCdb(h,cdb,12,16)" in FC05
    assert FC05.count("SendCdb(h,cdb,12,16)")==1

def test_signatureless_fc05_removed_from_ordinary_diagnostics():
    assert "cdb[2] = 0x05" not in DIAG
    assert "cdb[2]=0x05" not in DIAG
    assert "ProbeE40xFc05DeviceId" not in DIAG

def test_fc05_has_fresh_issue1_preflight_and_confirmation():
    assert 'RevalidateIssue1State(h,L"Stage 2D live preflight",&g_pubStage2dPreflight)' in FC05
    assert "Issue #1 state is not currently established" in FC05
    assert "MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2" in FC05
    assert "Recovery Stage 2D - authentic E40X FC/05+roga" in SRC

def test_fc05_is_one_shot_with_no_retry_or_write_followup():
    assert FC05.count("SendCdb(")==1
    assert "while(" not in FC05 and "for(" not in FC05
    assert "No retry, DATA OUT, FC/04, or follow-up vendor command" in FC05
    assert "SCSI_IOCTL_DATA_OUT" not in FC05

def test_fc05_rejects_ioctl_scsi_and_nonexact_lengths():
    gate="!rd.ioctlOk || rd.scsiStatus!=0 || rd.returnedDataLen!=16 || rd.dataLen!=16"
    assert gate in FC05
    assert "short, zero-length, over-length, CHECK CONDITION, non-GOOD, or IOCTL-failed responses are rejected" in FC05

def test_fc05_all_zero_and_partial_zero_have_no_content_gate():
    assert "memcmp" not in FC05
    assert "rd.data[" not in FC05
    assert "All-zero or partially-zero content is not assigned any device-side semantic meaning." in FC05

def test_fc05_raw_is_private_and_public_is_hash_only():
    assert 'SavePrivateBlob(L"FC05_DEVICEID",rd.data,16,g_fc05DeviceIdSha256)' in FC05
    assert "ShowScsiResultRedacted" in FC05
    assert "E40X FC/05+roga response SHA-256 only" in REPORT
    assert "g_fc05DeviceIdRead&&g_fc05DeviceIdState==PROBE_SUCCESS" in REPORT
    assert "raw FC/05 pbDeviceId" in REPORT
    assert "BytesToHex" not in REPORT

def test_public_fc05_summary_has_requested_and_actual_length():
    assert "Requested=%lu Actual=%lu" in SRC
    assert "requestedDataLen=src->requestedDataLen" in SRC
    assert "actualDataLen=src->returnedDataLen" in SRC

def test_only_fixed_a3_remains_data_out():
    assert SRC.count("SCSI_IOCTL_DATA_OUT")==1
    assert "SendFixedA3SelectDeviceId" in SRC

def test_fc04_gate_is_unchanged_and_not_reachable_from_fc05_probe():
    assert "g_rootPackageIntact&&g_resumeEligible&&g_officialFirmwareVerified" in SRC
    assert "RevalidateIssue1BeforeWrite" in SRC
    assert "SendCdb(h,cdb,12,0)" in SRC
    assert "ResumeVerifiedUpdate(" not in FC05

def test_stage2d_is_offered_before_legacy_stage2a_2b_2c():
    assert RUN.index("int fc05ans=MessageBoxW") < RUN.index("int fbans=MessageBoxW")
    assert RUN.index("int fc05ans=MessageBoxW") < RUN.index("int a3ans=MessageBoxW")
    assert RUN.index("int fc05ans=MessageBoxW") < RUN.index("int icdans=MessageBoxW")


def test_stage2d_selection_terminates_ladder_without_legacy_fallthrough():
    assert "if(fc05ans==IDYES){ProbeE40xFc05DeviceId();SavePublicReport();return;}" in RUN
    yes_end=RUN.index("if(fc05ans==IDYES){ProbeE40xFc05DeviceId();SavePublicReport();return;}")
    assert RUN.index("int fbans=MessageBoxW") > yes_end


def test_legacy_stage2_probes_are_only_after_stage2d_outer_decline():
    decline="g_fc05DeviceIdState=PROBE_DECLINED;g_stage2dPreflightState=PROBE_NOT_ATTEMPTED"
    assert decline in RUN
    assert RUN.index(decline) < RUN.index("int fbans=MessageBoxW")
    assert "Stage 2D was declined before preflight. Legacy Stage 2A/2B/2C research probes may now be offered separately." in RUN


def test_current_safety_docs_match_allowed_a3_and_gated_fc04():
    assert "The current main branch does not contain `FC/04`, SCSI DATA OUT" not in RESEARCH
    assert "exactly one explicit SCSI DATA OUT implementation: the fixed A3 Device-ID select" in RESEARCH
    assert "exactly one FC/04 update-start builder" in RESEARCH
    assert "Stage 2D FC/05+`roga` itself is DATA IN only" in RESEARCH
    assert "release validation rejects SCSI DATA OUT, FC/04" not in BUILD
    assert "permits exactly one explicit DATA OUT implementation" in BUILD
    assert "exactly one existing gated FC/04 builder" in BUILD
    assert "現在のmain/v0.6.1-devは読み取り専用です" not in README


def test_v082_signatureless_result_is_preserved_as_history():
    assert "signature-less CDB `FC 00 05 00 00 00 00 00 00 10 00 00`" in README
    assert "05/20/00" in README
    assert "support/unsupported" in README
