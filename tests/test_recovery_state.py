from pathlib import Path
import itertools, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from recovery_state import *

def base(**kw):
 d=dict(exact_usb=True,exact_scsi=True,tur_3a00=True,capacity_3a00=True,fc03_good=True,fw_info=KNOWN_FW_INFO)
 d.update(kw); return Snapshot(**d)

def test_issue1_is_post_start_not_fc04_retry(): assert decide(base()) is Action.FAILED_POST_START
def test_wrong_pid_blocks(): assert decide(base(exact_usb=False)) is Action.BLOCK
def test_wrong_scsi_blocks(): assert decide(base(exact_scsi=False)) is Action.BLOCK
def test_bad_fc03_readonly(): assert decide(base(fc03_good=False)) is Action.READ_ONLY_DIAG
def test_unknown_fw_readonly(): assert decide(base(fw_info=b'12345678')) is Action.READ_ONLY_DIAG
def test_normal_update_requires_all_safety_gates():
 s=base(tur_3a00=False,capacity_3a00=False,media_writable=True,free_bytes=SAFE_MIN_FREE,
        firmware_verified=True,metadata_backup_complete=True,storage_backup_complete=True)
 assert decide(s) is Action.NORMAL_UPDATE_POSSIBLE
def test_under_safe_margin_never_normal():
 s=base(tur_3a00=False,capacity_3a00=False,media_writable=True,free_bytes=SAFE_MIN_FREE-1,
        firmware_verified=True,metadata_backup_complete=True,storage_backup_complete=True)
 assert decide(s) is Action.READ_ONLY_DIAG
def test_missing_any_preflight_never_normal():
 names=['firmware_verified','metadata_backup_complete','storage_backup_complete']
 for missing in names:
  kw=dict(tur_3a00=False,capacity_3a00=False,media_writable=True,free_bytes=SAFE_MIN_FREE,
          firmware_verified=True,metadata_backup_complete=True,storage_backup_complete=True)
  kw[missing]=False
  assert decide(base(**kw)) is Action.READ_ONLY_DIAG

def test_exhaustive_boolean_gate_space():
 # Exhaust every boolean combination around the normal-update path.
 fields=['exact_usb','exact_scsi','fc03_good','media_writable','firmware_verified','metadata_backup_complete','storage_backup_complete']
 for values in itertools.product([False,True], repeat=len(fields)):
  kw=dict(zip(fields,values))
  kw.update(tur_3a00=False,capacity_3a00=False,fw_info=KNOWN_FW_INFO,free_bytes=SAFE_MIN_FREE)
  a=decide(Snapshot(**kw))
  if a is Action.NORMAL_UPDATE_POSSIBLE:
   assert all(kw[x] for x in fields)
