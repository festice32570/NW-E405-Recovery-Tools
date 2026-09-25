from pathlib import Path
import hashlib
DLL=Path('/home/festice/nw_e405_recovery/extracted/NW-E40X_V2_0J/FWUpdaterCom.dll')
SHA='525e44f9eff91fb6c07a67f6c3d76363bc2e5f243d0e74a573d1120d747f8799'

def test_exact_original_dll():
    if not DLL.exists(): return
    assert hashlib.sha256(DLL.read_bytes()).hexdigest()==SHA

def test_copy_failure_converges_on_fc04():
    if not DLL.exists(): return
    b=DLL.read_bytes()
    # CopyFileA call; success JNE -> 0x521f. Failure falls through error handling
    # and reaches the same 0x521f block without a return/branch around FC04.
    assert b[0x51dc:0x51e6] == bytes.fromhex('ff158cc000103bc37539')
    assert b[0x51e6:0x51ef] == bytes.fromhex('ff15d8c0001083f870')  # GetLastError / ERROR_DISK_FULL
    assert b[0x521f:0x522a] == bytes.fromhex('8b4740c6450cfcc6450e04')

def test_fc04_is_no_data_command_builder():
    if not DLL.exists(): return
    b=DLL.read_bytes()
    assert b[0x5222:0x522a] == bytes.fromhex('c6450cfcc6450e04')
