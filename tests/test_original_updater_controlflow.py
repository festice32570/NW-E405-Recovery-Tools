from pathlib import Path
import hashlib, struct
DLL=Path('/home/festice/nw_e405_recovery/extracted/NW-E40X_V2_0J/FWUpdaterCom.dll')
EXE=Path('/home/festice/nw_e405_recovery/extracted/NW-E40X_V2_0J/FWUpdater.exe')
DLL_SHA='525e44f9eff91fb6c07a67f6c3d76363bc2e5f243d0e74a573d1120d747f8799'
EXE_SHA='df5d20736d7c99922ade9c682a1352311fa2776ba7bec34d99de07d68e242fd6'

def u32(b,o): return struct.unpack_from('<I',b,o)[0]

def test_exact_original_binaries():
    if not DLL.exists() or not EXE.exists(): return
    assert hashlib.sha256(DLL.read_bytes()).hexdigest()==DLL_SHA
    assert hashlib.sha256(EXE.read_bytes()).hexdigest()==EXE_SHA

def test_copy_failure_is_caught_before_fc04():
    if not DLL.exists(): return
    b=DLL.read_bytes()
    # SendFWUpdateCommand has an MSVC EH frame. CopyFile failure enters the
    # exception helper; FuncInfo maps that exception to handler 0x10005287.
    assert b[0x50c8:0x50d2] == bytes.fromhex('b88cba0010e806120000')
    assert b[0x51dc:0x51e2] == bytes.fromhex('ff158cc00010')
    assert b[0x51e6:0x51ef] == bytes.fromhex('ff15d8c0001083f870')
    assert u32(b,0xcf30)==0x19930520
    assert u32(b,0xcf3c)==1
    assert u32(b,0xcf40)==0x1000cf68
    assert u32(b,0xcf74)==1
    assert u32(b,0xcf78)==0x1000cf80
    assert u32(b,0xcf8c)==0x10005287
    # Catch handler returns continuation 0x1000529A, bypassing FC/04 at 0x5222.
    assert b[0x5287:0x529a] == bytes.fromhex('837dec007c07c745ec01800480b89a520010c3')
    assert b[0x5222:0x522a] == bytes.fromhex('c6450cfcc6450e04')

def test_99_percent_is_post_start_wait():
    if not EXE.exists(): return
    b=EXE.read_bytes()
    # vtable +0x1c = SendFWUpdateCommand; only after success does the timed wait run.
    assert b[0x4ad9:0x4ade] == bytes.fromhex('ff521c3bc3')
    assert b[0x4c00:0x4c0a] == bytes.fromhex('83f8647c05b863000000')  # clamp 100+ to 99
    assert b[0x4cc0:0x4cca] == bytes.fromhex('6a646a00680504000053')  # completion posts 100

def test_timer_and_default_timeout_math():
    if not EXE.exists(): return
    b=EXE.read_bytes()
    assert b[0x25ac:0x25bf] == bytes.fromhex('8d044068b00041006a008d14808b45ecc1e202')
    assert b[0x2669:0x267c] == bytes.fromhex('8b4dec8b415485c076098bd0d1ea03d0895158')
