from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sonyicd_spec import *


def test_target_identifier_exact_cdb():
    assert build_cdb(0x01) == bytes.fromhex('FC 00 01 53 4F 4E 59 49 43 44 00 74')


def test_preference_exact_cdb():
    assert build_cdb(0x02) == bytes.fromhex('FC 00 02 53 4F 4E 59 49 43 44 00 48')


def test_command_families():
    assert transfer_family(0x01) == 'in'
    assert transfer_family(0x41) == 'out'
    assert transfer_family(0x80) == 'none'
    assert transfer_family(0xC0) == 'unsupported'


def test_only_get_commands_are_live_probe_candidates():
    assert READ_ONLY_PROBE_COMMANDS == (0x01, 0x02)
    assert all(COMMANDS[c].transfer == 'in' for c in READ_ONLY_PROBE_COMMANDS)
    assert all(COMMANDS[c].transfer != 'out' for c in READ_ONLY_PROBE_COMMANDS)


def test_target_identifier_raw_fields_are_not_exposed():
    r = bytearray(0x74)
    r[0x0F] = 7
    r[0x24:0x30] = b'PRIVATE-DATA'
    s = target_identifier_safe_summary(bytes(r))
    assert set(s) == {'status', 'length', 'sha256'}
    assert s['status'] == 7 and s['length'] == 0x74
    assert 'PRIVATE' not in repr(s)


def test_target_identifier_requires_exact_length():
    try:
        target_identifier_status(b'\0' * 0x73)
        assert False
    except ValueError:
        pass
