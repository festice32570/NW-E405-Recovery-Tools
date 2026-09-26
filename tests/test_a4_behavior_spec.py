from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from a4_behavior_spec import *


def test_exact_cdb():
    assert build_cdb() == bytes.fromhex('A4 00 00 00 00 00 00 BC 04 04 33 00')


def test_mode_bit_offset_and_behavior_mapping():
    r=bytearray(RESPONSE_LEN)
    assert mode_bit(bytes(r)) == 0
    assert sony_behavior_type(bytes(r)) == 2
    r[0x0c]=0x80
    assert mode_bit(bytes(r)) == 1
    assert sony_behavior_type(bytes(r)) == 4


def test_other_bits_do_not_change_mode():
    r=bytearray(RESPONSE_LEN); r[0x0c]=0x7f
    assert mode_bit(bytes(r)) == 0


def test_wrong_length_rejected():
    for n in (0, RESPONSE_LEN-1, RESPONSE_LEN+1):
        try: mode_bit(bytes(n)); assert False
        except ValueError: pass


def test_safe_summary_excludes_raw_response():
    r=bytearray(RESPONSE_LEN); r[100:112]=b'PRIVATE-DATA'; r[0x0c]=0x80
    s=safe_summary(bytes(r))
    assert set(s)=={'length','sha256','mode_bit','sony_behavior_type'}
    assert 'PRIVATE' not in repr(s)
