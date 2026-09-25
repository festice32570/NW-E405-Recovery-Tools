from itertools import product


def decision(issue_state, lba_unreadable, root_pkg_exact, space_ok, official_verified):
    if not issue_state:
        return 'LOCKED'
    if root_pkg_exact:
        if space_ok and official_verified:
            return 'FC04_RESUME'
        return 'LOCKED_AFTER_ANALYSIS'
    if lba_unreadable:
        return 'A3_A4_QUERY'
    return 'LBA_RESCUE'


def test_fc04_requires_every_destructive_gate():
    for vals in product([False, True], repeat=5):
        issue,lba,root,space,official=vals
        d=decision(*vals)
        if d=='FC04_RESUME':
            assert issue and root and space and official
        if not (issue and root and space and official):
            assert d!='FC04_RESUME'


def test_lba_unreadable_routes_to_vendor_query_only_when_no_verified_root_pkg():
    assert decision(True,True,False,False,False)=='A3_A4_QUERY'
    assert decision(True,True,True,False,True)=='LOCKED_AFTER_ANALYSIS'


def test_normal_issue_state_starts_with_lba_rescue():
    assert decision(True,False,False,False,False)=='LBA_RESCUE'


def test_wrong_state_never_actions():
    for lba,root,space,official in product([False,True], repeat=4):
        assert decision(False,lba,root,space,official)=='LOCKED'


def test_a3_payload_is_fixed_select_record_shape():
    cdb=bytes([0xA3,0,0,0,0,0,0,0xBC,0,0x14,0x30,0])
    payload=bytes([0,0x12]+[0]*18)
    assert len(cdb)==12 and cdb[0]==0xA3 and cdb[7]==0xBC and cdb[9:11]==bytes([0x14,0x30])
    assert len(payload)==20 and payload[:2]==bytes([0,0x12]) and not any(payload[2:])


def test_a4_expected_shape():
    cdb=bytes([0xA4,0,0,0,0,0,0,0xBC,0,0x12,0x3F,0])
    assert len(cdb)==12 and cdb[0]==0xA4 and cdb[7]==0xBC and cdb[9:11]==bytes([0x12,0x3F])
