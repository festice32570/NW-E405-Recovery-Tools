#!/usr/bin/env python3
import importlib.util, inspect, pathlib, sys, traceback
root=pathlib.Path(__file__).resolve().parent
files=['test_upg_analyzer.py','test_recovery_state.py','test_official_package_local.py','test_original_updater_controlflow.py','test_win7_compat.py','test_rescue_fat.py','test_v07_recovery_ladder.py','test_v08_vendor_probes.py','test_sonyicd_spec.py','test_a4_behavior_spec.py']
failed=0; total=0
for fn in files:
 p=root/fn
 spec=importlib.util.spec_from_file_location(p.stem,p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
 for name,obj in sorted(vars(m).items()):
  if name.startswith('test_') and callable(obj):
   total+=1
   try: obj(); print('PASS',fn,name)
   except Exception:
    failed+=1; print('FAIL',fn,name); traceback.print_exc()
print(f'\n{total-failed}/{total} tests passed')
sys.exit(1 if failed else 0)
