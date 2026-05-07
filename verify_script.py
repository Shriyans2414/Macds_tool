import os, sys
sys.path.insert(0, 'control_plane')
from macds.agents.multi_agent import (
    ATTACK_TYPES, N_ATTACK_TYPES, STATE_DIM, CONTINUOUS_DIM
)

results = []
def ck(cond, label):
    s = 'PASS' if cond else 'FAIL'
    results.append((s, label))
    print(f'  {s}  {label}')

print('=== Fix 1: import os ===')
tf = open('test_flow.py').read()
ck('import os' in tf, 'import os present in test_flow.py')
ck('os.environ' in tf, 'os.environ used correctly')

print()
print('=== Fix 2: ATTACK_TYPES expanded ===')
ck(N_ATTACK_TYPES == 27, f'N_ATTACK_TYPES=27 (got {N_ATTACK_TYPES})')
ck(STATE_DIM == 35, f'STATE_DIM=35 (got {STATE_DIM})')
ck(CONTINUOUS_DIM == 8, f'CONTINUOUS_DIM=8 (got {CONTINUOUS_DIM})')
for t in ['spring4shell','struts_rce','php_injection','xxe','ssti']:
    ck(t in ATTACK_TYPES, f'{t} in ATTACK_TYPES')

print()
print('=== Fix 3: is_app expanded ===')
ma = open('control_plane/macds/agents/multi_agent.py').read()
for t in ['spring4shell','struts_rce','php_injection','xxe','ssti']:
    ck(t in ma.split('is_app = attack_type.lower() in')[1].split(')')[0],
       f'{t} in is_app')

print()
print('=== Fix 4: skip learning when no prior state ===')
main = open('control_plane/api/main.py').read()
ck('skip_learning = attacked_state is None' in main,
   'skip_learning flag set')
ck('if not skip_learning:' in main,
   'learning conditional on skip_learning')
ck('\"attack_type\":     \"anomaly\"' not in main,
   'fabricated anomaly state removed')

print()
print('=== Fix 5: csv writer per entry not per row ===')
ck('writer = _csv.writer(handler.stream)' in main,
   'writer assigned to variable inside try block')

print()
print('=== Fix 6: new scenarios in training ===')
for t in ['spring4shell','struts_rce','php_injection','xxe','ssti']:
    ck(f'\"attack_type\":\"{t}\"' in main or
       f'\"attack_type\": \"{t}\"' in main or
       t in main.split('_TRAINING_SCENARIOS')[1].split(']')[0],
       f'{t} scenario in _TRAINING_SCENARIOS')

print()
print('=== Fix 7: federation validates shapes ===')
fed = open('control_plane/api/federation.py').read()
ck('reference_keys' in fed, 'key validation present')
ck('Shape mismatch' in fed or 't.shape' in fed, 'shape validation present')
ck('except ValueError' in fed, 'ValueError caught in handle_federation')
ck('status.*error' in fed or '\"error\"' in fed, 'error response returned')

print()
print('=== BLOCK_ON_SIGHT vs ATTACK_TYPES alignment ===')
import re
bos_raw = re.search(r'BLOCK_ON_SIGHT = \{([^}]+)\}', main, re.DOTALL).group(1)
bos = set(re.findall(r'\"([A-Z_]+)\"', bos_raw))
at_upper = set(a.upper() for a in ATTACK_TYPES)
missing = bos - at_upper
ck(len(missing) == 0, f'All BLOCK_ON_SIGHT types in ATTACK_TYPES (missing={missing})')

print()
failed = [l for s,l in results if s=='FAIL']
passed = [l for s,l in results if s=='PASS']
print(f'TOTAL: {len(passed)} PASS  {len(failed)} FAIL')
if failed:
    print()
    print('FAILED:')
    for l in failed: print(f'  x {l}')
else:
    print()
    print('ALL FIXES VERIFIED')
