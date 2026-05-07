import sys, os
sys.path.insert(0, 'control_plane')
from macds.agents.multi_agent import N_ATTACK_TYPES, STATE_DIM

results = []
def ck(cond, label):
    s = 'PASS' if cond else 'FAIL'
    results.append((s, label))
    print(f'  {s}  {label}')

print('=== Fix 1: stale comments ===')
ma = open('control_plane/macds/agents/multi_agent.py').read()
ck('# 27' in ma, 'N_ATTACK_TYPES comment says 27')
ck('# 35' in ma, 'STATE_DIM comment says 35')
ck('State dim 35' in ma, 'docstring says 35')
ck('27-type' in ma, 'docstring says 27-type')
ck(N_ATTACK_TYPES == 27, f'N_ATTACK_TYPES runtime = 27 (got {N_ATTACK_TYPES})')
ck(STATE_DIM == 35, f'STATE_DIM runtime = 35 (got {STATE_DIM})')

print()
print('=== Fix 2: test_flow all requests have key ===')
tf = open('test_flow.py').read()
api_calls = [i for i,l in enumerate(tf.split('\n'))
             if '/api/' in l and 'requests.' in l and 'CONTROL_PLANE_URL' in l]
headers_calls = [i for i,l in enumerate(tf.split('\n'))
                 if 'X-MACDS-Key' in l or ('headers' in l and 'API_KEY' in l)]
ck(len(api_calls) > 0, f'Found {len(api_calls)} API calls in test_flow')
lines = tf.split('\n')
api_line_nums = [i for i,l in enumerate(lines)
                 if '/api/' in l and 'requests.' in l and 'CONTROL_PLANE_URL' in l]
for ln in api_line_nums:
    context = '\n'.join(lines[ln:ln+5])
    ck('X-MACDS-Key' in context or 'API_KEY' in context,
       f'Line {ln+1} has API key in context')

print()
print('=== Fix 3: DDOS renamed to ICMP_FLOOD ===')
h4 = open('execution_plane/ids/h4_ids.py').read()
ck('\"DDOS\"' not in h4, 'DDOS string removed from h4_ids')
ck('\"ICMP_FLOOD\"' in h4, 'ICMP_FLOOD present in h4_ids')
main = open('control_plane/api/main.py').read()
ck('\"ICMP_FLOOD\"' in main.split('BLOCK_ON_SIGHT')[1][:200],
   'ICMP_FLOOD in BLOCK_ON_SIGHT')
from macds.agents.multi_agent import ATTACK_TYPES
ck('icmp_flood' in ATTACK_TYPES, 'icmp_flood in ATTACK_TYPES')

print()
print('=== Fix 4: file lock on pretrain ===')
ck('fcntl' in main, 'fcntl imported for file lock')
ck('.pretrain.lock' in main, '.pretrain.lock file used')
ck('LOCK_EX' in main, 'exclusive lock acquired')
ck('agents.load_all(QTABLE_DIR)' in main.split('lifespan')[1].split('yield')[0],
   'load_all called if .pt files exist')

print()
print('=== Fix 5: RotatingFileHandler uses emit ===')
ck('handler.emit(record)' in main, 'emit() called instead of stream.write')
ck('logging.makeLogRecord' in main, 'makeLogRecord used')
ck('handler.stream.write' not in main, 'stream.write removed')

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
    print('ALL 5 FIXES VERIFIED')
