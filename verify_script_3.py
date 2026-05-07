h4 = open('execution_plane/ids/h4_ids.py').read()

results = []
def ck(cond, label):
    s = 'PASS' if cond else 'FAIL'
    results.append((s, label))
    print(f'  {s}  {label}')

ck('\"ddos\"' not in h4,           'no ddos key anywhere')
ck('\"icmp_flood\":  False' in h4, 'attack_state uses icmp_flood')
ck('\"icmp_flood\":  None' in h4,  '_last_attacker uses icmp_flood')
ck('attack_state[\"icmp_flood\"]' in h4,   'attack_state reads icmp_flood')
ck('_last_attacker[\"icmp_flood\"]' in h4, '_last_attacker reads icmp_flood')
ck('ICMP_FLOOD' in h4,             'ICMP_FLOOD in send_alert')
ck('\"DDOS\"' not in h4,           'no DDOS string anywhere')
ck('detect_ddos' in h4,            'function name unchanged')

failed = [l for s,l in results if s=='FAIL']
passed = [l for s,l in results if s=='PASS']
print(f'TOTAL: {len(passed)} PASS  {len(failed)} FAIL')
if failed:
    print('FAILED:', failed)
else:
    print('ALL CHECKS PASSED')
