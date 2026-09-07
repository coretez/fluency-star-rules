#!/usr/bin/env python3
"""Contract coverage report. Report this, never rule count — rule count rewards
volume, coverage rewards closing gaps."""
import pathlib, yaml, collections, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
items = yaml.safe_load((ROOT/'contract/contract.yaml').read_text())['items']
fams = yaml.safe_load((ROOT/'contract/contract.yaml').read_text())['families']
impl = collections.defaultdict(list)
for f in sorted((ROOT/'rules').rglob('*.yaml')):
    r = yaml.safe_load(f.read_text()); impl[r['contract']].append((r['variation'], r['status'], r['platform']))

M = {'active':'●','planned':'○','accepted-gap':'⊘','deprecated':'×'}
cur = None
for cid, it in items.items():
    fam = cid.split('.')[0]
    if fam != cur:
        cur = fam; print(f"\n\033[1m{fam} — {fams[fam]['name']}\033[0m")
    vs = impl.get(cid, [])
    blocked = sum(1 for v in vs if v[1] == 'blocked-on-harvest')
    tag = ' '.join(sorted(v[0] for v in vs)) or '—'
    flag = f"  ⚠ {blocked} blocked-on-harvest" if blocked else ''
    print(f"  {M[it['status']]} {cid}  {it['severity']:<6} {tag:<14}{flag}  {it['intent'][:52]}")

tot = len(items)
act = [k for k, v in items.items() if v['status'] == 'active']
covered = [k for k in act if k in impl]
gaps = [k for k, v in items.items() if v['status'] == 'accepted-gap']
blocked = sum(1 for v in impl.values() for x in v if x[1] == 'blocked-on-harvest')
print(f"\n\033[1mCoverage\033[0m")
print(f"  contract items      {tot}")
print(f"  active              {len(act)}  implemented {len(covered)}/{len(act)}")
print(f"  planned             {tot-len(act)-len(gaps)}")
print(f"  accepted gaps       {len(gaps)}  ({', '.join(gaps)})")
print(f"  rules               {sum(len(v) for v in impl.values())}")
print(f"  blocked on harvest  {blocked}  ← seed identity/hashes/ to unblock")
