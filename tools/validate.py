#!/usr/bin/env python3
"""CI gate: rules must cite real contract IDs, IDs must be immutable and sortable,
placeholders must resolve, and no rule may hardcode identity data."""
import pathlib, re, sys, yaml
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'tools'))
import render as R

errs, warns = [], []
contract = yaml.safe_load((ROOT/'contract/contract.yaml').read_text())
items, prims = contract['items'], yaml.safe_load((ROOT/'contract/primitives.yaml').read_text())['primitives']
ID_RE = re.compile(r'^RC-\d{2}\.\d{2}$')

for cid in items:
    if not ID_RE.match(cid): errs.append(f"contract {cid}: ID must be RC-FF.II zero-padded")
if list(items) != sorted(items): errs.append("contract items are not in sorted order")

seen = {}
for f in sorted((ROOT/'rules').rglob('*.yaml')):
    r = yaml.safe_load(f.read_text()); rid = r['id']; n = f.name
    if rid in seen: errs.append(f"{n}: duplicate rule id {rid} (also {seen[rid]})")
    seen[rid] = n
    if r['contract'] not in items: errs.append(f"{n}: cites unknown contract id {r['contract']}")
    if not n.startswith(f"{r['contract']}-{r['variation']}-"): errs.append(f"{n}: filename does not match id {rid}")
    for p in ([r['primitive']] if isinstance(r['primitive'], str) else r['primitive']):
        if p not in prims: errs.append(f"{n}: unknown primitive {p}")
    if r['contract'] in items and items[r['contract']]['status'] == 'accepted-gap':
        errs.append(f"{n}: implements {r['contract']} which is an accepted-gap — contract says this is not satisfiable")
    # hardcoded identity data
    q = r['query']
    for lit in ('AnthropicClaude', 'chatgpt.com', 'openrouter.ai', '1.1.1.1', 'deepseek.com', '/Applications/Claude.app'):
        if lit in q: errs.append(f"{n}: hardcodes '{lit}' — reference identity/ via a placeholder instead")
    try:
        out = R.render(r, {'restricted_groups': ['_stub'], 'exempt_groups': [], 'integration_endpoints': []})
        if '""' in out and 'hashes:' in q and r['status'] != 'blocked-on-harvest':
            warns.append(f"{n}: renders an empty hash list but status is not blocked-on-harvest")
    except KeyError as e:
        errs.append(f"{n}: {e}")

for k, v in items.items():
    if v['status'] == 'active' and k not in {r['contract'] for r in
        (yaml.safe_load(f.read_text()) for f in (ROOT/'rules').rglob('*.yaml'))}:
        errs.append(f"contract {k}: status=active but no rule implements it")

for w in warns: print(f"WARN  {w}")
for e in errs: print(f"ERROR {e}")
print(f"\n{len(seen)} rules · {len(errs)} errors · {len(warns)} warnings")
sys.exit(1 if errs else 0)
