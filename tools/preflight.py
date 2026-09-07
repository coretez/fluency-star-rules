#!/usr/bin/env python3
"""Pre-deployment gate. Enforces config/gates.yaml before a rule reaches a tenant.

    tools/preflight.py --tenant acme --wave 1
    tools/preflight.py --tenant acme --health

Checks what is machine-checkable. The rest is human sign-off in the change record —
see docs/processes/00-isolation.md.
"""
import argparse, datetime, pathlib, sys, yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
def load(p): return yaml.safe_load((ROOT/p).read_text())

G = load('config/gates.yaml')
WAVES = {
    1: ['RC-02.01','RC-02.02','RC-03.01','RC-05.01'],
    2: [],  # harvest gate — no rules
    3: ['RC-03.01','RC-09.04','RC-09.05','RC-09.06','RC-02.05','RC-03.06'],
    4: ['RC-06','RC-07','RC-05.03'],
    5: ['RC-08','RC-09.01','RC-09.02'],
}
FAIL, WARN, CONSOLE = [], [], {}
def fail(m): FAIL.append(m)
def warn(m): WARN.append(m)

def rules():
    for f in sorted((ROOT/'rules').rglob('*.yaml')):
        yield f, yaml.safe_load(f.read_text())

def hash_age():
    newest = None
    for f in (ROOT/'identity/hashes').glob('*.yaml'):
        d = yaml.safe_load(f.read_text())
        if d.get('last_harvest'):
            dt = datetime.date.fromisoformat(str(d['last_harvest']))
            newest = max(newest, dt) if newest else dt
    return (datetime.date.today() - newest).days if newest else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tenant', required=True)
    ap.add_argument('--wave', type=int)
    ap.add_argument('--health', action='store_true')
    a = ap.parse_args()

    tp = ROOT/f'tenants/{a.tenant}.yaml'
    if not tp.exists(): print(f"FAIL  no tenant overlay: tenants/{a.tenant}.yaml"); return 1
    T = yaml.safe_load(tp.read_text())

    # ---- tier prerequisite (SOP-00 §5a)
    pkg = str(T.get('s1_package', '')).lower()
    allowed = G.get('required_s1_package', [])
    if not pkg:
        warn("tenant has no s1_package recorded — STAR requires Singularity Complete or above (SOP-00 §5a)")
    elif pkg not in allowed:
        fail(f"s1_package={pkg}: STAR is a Singularity Complete feature. Core/Control cannot "
             f"run any rule in this repo. Establish the tenant's package before scoping work")

    selected = []
    for f, r in rules():
        if a.wave is not None:
            if not any(r['contract'].startswith(p) for p in WAVES.get(a.wave, [])): continue
        if T.get('overrides', {}).get(r['id'], {}).get('enabled') is False: continue
        selected.append((f, r))

    # ---- rule budget (SOP-00 §5)
    allowance = T.get('star_allowance')
    budget = G['rule_budget']['max_rules_absolute']
    if allowance:
        budget = min(budget, int(allowance * G['rule_budget']['max_pct_of_star_allowance']))
    else:
        warn(f"tenant has no star_allowance recorded — cannot verify rule budget (SOP-00 §5)")
    if len(selected) > budget:
        fail(f"rule budget: {len(selected)} rules exceeds budget {budget}. "
             f"Default STAR entitlement is 100 rules, so this pack is a large share of it. "
             f"Deploy by wave rather than wholesale, upgrade the entitlement, or prune the "
             f"/v3 hash variations first (SOP-00 §5)")

    # ---- per-rule gates
    for f, r in selected:
        rid = r['id']
        # forbidden response actions (SOP-00 §2)
        for act in G['response_actions']['forbidden']:
            if act in str(r.get('response', '')).lower():
                fail(f"{rid}: declares forbidden response action '{act}' — alert only, not tenant-tunable")
        # severity ceiling (SOP-00 §3): contract severity maps DOWN to console severity.
        # Only an explicit tenant override to 'high' on a non-exempt rule is a failure.
        ov_sev = T.get('overrides', {}).get(rid, {}).get('severity')
        may_high = rid in G['severity_ceiling']['may_be_high']
        if ov_sev == 'high' and not may_high:
            fail(f"{rid}: tenant override sets console severity=high but rule is not in "
                 f"gates.yaml may_be_high (SOP-00 §3)")
        console_sev = ov_sev or ('medium' if r['severity'] == 'high' else 'low')
        if may_high and not ov_sev:
            console_sev = 'medium'   # promote to high only deliberately, after T4
        CONSOLE[rid] = console_sev
        # blocked on harvest (SOP-03 wave 2 gate)
        if r['status'] == 'blocked-on-harvest':
            fail(f"{rid}: blocked-on-harvest — empty hash list. Seed identity/hashes/ first "
                 f"or it matches nothing while looking clean")
        if r['status'] in ('deprecated', 'rolled-back'):
            fail(f"{rid}: status={r['status']} — must not be deployed")
        # scope policy (SOP-00 §6)
        if r['contract'] in G['scope_policy']['restricted_groups_required']:
            if not T.get('restricted_groups'):
                fail(f"{rid}: requires restricted_groups in the tenant overlay — "
                     f"never site-wide")
        # test record (SOP-02)
        if not (ROOT/f"tests/records/{rid.replace('/','-')}.md").exists():
            warn(f"{rid}: no test record in tests/records/ — T0-T4 evidence missing (SOP-02)")

    # ---- hash freshness (SOP-04)
    age = hash_age()
    if age is None:
        warn("identity/hashes/: never harvested — RC-09.05 covers nothing (SOP-01 §B)")
    elif age > G['health']['hash_staleness_days']:
        warn(f"identity/hashes/: {age}d since last harvest (limit {G['health']['hash_staleness_days']}) "
             f"— RC-09.05 coverage decaying")

    # ---- report
    print(f"preflight · tenant={a.tenant}" + (f" wave={a.wave}" if a.wave is not None else "")
          + f" · {len(selected)} rules selected · budget {budget}\n")
    for w in WARN: print(f"WARN  {w}")
    for e in FAIL: print(f"FAIL  {e}")
    print(f"\n{len(FAIL)} blocking · {len(WARN)} advisory")
    if CONSOLE and not FAIL:
        print("\nConsole severity to set (contract severity maps DOWN — SOP-00 §3):")
        for rid in sorted(CONSOLE):
            note = "  ← may be promoted to high after T4" if rid in G['severity_ceiling']['may_be_high'] else ""
            print(f"  {rid:<16} {CONSOLE[rid]}{note}")
    if not FAIL:
        print("\nMachine checks pass. Human sign-off still required:")
        print("  [ ] shadow-ai queue exists, excluded from paging + threat-detection metrics")
        print("  [ ] no shared/global exclusions modified")
        print("  [ ] change record approved by customer")
    return 1 if FAIL else 0

if __name__ == '__main__': sys.exit(main())
