#!/usr/bin/env python3
"""RC-09.04 hash harvest. Reads candidate (sha256, path, signer, original_filename)
records from EDR export and appends to identity/hashes/ ONLY when the signer matches.

    tools/harvest.py candidates.json [--apply]

GUARDRAIL: a candidate with no signer match is never appended. It is reported as a
possible impostor. Without this, identity/hashes/ becomes an allowlist an attacker
can write to by naming a binary correctly.
"""
import json, sys, pathlib, datetime, yaml
ROOT = pathlib.Path(__file__).resolve().parent.parent
APPS = yaml.safe_load((ROOT/'identity/apps.yaml').read_text())['apps']

def owner(sig, ofn):
    if not sig: return None
    for name, a in APPS.items():
        for os_ in ('windows','macos','linux'):
            d = a.get(os_)
            if not isinstance(d, dict): continue
            s = (d.get('signer') or '').lower()
            if s and s in sig.lower(): return name, os_
    return None

def main():
    if len(sys.argv) < 2: print(__doc__); return 2
    apply = '--apply' in sys.argv
    cands = json.loads(pathlib.Path(sys.argv[1]).read_text())
    add, reject = {}, []
    for c in cands:
        m = owner(c.get('signer'), c.get('original_filename'))
        if not m:
            reject.append(c); continue
        app, os_ = m
        known = {h for d in [yaml.safe_load((ROOT/f'identity/hashes/{app}.yaml').read_text())]
                 for lst in (d.get('hashes') or {}).values() for h in (lst or [])}
        if c['sha256'] not in known:
            add.setdefault((app, os_), []).append(c)
    for (app, os_), cs in add.items():
        p = ROOT/f'identity/hashes/{app}.yaml'
        d = yaml.safe_load(p.read_text())
        d.setdefault('hashes', {}).setdefault(os_, [])
        for c in cs:
            print(f"ADD   {app}/{os_} {c['sha256'][:16]}… {c.get('version','?')}")
            if apply: d['hashes'][os_].append(c['sha256'])
        if apply:
            d['last_harvest'] = datetime.date.today().isoformat()
            p.write_text("# MACHINE-OWNED — see README.md. Do not hand-edit.\n" +
                         yaml.safe_dump(d, sort_keys=False))
    for c in reject:
        print(f"REJECT {c.get('sha256','?')[:16]}… no signer match "
              f"(signer={c.get('signer')!r} name={c.get('original_filename')!r}) → possible impostor, escalate")
    print(f"\n{sum(len(v) for v in add.values())} to add · {len(reject)} rejected · "
          f"{'APPLIED' if apply else 'DRY RUN (pass --apply)'}")

if __name__ == '__main__': sys.exit(main() or 0)
