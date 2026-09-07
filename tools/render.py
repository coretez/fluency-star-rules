#!/usr/bin/env python3
"""Expand identity placeholders in rule queries into deployable S1QL.

Rules reference identity keys; they never hardcode paths, domains or hashes.
One source of truth: identity/. Usage:
    tools/render.py                      all rules, base
    tools/render.py --tenant acme        with tenant overlay
    tools/render.py --rule RC-03.01/v1
"""
import argparse, pathlib, re, sys, yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
def load(p): return yaml.safe_load((ROOT/p).read_text())

APPS = load('identity/apps.yaml')
DOMAINS = load('identity/domains.yaml')
HASHES = {f.stem: yaml.safe_load(f.read_text())
          for f in (ROOT/'identity/hashes').glob('*.yaml')}

def qlist(vals):
    vals = [v for v in dict.fromkeys(vals) if v not in (None, "")]
    return ", ".join('"%s"' % str(v).replace('\\', '\\\\') for v in vals) if vals else '""'

def app_paths(app, os_=None):
    a = APPS['apps'][app]
    return [p for k in (('windows','macos','linux') if not os_ else (os_,))
            if isinstance(a.get(k), dict) for p in a[k].get('paths', [])]

def app_field_all(field, os_=None):
    out = []
    for a in APPS['apps'].values():
        for k in (('windows','macos','linux') if not os_ else (os_,)):
            v = a.get(k, {}).get(field) if isinstance(a.get(k), dict) else None
            if isinstance(v, list): out += v
            elif v: out.append(v)
    return out

def all_hashes(app=None):
    src = [HASHES[app]] if app else HASHES.values()
    return [h for d in src for lst in (d.get('hashes') or {}).values() for h in (lst or [])]

def resolve(tok, tenant):
    tok = tok.strip()
    if tok.startswith('app:'):
        rest = tok[4:]
        app, _, field = rest.partition('.')
        if field == 'paths': return qlist(app_paths(app))
        os_, _, f2 = field.partition('.')
        if f2:
            v = APPS['apps'][app].get(os_, {}).get(f2)
            return qlist(v) if isinstance(v, list) else (str(v) if v else "")
        v = APPS['apps'][app].get(field)
        return qlist(v) if isinstance(v, list) else str(v or "")
    if tok.startswith('app_field:'):
        rest = tok[10:]; field, _, os_ = rest.partition('.')
        return qlist(app_field_all(field, os_ or None))
    if tok.startswith('hashes:'):
        app = tok[7:]
        return qlist(all_hashes(None if app == '*' else app))
    if tok.startswith('domains:'):
        key = tok[8:]
        comp = (DOMAINS.get('_composites') or {}).get(key)
        if comp:
            return qlist([d for t in comp for d in DOMAINS[t]])
        return qlist(DOMAINS[key])
    if tok.startswith('tenant:'):
        key = tok[7:]
        if not tenant: raise KeyError(f"rule needs --tenant for {{{{ {tok} }}}}")
        return qlist(tenant.get(key, []))
    if tok == 'user_writable_paths':
        return qlist([p for v in APPS['user_writable_paths'].values() for p in v])
    if tok == 'browser_processes':
        return qlist([p for v in APPS['browser_processes'].values() for p in v])
    if tok == 'cli_cmdline':
        return qlist([c for t in APPS['cli_tools'].values() for c in t.get('cmdline', [])])
    if tok == 'cli_binaries':
        return qlist([b for t in APPS['cli_tools'].values() for b in t.get('binaries', [])])
    if tok == 'api_key_patterns':
        k = APPS['api_key_patterns']; return qlist(k['env'] + k['prefixes'])
    if tok in DOMAINS: return qlist(DOMAINS[tok])
    raise KeyError(f"unknown placeholder: {tok}")

def render(rule, tenant=None):
    return re.sub(r'\{\{(.+?)\}\}', lambda m: resolve(m.group(1), tenant), rule['query'])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tenant'); ap.add_argument('--rule'); ap.add_argument('--platform', default='sentinelone')
    a = ap.parse_args()
    tenant = load(f'tenants/{a.tenant}.yaml') if a.tenant else None
    ov = (tenant or {}).get('overrides', {})
    rc = 0
    for f in sorted((ROOT/f'rules/{a.platform}').glob('*.yaml')):
        r = yaml.safe_load(f.read_text())
        if a.rule and r['id'] != a.rule: continue
        o = ov.get(r['id'], {})
        if o.get('enabled') is False:
            print(f"# ---- {r['id']} DISABLED for {a.tenant}: {o.get('reason','no reason given')}\n"); continue
        sev = o.get('severity', r['severity'])
        print(f"# ==== {r['id']} — {r['name']}")
        print(f"# severity={sev} status={r['status']} tier={r.get('identity_tier')} primitive={r['primitive']}")
        print(f"# console rule name: {r['id']} — {r['name']}")
        if r['status'] == 'blocked-on-harvest':
            print("# !! BLOCKED: references an empty hash list. Harvest first (RC-09.04).")
        try:
            print(render(r, tenant))
        except KeyError as e:
            print(f"# !! RENDER ERROR: {e}\n"); rc = 1
    return rc

if __name__ == '__main__': sys.exit(main())
