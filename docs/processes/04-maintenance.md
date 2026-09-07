# SOP-04 — Maintenance

A detection library decays silently. Vendors change install paths, rotate certificates,
ship new versions; domains appear; rules that once fired stop. **Nothing about that decay
is visible in the console** — a broken rule and a rule with nothing to find look identical.

These cadences exist to make decay visible.

---

## Cadences

| Cadence | Task | Owner |
|---|---|---|
| **Weekly** | Hash harvest ([SOP-01 §B](01-sample-collection.md)) | Detection Eng |
| **Weekly** | Triage `shadow-ai` queue; disposition every alert | MSSP Ops |
| **Monthly** | Domain list review — new AI services, dead domains | Detection Eng |
| **Monthly** | Rule health report (below) | Detection Eng |
| **Quarterly** | Re-verify `verify: true` entries against live installs | Detection Eng |
| **Quarterly** | Contract review — promote `planned` → `active`, retire dead items | Lead |
| **Quarterly** | Re-run the [ecosystem survey](../ECOSYSTEM.md) | Lead |

## Rule health report

```bash
python3 tools/coverage.py
python3 tools/preflight.py --tenant <t> --health
```

Four failure modes to look for:

**Dead rule** — 0 fires in 90 days. Not automatically wrong; RC-08.01 (Tier A
jurisdiction) firing zero times is a good outcome. But confirm *why*:
- Is the app genuinely absent? → fine, keep
- Did the install path change? → rule is broken, fix
- Is DoH blinding it? → coverage gap, not a clean result

**Never-verified rule** — deployed but never observed firing anywhere, including lab.
Treat as untested regardless of what the test record says.

**Volume drift** — steady-state volume moved > 3× from the T2 baseline. Usually a vendor
release changed behaviour, or a customer rolled out a new tool. Re-baseline, do not just
raise the threshold.

**Stale hashes** — no harvest in 30 days. RC-09.05 coverage is decaying and the dashboard
will not show it.

## Contract changes

**Contract IDs are immutable.** Deprecate; never renumber, never reuse. Reusing a retired
number is how a rule silently claims coverage it does not have.

| Change | Version | Action |
|---|---|---|
| New item | minor | Add with `status: planned` |
| `planned` → `active` | minor | Must have an implementation or `validate.py` fails |
| Intent reworded, meaning unchanged | patch | Note in CHANGELOG |
| **Meaning changed** | **major** | New ID. Deprecate the old one. Deployed rules citing it must be re-reviewed |
| Item retired | minor | `status: deprecated`, keep the ID forever |

A major bump means every deployed rule citing the changed ID is now questionable. That is
the whole reason for the rule — it forces the review instead of letting the drift pass.

## Rule deprecation

1. `status: deprecated` in the rule file, with reason and date
2. Disable in consoles (do not delete — retention/audit)
3. Remove after 90 days if nothing regressed
4. CHANGELOG entry
5. Contract item stays; if nothing implements an `active` item, `validate.py` fails and
   forces the decision — reimplement, or move it to `planned`

## Onboarding a new AI app

1. Lab install ([SOP-01 §A](01-sample-collection.md)) → identity captured
2. `identity/apps.yaml` PR — signer, metadata, paths, `install_root`
3. Map to existing contract items; add new ones only if genuinely uncovered
4. Rule variations per [contract Part D](../../contract/contract.yaml)
5. T0–T5 ([SOP-02](02-testing.md))
6. Rings ([SOP-03](03-deployment.md))

Most new apps need **no new contract items** — RC-03.0x and RC-05.0x already cover
"an AI desktop app runs" and "a local runtime serves." Adding an app is usually an
`identity/` change plus rule variations, not a contract change. If you find yourself
adding contract items for every new app, the contract is too specific.

## Watch list

Re-check quarterly; both change the build-vs-buy calculus:

- **Defender `AgentsInfo`** — leaves preview / expands app coverage → do not port RC-03/05/06
- **SentinelOne Prompt Security** — if endpoint coverage extends to local runtimes, RC-05
  becomes duplicated effort
- **pySigma S1 backend** — if `OriginalFileName` and publisher get mapped, IT-1/IT-2
  variations become emittable and ADR-0001 is revisited
