# SOP-05 — Emergency rollback

**Print this. Target: under 5 minutes to stop all shadow-AI alerting in a tenant.**

---

## Decision tree

| Symptom | Action | Scope |
|---|---|---|
| One rule flooding the `shadow-ai` queue | Disable that rule | Rule |
| Alerts landing in the **incident queue** | Disable that rule, fix routing | Rule + config |
| Multiple rules noisy in one tenant | Disable by `shadow-ai` tag | Tenant |
| Noisy across several tenants | Disable by tag, all affected | Multi-tenant |
| **Any response action observed firing** | **Disable by tag immediately, all tenants** | **Global** |
| Customer reports a business tool disrupted | Disable by tag, then investigate | Tenant |

## The stop

1. Console → STAR rules → filter tag `shadow-ai`
2. Select all → **Disable** (do not delete — you lose history and the audit trail)
3. Confirm zero active rules carry the tag
4. Note the time

This is why [SOP-00 §1](00-isolation.md) mandates the tag and the name prefix. Without
them, rollback means clicking through rules individually while the queue fills.

## A response action fired

Treat as a **P1 self-inflicted incident**, not a tuning problem.

1. Disable by tag, **every tenant** — not just the one that fired
2. Identify affected endpoints and what was killed or quarantined
3. Restore; notify the customer before they notice
4. Full stop on shadow-AI deployment until root cause is understood

[SOP-00 §2](00-isolation.md) makes response actions forbidden and not tenant-tunable
precisely so this cannot happen. If it did, the isolation model was bypassed — find out
how before re-enabling anything.

## After the stop

- Incident note: what fired, volume, blast radius, customer impact
- Rule → `status: rolled-back` with the reason
- Back to **T2** ([SOP-02](02-testing.md)), not T4 — if it got through canary, the
  volume model was wrong, and that is a T2 failure
- Update the T2 baseline in the test record with the real number
- Ring clock resets

## What not to do

- **Do not** add a global or shared exclusion to silence it. That risks blinding threat
  detection — the worst outcome available ([SOP-00 §7](00-isolation.md)).
- **Do not** delete rules. Disable. Deleting destroys the history you need for the
  post-mortem.
- **Do not** raise the volume threshold to make an alert stop. Fix the rule.
