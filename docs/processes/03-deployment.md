# SOP-03 — Deployment

**Never all tenants at once.** A bad rule pushed fleet-wide across every customer is a
mass incident of our own making — the exact outcome [SOP-00](00-isolation.md) exists to
prevent.

---

## Tenant rings

| Ring | Who | Soak | Gate to advance |
|---|---|---|---|
| **R0 canary** | Fluency internal | 7–14d (T4) | FP < 10%, volume in budget |
| **R1 early** | 2–3 consenting customers, mixed size/vertical | 7d | No regression in any |
| **R2 general** | Remaining tenants, batched ≤ 5 per day | — | R1 clean |

**One ring per week maximum.** If a ring surfaces anything, the clock resets — it does not
carry forward.

R1 customers must have **agreed in advance** to early exposure. This is a contractual
conversation, not an operational one. Do it once, per customer, not per rule.

## Per-tenant preflight

```bash
python3 tools/preflight.py --tenant acme --wave 1
```

Checks what is checkable: rule budget, scope policy, severity ceiling, forbidden response
actions, `restricted_groups` present for RC-08.03, hash freshness, test records exist.

The rest is human sign-off in the change record — see the [SOP-00 gate](00-isolation.md#pre-deployment-gate).

## Deployment waves (within a tenant)

Waves are about *rule risk*, rings are about *customer risk*. Both apply.

| Wave | Rules | Why first |
|---|---|---|
| **0** | **None — discovery sweep only** | **Hunts, not rules. Zero rule budget, zero alerts, zero SOC impact. Establishes what AI is actually present before anything is written for this tenant** |
| 1 | RC-02.01/02, RC-03.01 v1+v4, RC-05.01 | Low volume, high signal, builds the inventory |
| 2 | **Harvest** → seed `identity/hashes/` | **Hard gate** |
| 3 | RC-03.01/v3, RC-09.04/05/06, RC-02.05, RC-03.06 | Evasion detections |
| 4 | RC-06.x, RC-07.x, RC-05.03 | Developer + browser surface |
| 5 | RC-08.x, RC-09.01/02 | Highest volume — fix DoH policy first |

**Wave 0 is mandatory per tenant.** Run the [discovery sweep](01-discovery-and-sampling.md#a1-discovery-sweep--the-wave-0-inventory)
and commit `discovery/<tenant>/<date>.md` before wave 1. Rules written from another
tenant's footprint will miss this one's — the sweep is what makes the rule set specific to
the customer rather than generic. It is also the safest thing in the programme: queries
only, so it can run before any change record.

**Wave 2 is a hard gate.** Rules with `status: blocked-on-harvest` reference empty hash
lists. Deployed early they match nothing, pass every check, and produce a dashboard that
looks clean while covering nothing. `preflight.py` refuses them.

**Wave 5 precondition:** confirm the tenant's browser DoH policy. Deploying RC-08.x into a
DoH-enabled fleet produces a compliant-looking report that is a false negative
(see RC-10.04).

## Change record

One per tenant per wave, in the customer's normal change system:

```
change:      Deploy shadow-AI detection wave 1 — <tenant>
rules:       RC-02.01/v1, RC-02.02/v1, RC-03.01/v1, RC-03.01/v4, RC-05.01/v1
ring:        R1
severity:    all Low, alert-only
scope:       site-wide (wave 1 families)
queue:       shadow-ai (not incident queue)
budget:      5 of 20 AI slots; tenant STAR allowance 100, current use 43
predicted:   0.3–0.9 events/100ep/day (from T2)
rollback:    disable by tag `shadow-ai` — SOP-05, < 5 min
test records: tests/records/RC-*.md
approved:    <customer contact> <date>
```

Customer-facing framing: **this is visibility, not enforcement.** Nothing is blocked,
nothing is killed. Say so explicitly — "AI detection" reads as "AI blocking" to most
stakeholders and generates objections that do not apply.

## Post-deployment — first 72 hours

| When | Check |
|---|---|
| +1h | Rules active, firing or not; no console errors |
| +24h | Volume vs T2 prediction; drift > 3× → [SOP-05](05-rollback.md) |
| +72h | Queue routing held; nothing landed in the incident queue |
| +7d | FP dispositions reviewed; ring gate decision |

Record actuals against the T2 prediction in the test record. That feedback is what makes
the next rule's T2 estimate trustworthy.
