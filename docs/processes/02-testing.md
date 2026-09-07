# SOP-02 — Signature testing

**Six gates. No rule reaches a customer tenant without passing all six.**

The gates exist in this order because each is cheaper than the next. T0 costs seconds,
T5 costs customer trust.

| Gate | What | Where | Blocks on |
|---|---|---|---|
| **T0** | Static validation | CI | Any error |
| **T1** | Syntax parse | Lab console | Query rejected |
| **T2** | **Historical replay** — recall *and* precision | Lab/canary DV, 30d | Misses its source cluster, or volume over budget |
| **T3** | Lab detonation | Lab VM | No fire, or negative sample fires |
| **T4** | Canary soak | Internal tenant, 7–14d | Volume drift, FP rate |
| **T5** | Staged rollout | Customer tenants | Any tenant regression |

---

## T0 — Static validation (CI, seconds)

```bash
python3 tools/validate.py
```

Fails on: unknown contract ID · filename/ID mismatch · duplicate rule ID · unknown
primitive · **hardcoded identity literal** · unresolvable placeholder · a rule implementing
an `accepted-gap` item · an `active` contract item with no implementation.

Runs on every PR. Nothing merges red.

## T1 — Syntax parse (minutes)

Render and paste into the lab console's Deep Visibility query bar:

```bash
python3 tools/render.py --rule RC-03.01/v1 --tenant lab
```

Confirms the query parses and the fields exist in **your** agent version. This is where
schema assumptions die — notably `tgt.file.internalName` on Process Creation, which is
unverified and gates RC-03.01/v2 and RC-09.06. If a field does not resolve, the rule moves
to `status: blocked-on-schema` and the variation is re-homed per
[ADR-0001](../ECOSYSTEM.md).

## T2 — Historical replay (recall *and* precision)

**The most important gate**, and it has two halves. A rule that sits comfortably inside
the volume budget and detects nothing real passes a precision-only test. Most of ours are
derived from a known cluster ([SOP-01 A2](01-discovery-and-sampling.md)), which means we
have ground truth and no excuse for skipping recall.

### T2a — Recall: does it catch the cluster it came from?

Run the rendered rule over the exact historical window the gap was found in.

```bash
python3 tools/render.py --rule RC-05.01/v4 --tenant lab
```

| Result | Meaning | Action |
|---|---|---|
| Catches every event in the source cluster | Gap closed | Proceed to T2b |
| Catches some | Partial coverage | Identify the missed subset — usually a second gap |
| Catches none | Rule does not do what it claims | Back to authoring |
| Catches the cluster **and** more | Either broader true coverage or FPs | Resolve in T2b before proceeding |

Record the source cluster/gap ID and the recall fraction. **A rule with no recorded recall
number has not passed T2**, regardless of how quiet it is.

For rules not derived from a cluster (new app from Mode B), recall is proven at T3
detonation instead — but say so explicitly in the test record rather than leaving it blank.

### T2b — Precision: is the volume affordable?

Run over 30 days of DV data and count.

```
events_per_100_endpoints_per_day = total_hits / (endpoint_count/100) / 30
```

Against `config/gates.yaml`:

| Scope | Budget | If exceeded |
|---|---|---|
| Site-wide | ≤ 1 / 100 endpoints / day | Narrow, or re-scope to groups |
| Group-scoped | ≤ 10 / 100 endpoints / day | Narrow, or reject |
| Harvest queue (RC-09.04) | ≤ 50 / 100 endpoints / day | Acceptable — not analyst-facing |

Also record **distinct endpoints**, **distinct processes**, and the **top 10 contributors**.
4000 hits on one endpoint is a different problem from 4000 endpoints hit once.

### The trade you are actually making

T2a and T2b pull against each other. Broadening a rule to close recall raises volume;
narrowing for volume drops recall. Record both numbers so the trade is explicit and
reviewable, rather than a rule quietly drifting toward whichever one someone measured last.

> Fluency's replay tooling (`replay_tenant_window`, scenario capture,
> `evaluate_scenario_against_signatures`) is the natural harness — a captured cluster
> becomes a reusable regression scenario, so T2a re-runs automatically on every rule change
> instead of being a one-off measurement.

## T3 — Lab detonation (does it actually fire?)

On the lab VM from [SOP-01](01-sample-collection.md):

1. Install / run the target app → **confirm the rule fires**
2. Run the **negative sample** → **confirm the rule does not fire**
3. For rename/relocate rules, actively try to evade:
   - copy the binary to `Downloads\` and rename it → RC-09.05 and RC-09.06 must fire
   - RC-03.01/v1 (path) must *not* fire — that is the coverage gap those rules exist to close

Step 3 is the whole point of the four-variation model. If a renamed binary evades every
variation, the identity strategy has a hole and the rule set is not ready.

**A rule that has never been observed firing is not tested.** Record the event ID.

## T4 — Canary soak (7–14 days)

Deploy alert-only to **one internal or friendly tenant**, never a customer first.

- 7 days minimum; **14 days for RC-08.x** (weekly business cycles distort DNS volume)
- Daily volume check against the T2 prediction. Drift > 3× → back to T2.
- Every alert dispositioned: `policy-violation` / `approved-tool` / `false-positive` /
  `escalate`
- **Exit criteria:** FP rate < 10%, volume within budget, zero SOC-queue contamination
  (confirm the `shadow-ai` routing from [SOP-00 §4](00-isolation.md) actually held)

## T5 — Staged customer rollout

Covered in [SOP-03](03-deployment.md). Never all tenants at once.

---

## Rules requiring extra scrutiny

| Rule | Why | Extra gate |
|---|---|---|
| RC-08.03 | Highest volume in the set | T2 **per tenant**, not once globally |
| RC-06.02 | `claude`/`codex`/`llm` name collisions | Negative sample mandatory |
| RC-09.05 | Console High, crosses to incident queue | 14-day canary, no exceptions |
| RC-05.03 | Console High | Verify loopback exclusion works before deploy |
| RC-03.01/v2, RC-09.06 | Schema-dependent | Cannot pass T1 until `internalName` is verified |
| Anything `blocked-on-harvest` | Empty hash list | **Cannot pass T2a** — zero recall, but looks quiet in T2b |

---

## Test record

Every rule carries a test record before T5, committed to `tests/records/<rule-id>.md`:

```
rule:            RC-05.01/v4
derived_from:    GAP-2026-09-014 (case 4471, 12 endpoints, 3 tenants)
T0 validate:     pass  2026-09-05
T1 syntax:       pass  lab console, agent 24.1
T2a recall:      12/12 source-cluster events caught (100%)
T2b precision:   0.3 events/100ep/day over 30d, 19 endpoints, top contributor 4 hits
T3 detonation:   fired (event 7f3a...); negative sample did not fire
T4 canary:       fluency-internal, 14d, 41 alerts, 2 FP (4.9%)
approved_by:     <name>  2026-09-19
```

No test record, no deployment. The record is what makes a rule auditable a year later
when someone asks why it exists and whether it still works.
