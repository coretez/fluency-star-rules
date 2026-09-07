# SOP-00 — Isolation model

**Constraint: AI detection must not degrade production detection or SOC operations.**

Shadow-AI findings are *policy* findings. Malware detections are *incidents*. The moment
those two share a queue, a severity scale, or a rule budget, the AI programme starts
costing the SOC attention it owes to real threats. Every control below exists to keep
them apart.

This SOP is a precondition for SOP-03. Do not deploy anything until all seven controls
are in place in the target tenant.

---

## The seven controls

### 1. Namespace — every rule is bulk-identifiable

Console rule name **must** start with the contract ID:

```
RC-03.01/v1 — Claude Desktop execution (path)
```

Console tag on every rule: `shadow-ai`

Why: one filter selects every AI rule for bulk disable. Without a namespace, emergency
rollback means clicking through rules one at a time while the queue fills.

### 2. No response actions — ever

| Setting | Value |
|---|---|
| Response | **Alert only** |
| Kill process | ❌ never |
| Quarantine | ❌ never |
| Network isolate | ❌ never |
| Remediate / rollback | ❌ never |

An accidental quarantine of a business-approved AI tool is a **customer-visible outage**
caused by a policy rule. There is no shadow-AI finding urgent enough to justify that risk.
This is not tunable per tenant.

### 3. Severity ceiling — contract severity ≠ console severity

Contract severity expresses *analytical* importance. Console severity drives *paging*.
They are not the same field and must not be copied across.

| Contract | Console severity at first deploy |
|---|---|
| low | Low |
| medium | Low |
| high | **Medium** — capped |

Only two rules may be promoted to console High, and only after passing T4 canary with
volume inside budget:

- **RC-05.03** — inference API reachable off-host (unauthenticated LLM API on the LAN)
- **RC-09.05** — relocated known binary (deliberate evasion, not policy noise)

Everything else stays at or below Medium permanently. If a rule seems to warrant High,
that is a signal to re-examine the rule, not the ceiling.

### 4. Separate queue — never the incident queue

Route by the `shadow-ai` tag to a dedicated view/queue. Requirements:

- Not paged on. Reviewed on a business-hours cadence.
- Not counted in MTTR/MTTD metrics for threat detection.
- Not auto-escalated to the customer.
- Distinct disposition codes: `policy-violation`, `approved-tool`, `false-positive`,
  `escalate-to-security`.

The only findings that cross into the incident queue are RC-05.03, RC-09.05 and RC-03.06
(unsigned binary carrying AI metadata) — and only after a human review step.

### 5. Rule budget — never starve threat detection

STAR enforces a cap on active rules per scope. AI detection must not consume slots that
threat detection needs.

```
ai_rule_budget = min(25% of tenant STAR allowance, 20 rules)
```

Record the tenant's allowance and current usage in `tenants/<name>.yaml` before the first
deploy. If adding a rule would breach the budget, **retire a lower-value AI rule** — do
not raise the budget. Budget pressure is the correct signal that the rule set needs
pruning.

### 6. Scope discipline — group-scoped by default

| Family | Scope |
|---|---|
| RC-02, RC-03, RC-05, RC-09.04/05/06 | Site-wide acceptable (low volume) |
| RC-06, RC-07 | Group-scoped (developer populations) |
| **RC-08.03** | **`restricted_groups` only — never site-wide** |
| RC-08.01/02/04, RC-09.01/02 | Site-wide only after T4 volume evidence |

RC-08.03 (consumer AI domains) is unusable fleet-wide. It is scoped by tenant overlay and
`tools/preflight.py` refuses to render it without one.

### 7. Exclusions stay separate

- **Never** edit a shared, global, or threat-detection exclusion to silence an AI rule.
- Tune inside the rule query, or in `tenants/<name>.yaml` overrides.
- An exclusion added for shadow AI that also blinds a malware rule is the single worst
  outcome this programme can produce.

---

## Pre-deployment gate

All seven must be true. `tools/preflight.py --tenant <name>` checks what is checkable;
the rest is a human sign-off recorded in the change record.

- [ ] Rule names carry contract IDs; `shadow-ai` tag applied
- [ ] Response = Alert only on every rule
- [ ] Console severity within ceiling
- [ ] `shadow-ai` queue exists and is excluded from paging and threat-detection metrics
- [ ] Tenant STAR allowance and current usage recorded; budget not breached
- [ ] Scoping matches the table above; RC-08.03 has `restricted_groups`
- [ ] No shared/global exclusions modified

---

## What "no operational impact" does not mean

It does **not** mean zero alerts. A rule set that never fires is not safe, it is broken —
see the dead-rule check in [SOP-04](04-maintenance.md).

It means: predictable volume, in a separate queue, at a severity that does not page, with
no response actions, inside a rule budget that leaves threat detection untouched.
