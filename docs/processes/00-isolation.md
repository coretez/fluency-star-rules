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

**Why this control needs to be explicit rather than assumed.** In SentinelOne these are
checkboxes in the rule-creation flow, not a separate privileged action:

> "by checking a box when creating a rule, the analyst can enable STAR to kill any process
> that matches a STAR rule… By checking a different box, the user can enable STAR to
> automatically quarantine any device that sees a matching event."
> — [SentinelOne on STAR](https://www.sentinelone.com/blog/customize-your-edr-to-adapt-to-your-environment-with-sentinelone-storyline-active-response-star/)

Kill and quarantine are one click away from alert-only, on the same screen, during routine
rule authoring. That is precisely why it is a written control with a
[rollback SOP](05-rollback.md) behind it rather than an assumption about good judgement.

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

### 5. Rule budget — 100 documented, tier mapping UNVERIFIED

| Source | Figure | Confidence |
|---|---|---|
| [Package datasheet](https://www.cvisionintl.com/media/xhlbwibj/datasheet-sentinelone-singularity-product-packages.pdf) (`S1-DS-...-02162024`, © 2024) | *"STAR Custom Detection Rules. **100 default. Upgradable.**"* | Documented |
| [STAR blog](https://www.sentinelone.com/blog/customize-your-edr-to-adapt-to-your-environment-with-sentinelone-storyline-active-response-star/) | *"up to **1,000** STAR rules"* | Documented |
| "Complete gets 1,000" | — | ❌ **Not established. Do not assume it.** |

#### Three reasons to treat the mapping as unknown

1. **The tier ticks do not extract.** The datasheet's Core/Control/Complete columns mark
   inclusion with glyphs that are graphics, not text. Zero extracted. Which tiers include
   STAR, and whether the 100 varies by tier, is **not readable from this document.**
2. **The datasheet is from February 2024** and describes Core / Control / Complete. The
   current published lineup is **Complete / Commercial / Enterprise**. The figures may
   still hold; the tier names definitively do not.
3. **An unattributed "Open XDR data only" qualifier sits in the STAR row's tier columns.**
   See §5b — it is potentially the most consequential unknown in this repo.

#### The working assumption

**100 default, upgradable toward a 1,000 ceiling.** That reads consistently across both
sources, but it is an inference, not a documented mapping.

```
ai_rule_budget = 25 rules          # 25% of the documented 100 default
```

The full 34-rule pack deliberately does not fit. Deploy by wave (wave 1 is 7 rules),
upgrade the entitlement, or prune the `/v3` hash variations first — they are the harvest
product and duplicate coverage `/v1` and `/v4` already give you.

**Record each tenant's real `star_allowance`.** An upgraded tenant looks identical to a
default one until you hit the wall.

### 5a. Tier prerequisite — Complete or above *(probable, not confirmed)*

The Complete description block lists *"Custom detections and automated hunting rules with
Storyline Active Response (STAR™)"* alongside Deep Visibility and Storyline, which puts
STAR at Complete and above. That reading comes from a **two-column prose layout**, not from
the tick table, so treat it as probable rather than confirmed.

The current lineup starts at Complete, so any tenant on a current package should have STAR.
The exposure is legacy Core/Control tenants. `preflight.py` blocks on those.

### 5b. OPEN QUESTION — "Open XDR data only"

The STAR row carries the qualifier **"Open XDR data only"** in one of the tier columns. The
column it belongs to did not extract.

**If that qualifier applies to a tier one of your tenants is on, every rule in this repo is
inoperable there.** Open XDR data is *ingested third-party* telemetry. Every rule here
queries **native** SentinelOne endpoint events — `tgt.process.*`, `event.dns.request`,
`url.address`. A STAR entitlement limited to Open XDR data would not evaluate any of them.

This is not a tuning detail. It decides whether the pack functions at all on a given tier,
and it is the first thing to confirm.

#### Ask the rep, in writing

1. For **Singularity Complete**, what is the STAR custom-detection-rule entitlement — 100,
   1,000, or something else? What does an upgrade cost and what is the ceiling?
2. Does the entitlement differ across **Complete / Commercial / Enterprise**?
3. **Does STAR on our tier evaluate native SentinelOne endpoint telemetry, or Open XDR
   ingested data only?** ← blocking
4. Is there a per-Site/Account/Group limit distinct from the tenant total?

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
