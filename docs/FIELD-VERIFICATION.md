# Field verification — live evidence

Verified 2026-09-05 against a live Fluency MSSP deployment (`fluency-mssp` 0.9.0).
Method: `describe_available_fields` / `count_resources_across_tenants` /
`review_sentinelone_footprint`. Re-verify per tenant before deploying.

## Where SentinelOne data actually is

Probed every tenant in the estate with `count_resources_across_tenants`
(`sentinelOneAgent`, `sentinelOneApplication`, `sentinelOneThreat`).

**Only a small minority carry SentinelOne at all.** The rest are
O365 / Azure / Okta / Defender / email-security estates with no S1 resources. A further
handful return connector errors rather than empty results — worth distinguishing, since an
errored probe is not evidence of absence.

**Consequence:** T2 historical replay ([SOP-02](processes/02-testing.md)) can only run
where S1 data actually lands. Identify those tenants first; they become the de-facto
R0/R1 ring whether or not you planned it that way.

**Run this before assuming coverage.** "We support SentinelOne" and "we hold SentinelOne
telemetry for this customer" are different claims, and only the second one lets you
develop signatures.

---

## THREE schemas — do not conflate

| Schema | Naming | Where | Carries |
|---|---|---|---|
| **Alerts API** | `sourceProcessInfo.*`, `targetProcessInfo.tgtProcName` | **What Fluency receives today** | Alerts only |
| **Deep Visibility 2.0** | `tgt.process.image.sha256` (dotted) | S1 console; Cloud Funnel export | Full telemetry |
| **Legacy DV** | `TgtProcImagePath` (Pascal) | What pySigma emits ([ADR-0001](ECOSYSTEM.md)) | Full telemetry |

Fluency's `@s1.*` field set maps **exactly** onto the Alerts API objects —
`sourceProcessInfo`, `targetProcessInfo`, `agentDetectionInfo`, `agentRealtimeInfo`,
`threatInfo`. No dotted `tgt.process.image.*` field appears anywhere. That is the
signature of an Alerts integration, not a DV one.

**In DV 2.0, `src.process.*` is the process performing the action and `tgt.process.*` is
the process launched or acted on** — so for Process Creation the new process is
`tgt.process.*`. Our rules target `tgt.*` and are correct for the console.

### Why the Cloud Funnel schema is valid evidence for STAR rules

Cloud Funnel is a **transport**, not a separate event model. It exports Deep Visibility 2.0
events — the same events STAR rules evaluate and the same events a DV query searches. One
event model, three consumers:

```
                   Deep Visibility 2.0 events
                   (tgt.process.image.*, event.dns.request, event.type)
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   STAR rule engine      DV query bar         Cloud Funnel export
   (real-time)           (interactive)        (streamed out)
```

This matters for two reasons.

**1. It makes public Cloud Funnel schema docs a legitimate proxy for the STAR authoring
surface.** S1's own field reference is behind the support login, but a field documented in
a DeepVisibilityV2 export schema is a field a STAR rule can query, under the same name.
That is why `tgt.process.image.originalFileName` appearing in the Panther schema is
sufficient to conclude IT-2 is available to STAR — not merely hopeful.

**2. It makes T2 replay faithful.** Today, replaying a candidate rule against Fluency's
Alerts feed predicts nothing about STAR behaviour — different schema, and the feed only
contains what already fired. Against Cloud Funnel data it is the *same event stream the
STAR engine sees*, so a T2 volume and recall measurement in Fluency becomes a direct
prediction of what the rule will do once deployed in the console.

That is the strongest argument for onboarding it: it turns
[SOP-02](processes/02-testing.md) T2 from an approximation into a measurement.

Caveat: Cloud Funnel offers field-level and event-level filtering to control volume. Filter
too aggressively and the equivalence breaks — you would be testing against a subset of what
STAR sees. Record the funnel filter configuration alongside any T2 result.

### The gap this opens — and how to close it

[SOP-01](processes/01-discovery-and-sampling.md) is telemetry-first. It needs Process
Creation, DNS, File and Registry events. **Fluency's Alerts feed carries none of those** —
only alerts that already fired. You cannot mine for what you missed in a stream that only
contains what you caught.

Two options:

1. **Author and hunt in the S1 console.** Works today, full DV schema, but per-tenant and
   manual — no cross-tenant pivot, which is the main advantage of an MSSP position.
2. **Onboard Cloud Funnel 2.0 into Fluency.** Streams full DV 2.0 telemetry: `Process
   Creation`, `Command Script`, `DNS Resolved`/`Unresolved`, `File Creation`/`Deletion`/
   `Modification`/`Rename`, `IP Connect`, `IP Listen`, Registry, module loads, logins,
   scheduled tasks. It has field-level filtering to control volume and cost.

**Option 2 is the unlock.** It would light up TP-DNS, TP-PROC-META, TP-FILE-W and TP-REG
in Fluency simultaneously, make SOP-01 cross-tenant, and let T2 replay run against real
process telemetry instead of alert history. Scope it as an infrastructure decision with a
volume/cost estimate before committing — Cloud Funnel is high-volume by design.

---

## Verified `@s1.*` process fields

### Source / parent process — richly populated

```
@s1.sourceprocessname                     @s1.sourceparentprocessname
@s1.sourceprocessfilepath                 @s1.sourceparentprocesspath
@s1.sourceprocesscommandline              @s1.sourceparentprocesscommandline
@s1.sourceprocesssha256          IT-4     @s1.sourceparentprocesssha256        IT-4
@s1.sourceprocesssha1 / md5               @s1.sourceparentprocesssha1 / md5
@s1.sourceprocessfilesigneridentity IT-1  @s1.sourceparentprocesssigneridentity IT-1
@s1.sourceprocessusername                 @s1.sourceparentprocessusername
@s1.sourceprocessintegritylevel           @s1.sourceparentprocessintegritylevel
@s1.sourceprocessstoryline                @s1.sourceparentprocessstoryline
@s1.sourceProcessFileHashSha256/Sha1/Md5
```

### Target process — shallow

```
@s1.tgtprocname          @s1.tgtprocimagepath      @s1.tgtproccmdline
@s1.tgtprocsignedstatus  @s1.tgtprocintegritylevel @s1.tgtprocuid  @s1.tgtprocstorylineid
```

**No `tgtprocsha256`. No `tgtproc` signer identity.**

### The asymmetry that matters

Our rules are written against `tgt.process.*` — correct for the S1 console, where a
Process Creation event's new process is the target. **Fluency's feed inverts the
richness:** hashes and signer identity exist only on *source* and *parent*.

For hunting in Fluency, pivot on `@s1.sourceprocess*`. For STAR rules, keep `tgt.*`.
Same underlying data, two different access shapes.

---

## The three flagged fields — resolved

### IT-1 signer — ✅ available (source/parent only)

`@s1.sourceprocessfilesigneridentity`, `@s1.sourceparentprocesssigneridentity`.
A `signer` substring search returns exactly these two and nothing else.

RC-03.01/v4, RC-03.02/v4, RC-09.04 are supportable.

### IT-2 embedded metadata — ⚠️ CORRECTED 2026-09-05

**An earlier revision of this document said "CONFIRMED ABSENT". That was wrong.**

What the evidence actually supports: `originalfilename`/`internalname` are absent from
**the Alerts feed Fluency receives**. That says nothing about Deep Visibility.

**Deep Visibility 2.0 has both fields:**

```
tgt.process.image.originalFileName        src.process.image.originalFileName
tgt.process.image.internalName            src.process.image.internalName
```

Source: [Panther SentinelOne schema](https://docs.panther.com/data-onboarding/supported-logs/sentinel-one)
(DeepVisibilityV2). Also confirmed present: `tgt.process.image.sha256`,
`tgt.process.publisher`, `tgt.process.signedStatus`, `tgt.process.verifiedStatus`.

**IT-2 is fully supported on SentinelOne.** RC-03.01/v2, RC-03.02/v2, RC-09.06 and
RC-03.06 are viable — they must simply be authored and tested **in the S1 console**, not
against Fluency's current feed. The rules now use `tgt.process.image.originalFileName`
(they previously used `tgt.file.internalName`, which was the wrong field).

Note this does not contradict [ADR-0001](ECOSYSTEM.md): the pySigma S1 backend still does
not *map* `OriginalFileName`. The field exists in the product; the Sigma translation layer
does not reach it. Both statements are true and the upstream contribution is still worth
making.

### IT-4 SHA-256 — ✅ available (source/parent only)

`@s1.sourceprocesssha256`, `@s1.sourceparentprocesssha256`, `@s1.sourceProcessFileHashSha256`.

**RC-09.04 harvest is viable today** — sha256 *and* signeridentity are both present on
source process, which is exactly the pair the signer guardrail needs. This is the fastest
path to unblocking the four `blocked-on-harvest` rules.

---

## TP-DNS — ❌ no S1 DNS in the Fluency feed

A `dns` substring search returns exactly **one** field:
`@defender.fluency.deviceDnsName`. No `@s1.*` DNS fields at all.

**All of RC-08 and RC-09.01/09.02 have no data in Fluency's S1 feed** — but again, that
is an Alerts-feed limitation, not a product one. Deep Visibility 2.0 carries
`event.dns.request` and the `DNS Resolved` / `DNS Unresolved` event types. Author in the
console, or onboard Cloud Funnel (below).

---

## Unexpected find — Copilot telemetry already ingested

`@fields.CopilotEventData.*` is present, from the O365 audit stream:

```
@fields.CopilotEventData.AISystemPlugin.Name
@fields.CopilotEventData.ModelTransparencyDetails.ModelName
@fields.CopilotEventData.ModelTransparencyDetails.ModelProviderName
@fields.CopilotEventData.ParticipatingAgents.AgentName
@fields.CopilotEventData.TargetAgentName
@fields.CopilotEventData.AccessedResources.Name
@fields.ToolName  @fields.TargetAgentName
```

This is **first-party AI usage telemetry we already hold, on far more tenants than S1** —
model provider, plugins invoked, agents participating, and *resources the AI accessed*.

It answers questions RC-11 was marked `accepted-gap` for on the endpoint side: which
model, which user, what it touched. Worth a contract family of its own rather than being
squeezed into the endpoint families. **Filed as a follow-up, not yet in the contract.**

---

## Also available for cross-platform work

`@defender.*` (alert, entities, deviceDnsName), `@okta.*`, `@blackkite.*`,
`@abnormalThreat.*`. When the contract ports to Defender ([ADR-0001](ECOSYSTEM.md)),
some of that telemetry is already flowing.

---

## `review_sentinelone_footprint` — the built-in discovery sweep

Declares primary collections:

```
application_review_candidates · security_applications · ai_applications
shadow_it_candidates · external_ip_review_candidates
```

**`ai_applications` already exists** — Fluency classifies AI apps from S1 application
inventory. This is SOP-01 A1 discovery for RC-02/RC-03, already built.

Caveat observed: with `application_limit=2500` the response hit the 300,000-char
server cap (`rows_dropped_for_size: true`, `approx_response_chars: 354938`) and returned
counts only. Page it with smaller limits, or use `summary_only` then drill in, to get the
`ai_applications` rows.
