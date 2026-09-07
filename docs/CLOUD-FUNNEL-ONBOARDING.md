# Getting Deep Visibility into Fluency — how SentinelOne documents it

Researched 2026-09-05. **All sources are third-party integrators** (Exabeam, Red Canary,
Panther, Sekoia, Google SecOps) — SentinelOne's own runbook is behind the support login.
Confirm every step with S1 or your distributor before acting.

## The problem this solves

Fluency currently receives the **Alerts API** feed from S1 — only what already fired.
[SOP-01](processes/01-discovery-and-sampling.md) is telemetry-first and needs Process
Creation, DNS, File and Registry events. You cannot mine for what you missed in a stream
that only contains what you caught. See [FIELD-VERIFICATION](FIELD-VERIFICATION.md).

SentinelOne's documented answer is **Cloud Funnel**.

---

## 1. Licensing — it is a paid add-on, per endpoint

Cloud Funnel is **not included** in the base tiers. It is sold as its own SKU — CDW lists
`PM-CFL-ND-T1-F`, *"SentinelOne Cloud Funnel Data Export — subscription license, 1 year,
1 endpoint."*

**Per-endpoint pricing.** Size it against the endpoint count of the tenants that actually
hold S1 telemetry — not your whole estate. In a typical MSSP book that is a small fraction
of tenants, which makes the number smaller than it first looks.

### The MSSP structural problem

Cloud Funnel is licensed **on the customer's S1 account**, not yours. You cannot enable it
from the MSSP side. Each tenant must purchase it through whoever sells them their S1
licenses.

That makes this a **commercial conversation per customer**, not an internal infrastructure
decision. Plan it as such: the pitch is "we can detect shadow AI and hunt across your
endpoint telemetry, which requires this add-on," not "we need a feed."

## 2. Verify whether it is already enabled

```
Settings ▸ Accounts ▸ (action button on the account) ▸ Edit Account ▸ Add-ons
```

If **Cloud Funnel** appears in Add-ons, tick it. If it does not appear, it is not licensed
— contact the license channel.

Do this first for every tenant that holds S1. It is free to check and it may already be on.

## 3. Configure

```
Settings ▸ Integrations ▸ Cloud Funnel
```

Requires a SentinelOne admin account with **"Account" user scope**.

## 4. Destination — object storage, not syslog

Cloud Funnel streams to **customer-owned AWS S3 or Google Cloud Storage**. There is no
direct syslog or HEC destination, so Fluency must ingest from the bucket — the same
S3 + SQS-notification pattern Exabeam, Panther and Red Canary use.

Setup on the AWS side:

1. Create the S3 bucket
2. Grant SentinelOne **write objects** and **list objects**
3. Share the bucket details with SentinelOne
4. Configure S3 → SQS notification so Fluency is told when new objects land

> ⚠️ **Get the canonical ID from SentinelOne directly.** The setup requires adding S1's
> AWS canonical ID to your bucket ACL. Third-party docs publish a value for it, and one
> appears in the Exabeam page — **do not use it.** A canonical ID in a bucket ACL grants
> write access to whoever holds it; taking that string from a search result rather than
> from your S1 rep is exactly the kind of thing that should be verified at the source.
> Ask S1 to confirm the current value in writing.

## 5. Volume and cost — scope before committing

Three cost dimensions, and only the first is obvious:

1. Cloud Funnel license — per endpoint, customer-paid
2. S3/GCS storage and request costs — yours or theirs, decide up front
3. **Fluency ingest volume** — full EDR telemetry is orders of magnitude larger than the
   alert feed. This lands on your own platform economics

SentinelOne's platform marketing claims "granular control to filter and select fields to
manage volume and cost." **None of the third-party docs I found document that filtering
UI**, so treat it as unconfirmed and ask S1 to demonstrate it before you size the deal.

**If filtering exists, use it carefully.** Per [FIELD-VERIFICATION](FIELD-VERIFICATION.md),
the value of Cloud Funnel for [SOP-02](processes/02-testing.md) T2 is that it is *the same
event stream the STAR engine sees*. Filter aggressively and that equivalence breaks — you
would be testing against a subset. Record the funnel filter configuration alongside every
T2 result.

Minimum fields the contract needs, if you do filter:

```
event.type  event.category
tgt.process.image.path  tgt.process.name  tgt.process.cmdline
tgt.process.image.sha256          ← IT-4
tgt.process.image.originalFileName ← IT-2
tgt.process.publisher  tgt.process.signedStatus  tgt.process.verifiedStatus  ← IT-1
src.process.name  src.process.parent.name
event.dns.request                 ← all of RC-08
tgt.file.path  dst.ip.address  dst.port.number
endpoint.name  endpoint.os  agent.uuid
```

---

## Fallbacks if Cloud Funnel is not purchasable

| Option | Gets you | Limits |
|---|---|---|
| **S1 console DV** | Full schema, authoritative | Per-tenant, manual, no cross-tenant pivot — the main MSSP advantage is lost |
| **Deep Visibility query API** | Pull DV results programmatically | Rate-limited; suits T2 sampling, not continuous discovery |
| **Activities API** `/web/api/v2.1/activities` | Audit activity stream | **Not** DV — no process/DNS telemetry. Does not solve this |
| **Status quo (Alerts feed)** | What already fired | Cannot support SOP-01 discovery at all |

**The honest fallback is the console.** Author and test STAR rules there per tenant, and
accept that cross-tenant discovery waits for Cloud Funnel. That is a working programme —
it just gives up the MSSP-scale advantage the contract was designed around.

---

## Recommended sequence

1. **Check Add-ons on each S1 tenant** — free, may already be enabled
2. If enabled → configure to a bucket, wire Fluency ingest, re-run
   [FIELD-VERIFICATION](FIELD-VERIFICATION.md) and expect `tgt.process.image.*` to appear
3. If not enabled → get per-endpoint pricing for that tenant's estate, and decide whether it
   is a customer pitch or an internal cost
4. **Either way, do not block on it.** Wave 0 discovery and T1/T3 all work in the console
   today. Cloud Funnel improves T2 fidelity and makes discovery cross-tenant; it is not a
   prerequisite for writing the first rules

## Sources

[S1 Cloud Funnel platform page](https://www.sentinelone.com/platform/singularity-cloud-funnel/) ·
[Red Canary integration](https://docs.redcanary.com/docs/integrate-sentinelone-cloud-funnel-with-red-canary) ·
[Exabeam prerequisites](https://docs.exabeam.com/en/collectors/all/cloud-collectors-administration-guide/onboard-cloud-collectors/sentinelone-cloud-funnel-cloud-collector/prerequisites-to-configure-the-sentinelone-cloud-funnel-cloud-collector.html) ·
[Sekoia Cloud Funnel 2.0](https://docs.sekoia.com/integration/categories/endpoint/sentinelone_cloudfunnel2.0/) ·
[Panther SentinelOne](https://docs.panther.com/data-onboarding/supported-logs/sentinel-one) ·
[CDW SKU listing](https://www.cdw.com/product/sentinelone-cloud-funnel-data-export-subscription-license-1-year-1-en/8459198)
