# AI Detection Rules

Shadow-AI detection across multiple SentinelOne customers. Contract-first so the same
requirements port to Defender and Falcon.

## Layout

```
contract/     WHAT must be detected — vendor-neutral, stable, IDs immutable
identity/     WHO we're detecting — apps, domains, hashes
rules/        HOW, per platform — one file per rule, disposable
tenants/      Per-customer overlays — scoping, exemptions, overrides
tools/        validate · coverage · render · harvest
```

**Contract is stable. Rules are disposable.** Query languages change, vendors change,
install paths move every release. Contract IDs do not.

## Quick start

```bash
python3 tools/coverage.py                          # what's covered, what isn't
python3 tools/validate.py                          # CI gate
python3 tools/render.py --tenant acme              # deployable S1QL for one customer
python3 tools/render.py --rule RC-03.01/v1
```

## Processes

**Read [`docs/processes/00-isolation.md`](docs/processes/00-isolation.md) before deploying
anything.** AI detection must not degrade production detection: separate queue, no response
actions, capped severity, its own rule budget.

| SOP | Covers |
|---|---|
| [00 Isolation](docs/processes/00-isolation.md) | Seven controls keeping this out of SOC operations |
| [01 Discovery and sampling](docs/processes/01-discovery-and-sampling.md) | Telemetry-first: cluster → gap → rule. Lab confirms, never decides |
| [02 Testing](docs/processes/02-testing.md) | T0–T5 gates; T2 measures recall *and* precision |
| [03 Deployment](docs/processes/03-deployment.md) | Tenant rings R0→R2, waves, change records |
| [04 Maintenance](docs/processes/04-maintenance.md) | Harvest cadence, rule health, deprecation |
| [05 Rollback](docs/processes/05-rollback.md) | Emergency stop, < 5 min |

```bash
python3 tools/preflight.py --tenant acme --wave 1   # enforces config/gates.yaml
```

## Identity tiers

Four ways to identify the same binary, each with a different failure mode. Rules OR
across them.

| Tier | Identity | Update | Rename | Relocate |
|---|---|---|---|---|
| IT-1 | Code signer | ✅ | ✅ | ✅ |
| IT-2 | Embedded metadata | ✅ | ✅ | ✅ |
| IT-3 | Install path | ✅ | ✅ | ❌ |
| IT-4 | SHA-256 | ❌ | ✅ | ✅ |

**Windows:** `OriginalFilename` is inside the PE — IT-2 is strong.
**macOS:** `Info.plist` is a sibling file in the bundle, strippable — lean on IT-1.

SHA-256 exists to catch a known binary that was **renamed or moved** (IT-3 misses both).
It breaks on every vendor release, so it is maintained by the harvest loop, not by hand.

## The three rules the hash dictionary exists for

- **RC-09.04** hash drift — known signer, unknown hash → harvest queue, not an alert
- **RC-09.05** relocated binary — known hash, unexpected path → **real evasion signal**
- **RC-09.06** renamed binary — AI metadata, mismatched filename

RC-09.05 is the payoff. Without it you have an inventory; with it you have a detection.

## Rules never hardcode identity data

Queries reference `{{ app:claude-desktop.paths }}`, `{{ domains:tier_a_jurisdiction }}`,
`{{ hashes:* }}`. `render.py` expands from `identity/`. One source of truth —
`validate.py` fails the build on hardcoded literals.

## Deployment waves

| Wave | Rules | Why |
|---|---|---|
| 1 | RC-02.01/02, RC-03.01 v1+v4, RC-05.01 | Low volume, high signal, builds inventory |
| 2 | **Harvest** → seed `identity/hashes/` | Hard gate — nothing below works until seeded |
| 3 | RC-03.01/v3, RC-09.04/05/06, RC-02.05, RC-03.06 | Evasion detections |
| 4 | RC-06.x, RC-07.x, RC-05.03 | Developer + browser surface |
| 5 | RC-08.x, RC-09.01/02 | Highest volume — fix DoH policy first |

**Wave 2 is a hard gate.** Rules marked `status: blocked-on-harvest` reference empty
hash lists. Deploy them before harvesting and they match nothing while looking healthy.

## Verified field availability

[`docs/FIELD-VERIFICATION.md`](docs/FIELD-VERIFICATION.md) — live evidence, 2026-09-05.

- **S1 telemetry lands on only a minority of tenants.** Probe before assuming coverage —
  those tenants are the de-facto R0/R1 ring and T2 replay can only run there.
- **IT-1 signer ✅ / IT-4 sha256 ✅** — both on `@s1.sourceprocess*`. RC-09.04 harvest is
  viable today.
- **IT-2 metadata ❌ confirmed absent** — no `originalfilename`/`internalname` in `@s1.*`.
  RC-03.01/v2, RC-03.02/v2, RC-09.06, RC-03.06 cannot be built on the Fluency feed.
- **TP-DNS ❌** — no `@s1.*` DNS fields. All of RC-08 must run in the S1 console.
- Fluency's feed is **threat/alert-shaped**, not raw DV. Hashes and signer live on
  *source/parent* process; our rules target `tgt.*`. Same data, two access shapes.

## Getting Deep Visibility data

Fluency receives S1's **Alerts** feed — only what already fired — which cannot support
SOP-01 discovery. SentinelOne's documented answer is **Cloud Funnel**, a per-endpoint paid
add-on licensed on the *customer's* account. See
[`docs/CLOUD-FUNNEL-ONBOARDING.md`](docs/CLOUD-FUNNEL-ONBOARDING.md).

Not a prerequisite: Wave 0 discovery, T1 and T3 all work in the S1 console today.

Where telemetry for signature development comes from —
[`docs/TELEMETRY-SOURCING.md`](docs/TELEMETRY-SOURCING.md). Short version: **no public S1
telemetry corpus exists**, so an NFR lab is the route. The RC-09.04 hash harvest can run on
an existing Alerts feed today with no new licensing.

## Known gaps (declared, not overlooked)

- **RC-11.01/02** — EDR cannot distinguish a personal AI account from corporate SSO on
  the same domain. Needs SWG tenant-restriction headers or IdP enforcement.
- **DoH** blinds all of RC-08. Fix by policy (`DnsOverHttpsMode=off`); RC-09.01 is a stopgap.
- **`tgt.file.internalName` on Process Creation** is unverified on SentinelOne. If absent,
  RC-03.01/v2 and RC-09.06 move to File Creation events or to Sysmon/Falcon/Defender.

## Multi-tenant

Base rules are identical for every customer. Only `tenants/<name>.yaml` differs:
`restricted_groups`, `approved_apps`, `exempt_groups`, per-rule `overrides`.

Overlays never suppress RC-09.05/09.06 — an *approved* app running from the wrong path
is still evasion.
