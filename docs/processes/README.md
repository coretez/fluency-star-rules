# Processes

| SOP | Covers | Owner |
|---|---|---|
| [00 — Isolation model](00-isolation.md) | **Read first.** How AI detection stays out of production detection's way | Detection Eng Lead |
| [01 — Discovery and sampling](01-discovery-and-sampling.md) | Mining telemetry for gaps; lab capture only to confirm what discovery found | Detection Eng |
| [02 — Signature testing](02-testing.md) | T0–T5 gates before any customer sees a rule | Detection Eng |
| [03 — Deployment](03-deployment.md) | Staged rollout across tenants, change control | MSSP Ops |
| [04 — Maintenance](04-maintenance.md) | Harvest, review, deprecation, rule health | Detection Eng |
| [05 — Rollback](05-rollback.md) | Emergency stop. Print this one | On-call |

Thresholds live in [`gates.yaml`](../../config/gates.yaml) and are enforced by
`tools/preflight.py`. Change them there, not in prose.
