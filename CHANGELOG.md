# Changelog

Contract IDs are immutable. Deprecate, never renumber, never reuse a retired number.

## [1.0.0] — 2026-09-05
Initial structured release. Migrated from four flat markdown files.

- Contract: 11 families, 49 items, zero-padded sortable IDs (`RC-FF.II`)
- Identity split by change cadence and owner: `apps.yaml` (rare) /
  `domains.yaml` (monthly) / `hashes/` (weekly, machine-owned)
- 31 SentinelOne rules, one file each, referencing identity via placeholders
- Tooling: validate (CI gate), coverage, render, harvest
- Tenant overlays for multi-customer deployment
