# MACHINE-OWNED — do not hand-edit

Written by `tools/harvest.py`. Hand edits will be overwritten and, worse, will bypass
the signer guardrail.

## Why this is isolated

1. **Change cadence.** Hashes churn on every vendor release (Claude Desktop auto-updates
   via Squirrel). `apps.yaml` and `domains.yaml` change monthly at most. Sharing a file
   means every harvest commit conflicts with human edits.
2. **Ownership.** A bot writes here. Humans write everywhere else.
3. **Security.** Hashes appear in `NOT ... in (...)` exclusion clauses (RC-09.04).
   Write access here is the ability to create a blind spot. Gate it separately in
   CODEOWNERS with branch protection.

## Harvest loop (RC-09.04)

1. IT-3 path rules + IT-1 signer rules run continuously
2. Weekly: extract distinct `(sha256, path, signer, original_filename, version)`
3. Diff against these files
4. New hash **+ matching signer + matching original_filename** → append, set `first_seen`,
   open a low-priority review task
5. New hash **+ NO signer match** → **do NOT append.** Escalate: possible impostor
6. Existing hash at an unexpected path → RC-09.05, escalate as evasion

**Step 5 is the guardrail.** Never auto-trust a hash on filename alone, or this
directory becomes an allowlist an attacker can write to.

## Seeding

Empty arrays are intentional. Populate from a binary you installed yourself from the
vendor's official download, or from your own fleet telemetry. Never from a public
source, and never from a file handed to you.
