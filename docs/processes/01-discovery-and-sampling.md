# SOP-01 — Discovery and sampling

**Signatures are derived from telemetry, not from a wish list.**

The primary input is data we already hold: existing alerts, cases, behaviour clusters,
and raw DV events. We take a cluster, ask *what else did we miss*, and the gap becomes
the next rule. The lab exists to confirm the identity of things discovery found — never
to decide what to look for.

**Operational impact: none.** Everything in Mode A is a query. No rules, no rule budget,
no alerts, no SOC queue. This SOP can run in a customer tenant before a single rule is
deployed.

---

## Why this order

A lab-first process can only confirm apps someone already thought of. It is structurally
blind to the long tail — the tool a user installed last week that nobody has heard of —
which is most of the shadow-AI problem.

Telemetry-first inverts it. The environment enumerates itself; we lab-confirm only what
it surfaced.

`RC-09.04` (hash drift) is this pattern already: known signer, unknown hash, harvest it.
That rule is one instance of the loop below, not a special case.

---

## The loop

```
  cluster  ──▶  pivot  ──▶  gap  ──▶  sample  ──▶  rule  ──▶  backtest
     ▲              "what else                                    │
     └──────────── did we miss?" ◀───── new cluster ──────────────┘
```

Continuous, not a one-time build. Each pass through narrows a gap and usually opens a
smaller one.

---

# Mode A — Telemetry-derived (primary)

## A1. Discovery sweep — the Wave 0 inventory

Broad, deliberately low-precision hunts. Purpose is enumeration, not detection. Run over
30–90 days per tenant. **These are hunts. Do not promote them to rules** — they are far
too noisy and that is intentional.

**Unknown vendors by signer** — finds AI apps we never listed:
```
event.type = "Process Creation"
AND tgt.process.publisher in contains anycase ("AI","Labs","Intelligence","Anthropic","OpenAI","Perplexity","Mistral","Cohere","Hugging")
| group count() by tgt.process.publisher, tgt.process.name
```

**Unknown apps by name shape:**
```
event.type = "Process Creation"
AND tgt.process.image.path in contains anycase ("gpt","llm","llama","copilot","chatbot","-ai","ai-","assistant","agent")
| group count() by tgt.process.image.path
```

**Unknown services by DNS** — the highest-yield sweep:
```
event.type = "DNS Resolved"
AND (event.dns.request contains ".ai" OR event.dns.request in contains anycase ("gpt","llm","claude","chat","copilot","inference","model"))
| group count() by event.dns.request, src.process.name
```

**Local inference by listening port:**
```
event.type = "IP Connect" AND event.network.direction = "INCOMING"
AND dst.port.number in (11434, 1234, 8080, 5000, 7860, 8000)
| group count() by src.process.name, dst.port.number
```

**Model weights on disk:**
```
event.type = "File Creation"
AND tgt.file.path in contains anycase (".gguf",".safetensors",".ggml")
| group count() by tgt.file.path, src.process.name
```

**Package-manager installs:**
```
event.type = "Process Creation"
AND tgt.process.cmdline in contains anycase ("pip install","npm install","brew install","pipx install")
AND tgt.process.cmdline in contains anycase ("ai","gpt","llm","anthropic","openai","langchain","ollama")
| group count() by tgt.process.cmdline
```

**Output → `discovery/<tenant>/<date>.md`.** Every distinct publisher, process, domain and
port, with counts and endpoint spread. This is the tenant's actual AI footprint and it will
contain things not in `identity/apps.yaml`. Those are the backlog.

## A2. Cluster expansion — "what else did we miss?"

Start from something real: an existing case, a behaviour cluster, a confirmed AI finding,
or a single high-confidence hit from A1.

Pivot outward and record everything:

| Pivot | Question |
|---|---|
| **Endpoint** | What else AI-adjacent ran on this host in ±7 days? |
| **User** | Same activity on their other devices? |
| **Process tree** | What spawned it? What did it spawn? |
| **Signer** | Every other binary from this publisher, fleet-wide |
| **Hash** | Same binary elsewhere — different path or name? (→ RC-09.05) |
| **Domain** | Every process resolving it; every other domain those processes touched |
| **Timing** | File/archive activity immediately preceding AI egress (→ RC-10) |

The pivot that most often pays: **signer → fleet-wide**. One confirmed app surfaces every
other product from the same vendor, plus every version and install variant in the estate.

For each pivot, ask the question directly: **did an existing rule fire on this? If not,
why not?** The answers cluster into a small number of causes:

- Wrong tier — path rule, binary was relocated → needs the IT-4 variation
- Wrong scope — rule was group-scoped, activity was elsewhere
- Not in identity — app absent from `apps.yaml`
- No contract item — genuinely uncovered behaviour
- Telemetry gap — the primitive is not available (DoH, or a field this agent lacks)

## A3. Record the gap

One record per miss, in `gaps/`:

```
gap:          GAP-2026-09-014
found_in:     case 4471 / cluster behaviour-key 8823
observation:  ollama.exe running from D:\tools\ollama\ — RC-05.01/v1 path rule missed it
cause:        wrong tier — path-only coverage, no hash/signer variation for ollama
contract:     RC-05.01  (existing item, missing variation)
proposal:     add RC-05.01/v4 signer variation
evidence:     12 endpoints, 3 tenants, 90d
```

Cause `no contract item` is the one that changes the contract — everything else is a rule
or identity change. Route those to the quarterly contract review ([SOP-04](04-maintenance.md)).

> Fluency's own gap tooling (`create_investigation_gap`, `link_gap_to_signature`,
> `analyze_signature_gaps`) is the natural home for these rather than flat files, and
> keeps AI gaps in the same queue as everything else.

## A4. Extract samples from live data

Everything needed to author a rule is already in the cluster. Pull per distinct binary:

`sha256` · `image path` · `publisher / signer` · `original filename` (if the agent carries
it) · `command line` · `parent process` · endpoint and tenant spread

Feed hashes through `tools/harvest.py` — **the signer guardrail applies identically here.**
A hash observed in production is not more trustworthy than one from anywhere else; it is
recorded only when the signer matches a known vendor entry.

**Telemetry sampling has a ceiling.** DV may not expose `OriginalFileName` on process
events, and signer strings can be truncated. When either is missing, the app goes to
Mode B for authoritative capture. That is the *only* reason to open the lab.

---

# Mode B — Lab-derived (confirmatory)

**Entry condition: Mode A found something whose identity we cannot fully resolve from
telemetry.** Never a starting point.

Answers a narrower question than Mode A: *what is this thing's authoritative identity
across all four tiers?*

### Environment

**Licensing: use the SentinelOne NFR (Not-for-Resale) partner programme** — it exists for
exactly this. See [TELEMETRY-SOURCING](../TELEMETRY-SOURCING.md) for why a lab is not
optional: there is no public S1 telemetry corpus, so field-level questions
(`originalFileName` populated? `url.address` populated?) cannot be answered from
documentation.

- Dedicated VM per OS. **Never a production or corporate-managed endpoint.**
- Snapshot before install; revert after capture.
- Egress restricted to vendor download/update domains. AI apps phone home on first run —
  you want that observed, not blocked.
- EDR agent installed and reporting, so the install produces the telemetry a real endpoint
  would.

These are legitimate commercial applications, not malware. Isolation is for clean capture
and reversibility, not containment.

### Provenance — record before running anything

`samples/<app>/<version>/PROVENANCE.md`:

```
app:              ollama
version:          0.4.2
os:               windows
source_url:       https://ollama.com/download      # vendor official ONLY
downloaded:       2026-09-05T14:22Z
downloaded_by:    cjordan
tls_verified:     yes
installer_sha256: <hash of the downloaded installer>
discovered_via:   GAP-2026-09-014 (12 endpoints, 3 tenants)
```

If the download redirects off the vendor's domain, **stop** and record why. A CDN on the
vendor's own domain is fine; a mirror is not.

### Capture — all four tiers

**Windows**
```powershell
Get-FileHash -Algorithm SHA256 '<path>'
(Get-Item '<path>').VersionInfo | Format-List OriginalFilename,InternalName,FileVersion,CompanyName
Get-AuthenticodeSignature '<path>' | Select -Expand SignerCertificate | Format-List Subject,Thumbprint
```

**macOS**
```bash
shasum -a 256 "<binary>"
codesign -dv --verbose=4 "<app>.app" 2>&1 | grep -E 'TeamIdentifier|Identifier|Authority'
plutil -p "<app>.app/Contents/Info.plist" | grep -E 'CFBundleIdentifier|CFBundleExecutable'
```

Then run the app ~10 minutes and collect from the EDR console: process tree (including the
helper children to exclude), DNS, listening ports, config and weight paths, persistence.

### Negative samples — required

Per app, at least one benign lookalike: a differently-signed binary with a similar name; a
legitimate app writing to the same directories; for `RC-06.02`, a non-AI binary named
`claude`, `codex` or `llm` (this collision is real and will occur).

Negative samples are how T3 proves specificity. **A rule with no negative test has not
been tested.**

### Record

1. `identity/apps.yaml` — signer, `original_filename`, paths, `install_root` (human PR)
2. `identity/hashes/<app>.yaml` — via `tools/harvest.py --apply` only
3. `samples/<app>/<version>/PROVENANCE.md`
4. Revert the snapshot

Binaries are **not** committed. Provenance and derived identity only.

**Never** populate hashes from VirusTotal, a vendor blog, a threat feed, or a file someone
sends you. Only from a binary you installed yourself, or from your own fleet telemetry.

---

## Cadence

| Trigger | Mode | Action |
|---|---|---|
| New tenant onboarded | A1 | Discovery sweep before any rule deploys |
| Case involving AI, data movement, or an unknown binary | A2 | Cluster expansion |
| Quarterly | A1 | Re-sweep — the footprint changes |
| RC-09.04 fires | A4 | Weekly harvest (signer-gated) |
| Discovery found an app we cannot identify from telemetry | B | Lab capture |
| Vendor major release | B | Re-verify paths and signer, not just hash |
| **Signer changes** | B | **Stop.** Cert rotation or impersonation — verify out-of-band |
| Quarterly | B | Re-verify `verify: true` entries in `apps.yaml` |
