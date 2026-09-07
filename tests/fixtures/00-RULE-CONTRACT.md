# Rule Contract — GenAI Usage Visibility

Vendor-neutral. Defines **what must be detected**, not how. Implementations for
SentinelOne, Falcon, Sysmon, Defender, Bitdefender each satisfy contract items and
cite the ID they satisfy.

## Why a contract layer

- Contract IDs are **stable**. Vendor rules are **disposable** — vendors change query
  languages, you change vendors, install paths move every release.
- One contract item is satisfied by **multiple rule variations**. `RC-3.1` (Claude
  Desktop execution) is satisfied by a path rule, a metadata rule, a hash rule, and a
  signer rule. Each has a different failure mode. Together they close.
- Coverage becomes measurable. "We satisfy 34 of 41 contract items on Windows, 22 on
  macOS" is a reportable number. "We have 7 STAR rules" is not.

## ID scheme

```
RC-<family>.<item>/<variation>
        │       │        └── implementation variant: v1, v2, v3...
        │       └── contract item within the family
        └── family (1-11)
```

Every deployed rule carries its contract ID **in the rule name**, e.g.
`RC-3.1/v2 — Claude Desktop exec (OriginalFilename)`. Non-negotiable: it is the only
thing that lets you answer "why does this rule exist" two years from now.

---

# Part A — Telemetry primitives

The portability layer. A contract item declares which primitive it needs; any platform
providing that primitive can satisfy it.

| ID | Primitive | Needed for |
|---|---|---|
| `TP-PROC` | Process creation: image path, command line, parent | Execution, CLI use |
| `TP-PROC-HASH` | Process creation carrying image SHA-256 | Hash-dictionary matching |
| `TP-PROC-SIG` | Process creation carrying code-signer identity | Durable vendor identity |
| `TP-PROC-META` | Process creation carrying PE OriginalFilename / bundle ID | Rename-resistant identity |
| `TP-FILE-W` | File create/write with full path | Installation, extensions |
| `TP-FILE-HASH` | File write carrying SHA-256 | Hash harvesting at install |
| `TP-REG` | Registry write (Windows) | Persistence, uninstall keys |
| `TP-MOD` | Module / image load | Injected AI SDKs, DLL sideload |
| `TP-DNS` | DNS query **with originating process** | Network egress attribution |
| `TP-NET` | Network connect: remote IP, port, process | DoH detection, local runtimes |
| `TP-URL` | HTTP hostname or full URL | Browser AI use |
| `TP-SCRIPT` | Interpreter script content | pip/npm installs, agent scripts |

## Platform support matrix

Confirm each cell in your own environment before relying on it. Marked cells are my
best understanding, not a substitute for testing.

| Primitive | SentinelOne | CrowdStrike Falcon | Sysmon | Defender for Endpoint | Bitdefender |
|---|---|---|---|---|---|
| `TP-PROC` | ✅ Process Creation | ✅ ProcessRollup2 | ✅ EID 1 | ✅ DeviceProcessEvents | ✅ |
| `TP-PROC-HASH` | ✅ | ✅ SHA256HashData | ✅ EID 1 (enable SHA256) | ✅ SHA256 | ✅ |
| `TP-PROC-SIG` | ✅ publisher/signedStatus | ✅ | ⚠️ EID 7 only, not EID 1 | ✅ Signer fields | ⚠️ verify |
| `TP-PROC-META` | ✅ internalName | ✅ OriginalFilename | ✅ EID 1 OriginalFileName | ✅ ProcessVersionInfo* | ⚠️ verify |
| `TP-FILE-W` | ✅ File Creation | ✅ | ✅ EID 11 | ✅ DeviceFileEvents | ✅ |
| `TP-FILE-HASH` | ✅ | ✅ | ❌ EID 11 has no hash | ✅ | ⚠️ verify |
| `TP-REG` | ✅ | ✅ | ✅ EID 12/13/14 | ✅ | ✅ |
| `TP-MOD` | ✅ | ✅ | ✅ EID 7 | ✅ DeviceImageLoadEvents | ⚠️ verify |
| `TP-DNS` | ✅ DNS Resolved | ✅ DnsRequest | ✅ EID 22 | ✅ DeviceNetworkEvents | ⚠️ verify |
| `TP-NET` | ✅ IP Connect | ✅ NetworkConnectIP4 | ✅ EID 3 | ✅ | ✅ |
| `TP-URL` | ⚠️ web filter module — see S1 impl §8 | ⚠️ limited | ❌ none | ✅ RemoteUrl | ⚠️ verify |
| `TP-SCRIPT` | ✅ cmdline | ✅ cmdline | ⚠️ cmdline only | ✅ + DeviceEvents | ✅ |

**Sysmon has no `TP-URL` and no `TP-FILE-HASH`.** Any contract item depending on those
is unsatisfiable on a Sysmon-only estate — mark it as an accepted gap rather than
pretending coverage.

---

# Part B — Identity tiers

The answer to "they renamed it / moved it / it updated." Four ways to identify the same
binary, each with a different failure mode. **Detections OR across tiers.**

| Tier | Identity | Survives update | Survives rename | Survives relocation | Fails when |
|---|---|---|---|---|---|
| `IT-1` | **Code signer** (Authenticode subject / macOS Team ID) | ✅ | ✅ | ✅ | Unsigned, self-built, cert rotation |
| `IT-2` | **Embedded metadata** (PE OriginalFilename, CFBundleIdentifier) | ✅ mostly | ✅ | ✅ | Recompiled or resource-stripped |
| `IT-3` | **Install path** convention | ✅ | ✅ | ❌ | Portable build, custom dir, relocation |
| `IT-4` | **SHA-256** | ❌ **every release** | ✅ | ✅ | Any version change |

## What this means in practice

**IT-1 is your backbone, not IT-4.** A signer match survives everything except the vendor
rotating certificates. Lead with it.

**IT-2 is the rename killer — but it behaves differently per OS.**

| | Where metadata lives | Survives file rename | Survives extraction from bundle |
|---|---|---|---|
| **Windows** | PE version resource, **inside the binary** | ✅ | n/a — nothing to extract from |
| **macOS** | `Info.plist`, **sibling file in the .app bundle** | ✅ rename the .app | ❌ **stripped** |

Rename `claude.exe` to `svchost.exe` and the PE resource still reads
`OriginalFilename: claude.exe`. Most people never write this rule; it is the single
highest-value tier for the rename/relocate case on Windows.

On macOS the equivalent fields (`CFBundleIdentifier`, `CFBundleExecutable`) are not in
the Mach-O — they are in `Contents/Info.plist`. Rename the bundle and they survive; copy
the inner Mach-O out on its own and they are gone entirely.

**Therefore: macOS leans on IT-1, not IT-2.** The code signature (Team ID) *is* embedded
in the Mach-O and travels with an extracted binary. On macOS the `/v4` signer variation
carries the weight that `/v2` carries on Windows — build `/v4` first there, not last.

**IT-3 is a harvester, not just a detection.** Path rules are how you *discover* binaries
whose hashes you don't have yet. They feed IT-4.

**IT-4 is precise and perishable.** Never the only tier. Its real job is the two
derived detections below.

## The two detections that only a hash dictionary gives you

### `RC-9.4` — Hash drift (inventory maintenance)
Signer matches **and** OriginalFilename matches **and** SHA-256 is **not** in the
dictionary → new version shipped. Auto-open a review task, harvest the hash, extend the
dictionary. This is the maintenance loop that keeps IT-4 alive without manual curation.

### `RC-9.5` — Relocated known binary (genuine evasion signal)
SHA-256 **is** in the dictionary but the path is **not** the expected install path →
someone copied a known AI binary somewhere unusual, or renamed it. Unlike everything
else in this pack, this is not policy noise. Treat as a real evasion indicator and
escalate.

`RC-9.5` is the payoff for maintaining the dictionary at all. If you only harvest hashes
to match known-good installs, you have built an inventory. `RC-9.5` turns it into a
detection.

---

# Part C — Contract families

Severity: **L** informational/inventory · **M** policy violation · **H** investigate now

## RC-1 — Acquisition

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-1.1 | AI installer downloaded to disk | `TP-FILE-W` + `TP-FILE-HASH` | IT-3, IT-4 | L |
| RC-1.2 | AI installer fetched by CLI (curl/wget/Invoke-WebRequest) | `TP-PROC` | — | M |
| RC-1.3 | AI app pulled via OS package manager (winget/brew/choco/apt) | `TP-PROC` | — | L |
| RC-1.4 | AI installer arriving from removable media | `TP-FILE-W` | IT-3 | M |

## RC-2 — Installation

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-2.1 | AI installer/setup process executed | `TP-PROC` | IT-2, IT-3 | M |
| RC-2.2 | App bundle written to /Applications (macOS) | `TP-FILE-W` | IT-3 | M |
| RC-2.3 | Uninstall/ARP registry key created (Windows) | `TP-REG` | IT-3 | L |
| RC-2.4 | MSIX/Store package install | `TP-PROC` + `TP-REG` | IT-3 | M |
| RC-2.5 | Portable / no-install binary executed from user-writable path | `TP-PROC` | IT-1, IT-2, IT-4 | **H** |

RC-2.5 is deliberately high — it is install-evasion by construction.

## RC-3 — Execution

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-3.1 | Claude Desktop executed | `TP-PROC` | IT-1→4 | L |
| RC-3.2 | ChatGPT Desktop executed | `TP-PROC` | IT-1→4 | L |
| RC-3.3 | Copilot / Gemini / Perplexity desktop executed | `TP-PROC` | IT-1→4 | L |
| RC-3.4 | AI-native IDE executed (Cursor, Windsurf, Zed AI) | `TP-PROC` | IT-1→4 | M |
| RC-3.5 | AI desktop app executed from non-standard path | `TP-PROC` | IT-1, IT-2, IT-4 | **H** |
| RC-3.6 | Unsigned binary matching AI metadata executed | `TP-PROC-SIG` + `TP-PROC-META` | IT-2 | **H** |

Each RC-3.x item expects **4 variations** — see Part D.

## RC-4 — Persistence

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-4.1 | AI app added to Run key / Startup folder | `TP-REG` + `TP-FILE-W` | IT-3 | L |
| RC-4.2 | LaunchAgent/LaunchDaemon for AI app (macOS) | `TP-FILE-W` | IT-3 | L |
| RC-4.3 | AI runtime registered as a service | `TP-REG` | IT-3 | M |
| RC-4.4 | Scheduled task invoking an AI CLI | `TP-PROC` + `TP-SCRIPT` | — | M |

## RC-5 — Local inference runtime

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-5.1 | Local LLM runtime executed (ollama, llama.cpp, LM Studio) | `TP-PROC` | IT-1→4 | M |
| RC-5.2 | Local inference server bound to a listening port | `TP-PROC` + `TP-NET` | — | M |
| RC-5.3 | Local server reachable off-host (bound 0.0.0.0, not loopback) | `TP-NET` | — | **H** |
| RC-5.4 | Model weights written to disk (>1GB .gguf/.safetensors) | `TP-FILE-W` | IT-3 | L |

RC-5.3 is the one that matters: an unauthenticated inference API on the corporate LAN.

## RC-6 — Developer integration

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-6.1 | AI SDK installed via pip/npm/gem | `TP-PROC` + `TP-SCRIPT` | — | M |
| RC-6.2 | AI coding CLI executed (claude, codex, aider, gh copilot) | `TP-PROC` | IT-1→4 | M |
| RC-6.3 | IDE AI extension installed | `TP-FILE-W` | IT-3 | M |
| RC-6.4 | MCP server process spawned | `TP-PROC` | — | M |
| RC-6.5 | AI API key present in env/config write | `TP-FILE-W` + `TP-SCRIPT` | — | **H** |

RC-6.5 catches `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` landing in a dotfile or CI config
— strong evidence of programmatic use and a credential-hygiene finding in its own right.

## RC-7 — Browser-resident

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-7.1 | AI browser extension installed | `TP-FILE-W` | IT-3 | M |
| RC-7.2 | AI service installed as PWA / app shortcut | `TP-FILE-W` + `TP-REG` | IT-3 | M |
| RC-7.3 | AI-native browser executed (Comet, Dia, Atlas) | `TP-PROC` | IT-1→4 | **H** |

## RC-8 — Network egress

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-8.1 | Resolution of high-risk-jurisdiction AI domain | `TP-DNS` | — | **H** |
| RC-8.2 | Resolution of AI aggregator/proxy domain | `TP-DNS` | — | **H** |
| RC-8.3 | Resolution of mainstream consumer AI domain | `TP-DNS` | — | M (scoped) |
| RC-8.4 | **AI API resolution from a non-browser process** | `TP-DNS` | — | **H** |
| RC-8.5 | AI service hostname observed in web traffic | `TP-URL` | — | M |
| RC-8.6 | Sustained connection to local inference port from off-host | `TP-NET` | — | **H** |

RC-8.4 is the highest-value single item in the contract. It isolates programmatic bulk
data movement from ordinary browsing.

## RC-9 — Evasion & obfuscation

| ID | Intent | Primitive | Tier | Sev |
|---|---|---|---|---|
| RC-9.1 | Browser bypassing corporate DNS via DoH | `TP-NET` | — | M |
| RC-9.2 | DoH resolver hostname resolved | `TP-DNS` | — | M |
| RC-9.3 | AI traffic via aggregator masking backend model | `TP-DNS` | — | **H** |
| RC-9.4 | **Hash drift** — known signer+metadata, unknown SHA-256 | `TP-PROC-HASH` + `TP-PROC-SIG` | IT-1, IT-2, IT-4 | L → auto-harvest |
| RC-9.5 | **Relocated known binary** — known hash, unexpected path | `TP-PROC-HASH` | IT-3, IT-4 | **H** |
| RC-9.6 | Renamed binary — AI OriginalFilename, mismatched on-disk name | `TP-PROC-META` | IT-2 | **H** |

RC-9.4/9.5/9.6 are the three rules that only exist because you maintain the dictionary.

## RC-10 — Data movement precursor

Correlation-only. **Cannot be expressed in STAR** — needs SIEM.

| ID | Intent | Primitive | Sev |
|---|---|---|---|
| RC-10.1 | Bulk source-repo read followed by AI API egress, same process tree | `TP-FILE-W` + `TP-DNS` | **H** |
| RC-10.2 | Archive created then AI API egress within N minutes | `TP-FILE-W` + `TP-DNS` | **H** |
| RC-10.3 | First-ever AI resolution from a restricted-group endpoint | `TP-DNS` | M |
| RC-10.4 | DoH bypass present **and** zero AI DNS → coverage gap, not clean | `TP-NET` + `TP-DNS` | M |

RC-10.4 is a meta-detection. Without it, a DoH-enabled fleet reports as compliant.

## RC-11 — Identity & tenancy

| ID | Intent | Primitive | Sev | Status |
|---|---|---|---|---|
| RC-11.1 | Personal account on a sanctioned AI domain | `TP-URL` | **H** | ❌ **Not satisfiable by EDR** |
| RC-11.2 | AI service auth bypassing corporate IdP | — | **H** | ❌ IdP/SWG only |

**Declare RC-11 an accepted gap in writing.** DNS and hostname telemetry cannot separate
a corporate SSO session from a personal free account on the same domain. Closing it
requires SWG tenant-restriction headers or IdP enforcement. Recording it as an explicit
gap is what stops someone assuming the EDR covers it.

---

# Part D — Variation pattern

Every RC-3.x and RC-5.x item expands into four variations. Same intent, four
independent failure modes.

| Variation | Tier | Detects | Blind to |
|---|---|---|---|
| `/v1` **Path** | IT-3 | Standard install, all versions | Portable, relocated, renamed dir |
| `/v2` **Metadata** | IT-2 | Renamed and relocated binaries | Recompiled/stripped binaries |
| `/v3` **Hash** | IT-4 | Exact known builds anywhere on disk | Any version not yet harvested |
| `/v4` **Signer** | IT-1 | All vendor builds incl. unreleased | Unsigned/self-built |

Deploy `/v1` and `/v4` first — broadest coverage, lowest maintenance. `/v3` is the
harvest product and feeds RC-9.4/9.5.

Order the remainder by OS, per the IT-2 asymmetry in Part B:
- **Windows** — `/v2` next. PE `OriginalFilename` is inside the binary; it closes rename
  and relocation in one rule.
- **macOS** — `/v2` is weaker (Info.plist is strippable). Weight `/v4` signer and `/v3`
  hash instead, and treat a Mach-O with a matching Team ID outside `/Applications` as
  RC-9.5.

**Alert dedup matters.** One Claude launch fires all four. Suppress on
`(endpoint, contract_family, binary_hash)` per 24h so a single launch is one alert
carrying four corroborating variations, not four alerts.

---

# Part E — Coverage tracking

Track per platform, per OS:

```
RC-3.1  Claude Desktop exec
  win   v1 ✅  v2 ✅  v3 ⚠️ 2 of ~6 hashes  v4 ✅
  mac   v1 ✅  v2 ✅  v3 ❌ none harvested   v4 ✅
  linux — n/a
```

Report as contract coverage, never as rule count. Rule count rewards volume; contract
coverage rewards closing gaps.

---

## Related files

- `01-app-identity.yaml` — the identity dictionary (signers, metadata, paths, hashes)
- `10-sentinelone-star.md` — SentinelOne STAR implementations, labeled by contract ID
