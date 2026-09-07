# Ecosystem survey — who else publishes AI detection rules

Researched 2026-09-05. Re-check quarterly; this space is moving fast.

## Public rule corpora

| Corpus | Size / license | Shadow-AI content |
|---|---|---|
| [acquiredsecurity/Sentinel-One-STAR-Rules](https://github.com/acquiredsecurity/Sentinel-One-STAR-Rules-Threat-Hunts) | 78★ | **None** — tradecraft, ransomware, APT |
| [dannyroemhild/sentinelone-star-queries](https://github.com/dannyroemhild/sentinelone-star-queries) | 9★, GPL-3.0 | **None** — Nitrokod, downloads, process exec |
| [Sentinel-One/ai-siem](https://github.com/Sentinel-One/ai-siem) (official) | 165 parsers, 79 dashboards, 8 detections, AGPL-3.0 | **None** — AI *for* SIEM, not detecting AI |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) mainline | large, DRL | **None found** for shadow-AI discovery |
| [agentshield-ai/sigma-ai](https://github.com/agentshield-ai/sigma-ai) | Apache-2.0 | **Adjacent, not overlapping** — attacks *against* agents (prompt injection, tool poisoning, context exfil). Logsource `product: ai_agent`, not endpoint telemetry |
| Defender KQL repos ([SlimKQL](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules), [Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)) | active | **Copilot abuse only** — first-party, not third-party shadow AI |

**Conclusion: no public shadow-AI STAR corpus exists.** Nothing to fork or align to. This
repo is not duplicating published work.

---

## ADR-0001 — Sigma is a partial interchange format, not the source of truth

**Status:** accepted · 2026-09-05

### Context

A [pySigma SentinelOne backend](https://github.com/7RedViolin/pySigma-backend-sentinelone)
exists (MIT, maintained by Cori Smith, [announced by SigmaHQ](https://blog.sigmahq.io/community-contribution-highlights-sentinelone-joins-pysigma-cedd8825e063)),
and [Uncoder IO](https://github.com/UncoderIO/Uncoder_IO) translates Sigma → S1QL. If Sigma
were a complete interchange, we could author once and emit to S1, Defender and Falcon.

### Finding — the backend does not map our two most durable identity tiers

Field mappings confirmed from `sigma/pipelines/sentinelone/sentinelone.py` (branch `master`):

| Sigma field | S1 field | Tier | Status |
|---|---|---|---|
| `Image` | `TgtProcImagePath` | IT-3 | ✅ |
| `CommandLine` | `TgtProcCmdLine` | — | ✅ |
| `sha256` | `TgtProcSha256` | **IT-4** | ✅ |
| `ParentImage` | `SrcProcImagePath` | — | ✅ |
| `TargetFilename` | `TgtFilePath` | IT-3 | ✅ |
| `QueryName` | `DnsRequest` | — | ✅ |
| `DestinationIp` / `DestinationPort` | `DstIP` / `DstPort` | — | ✅ |
| `OriginalFileName` | — | **IT-2** | ❌ **not mapped** |
| `Signature` / `Signed` / `Publisher` | — | **IT-1** | ❌ **not mapped** |

Supported categories: `process_creation`, `file_event`/`change`/`rename`/`delete`,
`image_load`, `pipe_creation`, `registry_*`, `dns_query`, `network_connection`, `firewall`.
Unsupported fields throw errors rather than degrading.

**IT-1 (signer) and IT-2 (metadata) are the backbone of our identity strategy** — the only
tiers that survive a version update, and on macOS the only one that survives extraction
from the bundle. Neither can be emitted through the standard backend.

Also note the pipeline emits **legacy DV field names** (`TgtProcImagePath`), not the
unified dotted schema (`tgt.process.image.path`). Verify which your consoles accept.

### Decision

1. **Native platform rules remain the source of truth.** `rules/<platform>/` stays authoritative.
2. **Sigma is an emission target for the tiers it supports** — IT-3 (path), IT-4 (hash),
   DNS and network. That is ~60% of our rules and gets Defender/Falcon nearly free.
3. **IT-1 and IT-2 variations are hand-authored per platform.** Defender
   (`ProcessVersionInfoOriginalFileName`, signer fields) and Falcon (`OriginalFilename`)
   both expose them natively — only the Sigma path is blocked, not the platforms.
4. **Consider contributing the two mappings upstream.** MIT, single maintainer, small
   diff. It would close the gap for everyone and is a cheap, visible community contribution.

### Consequence

`tools/emit.py` (unwritten) must refuse to emit any rule whose `identity_tier` is IT-1 or
IT-2 rather than silently dropping the clause — a Sigma rule that quietly loses its signer
condition is worse than no rule, because it matches far more than intended.

---

## Vendor-native capability — the important one

### Microsoft Defender — local AI agent discovery (Preview)

Microsoft ships **native local AI agent discovery** in Defender for Endpoint Plan 2:

- **`AgentsInfo`** Advanced Hunting table (preview) — publisher, process, trust setting,
  auto-approve value, MCP configuration, device, account
- **20+ supported local AI agents** across Windows and macOS
- Covers AI coding agents, AI assistants, **local AI runtimes**, agentic IDE extensions,
  and **MCP servers** (incl. Ollama Desktop, OpenClaw, Nanobot, ZeroClaw)
- Local *and remote* MCP server configuration discovery

Docs: [discover-local-ai-agents](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents) ·
[overview](https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview) ·
[macOS hunting](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/hunting-local-ai-tools-on-macos-with-microsoft-defender-for-endpoint/4536965)

**This natively implements RC-03, RC-05, RC-06.03 and RC-06.04.**

> **When this repo reaches Defender: do NOT port those families.** Query `AgentsInfo`
> instead and map its output back to the contract IDs. Porting them would rebuild, worse,
> something the platform already does. Port RC-08/RC-09 (network + evasion), where
> `AgentsInfo` gives nothing — and RC-09.05 (relocated known binary), which an inventory
> table structurally cannot express.

### SentinelOne — the AI security portfolio

Re-surveyed 2026-09-07, including the RSAC 2026 announcements.

| Product | Scope | Relevant to this contract |
|---|---|---|
| **Prompt Security** | The AI discovery + governance product. Acquired 2025, built into Singularity | **RC-08, RC-11** |
| ├ AI Usage Control | Discovers/inventories employee AI tool usage in real time; 15,000+ AI services; enforces acceptable-use with selective data redaction | RC-08, **RC-11** |
| ├ Agentic AI Security | Maps and secures autonomous agents; **shadow MCP server discovery**; least-privilege agent access | RC-06.04 (partial) |
| └ AI Application Security | Protects homegrown GenAI apps; runtime "AI firewall" | — |
| **AI-SPM** | AI Security Posture Management — inventory + assessment across training pipelines, inference endpoints, managed AI services | — (cloud, not endpoint) |
| **DSPM** | Data layer — classifies sensitive data, stops high-risk datasets feeding AI | — |

**Naming — verified 2026-09-07.** Still **"Prompt Security"**, with no `Singularity`
prefix. SentinelOne's own page carries the line *"Prompt Security, a SentinelOne company"*
— it is kept as a distinct product line, not folded into Singularity branding. The SKU
reads "Prompt Security for Employees". They are **extending** the brand rather than
retiring it: the RSAC 2026 additions are named *Prompt AI Agent Security* and *Prompt AI
Red Teaming*. Related line items on the same page: "Prompt for Homegrown AI Apps",
"Agentic AI Security".

**Announced RSAC 2026 (23 March 2026):** Prompt AI Agent Security (agent/MCP discovery and
governance), Prompt AI Red Teaming (preview), Purple AI Auto Investigation (GA), AI Data
Pipelines in Singularity AI SIEM.

### The boundary — confirmed across three sources

**None of it does endpoint discovery of locally installed AI applications or local model
runtimes.** Checked the [Prompt Security page](https://www.sentinelone.com/platform/securing-ai-prompt/),
the [AI Security Platform page](https://www.sentinelone.com/platform/securing-ai/), and the
[RSAC 2026 announcement](https://www.sentinelone.com/press/sentinelone-unveils-new-ai-security-offerings-to-give-defenders-a-decisive-advantage/).
No mention of Ollama, LM Studio, desktop AI apps, or agent-based endpoint AI inventory in
any of them.

Prompt Security operates at the **prompt / SaaS / API layer**. It governs what is sent to
an AI service. It does not tell you `ollama.exe` is running from `D:\tools\`.

**Licensing:** separately licensed, per employee. Not in the public platform packages;
resellers list orderable SKUs ("Prompt Security for Employees").

### Contrast with Microsoft

Defender ships **endpoint** local AI agent discovery — the `AgentsInfo` table, 20+ agents
across Windows and macOS, including Ollama Desktop. SentinelOne does not have an
equivalent. **The endpoint gap this repo fills is real on S1 and closing on Defender.**

### Strategic read

The two vendors are building in **different halves**, and neither has closed both:

```
                    endpoint (installed apps, local runtimes)   prompt/SaaS layer
  SentinelOne       ✗  ← this repo                              ✓  Prompt Security
  Microsoft         ✓  AgentsInfo (preview)                     partial (Purview)
```

**On SentinelOne the endpoint half is not on the roadmap we can see**, which makes
RC-02/03/05/09 a durable build rather than a bridge. On Defender it is already shipping,
so those families should not be ported there ([above](#microsoft-defender--local-ai-agent-discovery-preview)).

**Joint-sell framing:** a tenant running Prompt Security *plus* these rules has both halves
— Prompt Security answers "who sent what to which model" (RC-08, RC-11, incl. the personal-
vs-corporate-account gap EDR structurally cannot close), and these rules answer "what is
installed and running, and is it where it should be." Neither substitutes for the other.

What stays durable regardless of vendor moves:

- the **contract** — vendor-neutral requirements
- the **identity dictionary** — signers, metadata, hashes
- **RC-09.05** — relocated known binary. An inventory table lists what is installed;
  it cannot tell you a known-good binary is running from the wrong path. That is the one
  detection no vendor inventory replaces.
