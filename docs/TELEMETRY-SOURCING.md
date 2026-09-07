# Where detection engineers get data to write signatures against

Researched 2026-09-05. Answers: *if you do not have a customer tenant with the telemetry,
how do you develop and test signatures?*

## The headline

**There is no public SentinelOne telemetry corpus.** Every major public dataset is
Sysmon / Windows Event Log / Zeek shaped. For S1 field-level work — the exact naming of
`tgt.process.image.originalFileName`, whether `url.address` is populated — you need an
agent reporting into a console you control. There is no substitute.

What *does* exist publicly for S1 is **queries, not data**. That distinction drives
everything below.

---

## Tier 1 — Your own lab with real agents *(what nearly everyone actually does)*

The industry norm, and unglamorous: a handful of VMs with every EDR agent installed,
reporting to a console the detection team owns.

**For SentinelOne specifically: the NFR programme.** SentinelOne's *Not-for-Resale*
programme gives approved channel partners product access "for testing, internal training
and to deliver product demonstrations." As an S1 MSSP partner this is the intended route —
NFR licences, a few lab endpoints, a console you can break.

Why this is the answer for AI detection in particular: **you need no adversary simulation.**
Generating the telemetry is installing Claude Desktop and running `ollama serve`. The lab
is cheap, legal, and produces exactly the events the contract targets. Compare that to
malware detection work, where the lab is the hard part.

Egress options once you have it — the user side can take any of them:

| Path | Shape | Note |
|---|---|---|
| Console DV query bar | Interactive | Zero setup, authoritative, per-tenant |
| Cloud Funnel → S3/GCS | Streamed objects | Paid add-on, see [CLOUD-FUNNEL-ONBOARDING](CLOUD-FUNNEL-ONBOARDING.md) |
| **Kafka** | Stream | S1 provisions a Kafka instance with the DV feature set — worth asking about, it may avoid the S3 detour |
| DV query API | Pull | Rate-limited; fine for T2 sampling |

## Tier 2 — Generate the activity

- **Just install the apps.** For this contract that is the whole technique library.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — technique execution
  for the parts of the contract that overlap real tradecraft (RC-02.05 portable execution,
  RC-09.05 relocated binary)
- BAS platforms (AttackIQ, SafeBreach, Picus) if the budget already exists — overkill here

## Tier 3 — Public datasets *(limited value for S1)*

| Dataset | Shape | Use for us |
|---|---|---|
| [OTRF Security-Datasets / Mordor](https://github.com/OTRF/Security-Datasets) | Sysmon + Windows Event Log JSON, ATT&CK-mapped, includes benign background events | The Sysmon arm of the contract; **not** S1 |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Raw EVTX | Sysmon arm |
| [Splunk attack_data](https://github.com/splunk/attack_data) | Multi-source | Sysmon arm |

These are genuinely good, and genuinely not SentinelOne. Use them when the contract ports
to Sysmon/Defender ([ADR-0001](ECOSYSTEM.md)), not for S1 field verification.

## Tier 4 — Query corpora as schema proxies

The workaround that got us this far. Published queries encode correct field usage even
without the underlying data:

- **[SentineLabs/S1QL-Queries](https://github.com/SentineLabs/S1QL-Queries)** — curated by
  **SentinelOne Research**. First-party field usage, freely readable. The best available
  proxy for the authoring surface when the schema reference is paywalled.
- [keyboardcrunch/sentinelone-queries](https://github.com/keyboardcrunch/sentinelone-queries) — DV queries by OS
- [ilyess-sellami/SentinelOne-Malware-Hunting](https://github.com/ilyess-sellami/SentinelOne-Malware-Hunting) — ATT&CK-mapped hunts
- Third-party integrator schemas (Panther, Sekoia, Google SecOps, Exabeam) — how
  [FIELD-VERIFICATION](FIELD-VERIFICATION.md) resolved IT-2 and TP-URL

**Limit:** these prove a field *exists*. They cannot tell you whether it is *populated* in
your environment, at your agent version, for the event types you care about. That is a
T1/T2 question and it needs real data.

## Tier 5 — Synthesise and replay into Fluency

Fluency's own replay tooling (`prepare_replay_hec_flow_script`, `ensure_replay_hec_flow`,
`start_replay`, `replay_tenant_window`, `create_scenario_from_event_search_url`) accepts
constructed events over HEC.

So: build DV 2.0-shaped JSON from the documented schema, push it into a test tenant, and
develop the Fluency-side correlation and regression scenarios against it.

**Be clear about what this does and does not prove.** It validates *your* logic and gives
you repeatable regression fixtures. It proves nothing about whether the S1 console accepts
your query syntax, or whether real agents populate those fields. Synthetic data tests the
rule; only real data tests the assumption.

---

## Recommended for this project

1. **NFR lab.** Two VMs (Windows 11, macOS), S1 agent, install the apps in
   `identity/apps.yaml`. Unblocks T1 syntax, T3 detonation, and all four identity tiers at
   once — including the `originalFileName` and `url.address` population questions that
   documentation cannot settle.
2. **Ask S1 about Kafka.** If DV can stream to Kafka rather than S3, Fluency ingest gets
   simpler and the Cloud Funnel S3 detour may be avoidable. Worth one question to the rep.
3. **Mine the existing Alerts feed for what it *does* carry.** `@s1.sourceprocesssha256`
   + `@s1.sourceprocessfilesigneridentity` are enough to run the RC-09.04 harvest **today**,
   with no new licensing. That seeds `identity/hashes/` and unblocks four rules.
4. **Read [S1QL-Queries](https://github.com/SentineLabs/S1QL-Queries) before authoring more.**
   First-party field usage will catch naming mistakes faster than any doc — it already
   would have caught `tgt.file.internalName`.

**Do not block the programme on Cloud Funnel.** Point 3 needs nothing new. Points 1 and 2
are cheap. Cloud Funnel is the scale-up, not the entry ticket.
