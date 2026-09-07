# SentinelOne — Network Layer (RC-8, RC-9.1/9.2, RC-10, RC-11)

Implements the network families of `00-RULE-CONTRACT.md`. Endpoint families are in `10-sentinelone-star.md`.

Part 1 catches installation and local execution. It misses the dominant case: a user
with no software installed, typing into chatgpt.com in a browser tab. This part covers
that, plus the enforcement options.

**Before you build on DNS: read section 13 (the DoH blind spot).** In a default Chrome
or Edge deployment, a meaningful share of your endpoints may not generate DNS events
for these domains at all. Design around that first or the whole layer is theatre.

## RC-8 scope — What SentinelOne sees on the network

Two separate data paths, and they have very different properties. Getting this wrong
sends you down the wrong design.

### Path 1 — Deep Visibility (what STAR rules can fire on)

| Telemetry | Event type | What you get | Limits |
|---|---|---|---|
| DNS | `DNS Resolved` / `DNS Unresolved` | Queried domain, response IPs, **originating process** | Blind when the browser uses DoH (section 13) |
| TCP/UDP | `IP Connect` | Remote IP, port, process | Destination identity lost behind CDN IPs |
| HTTP | `URL` / HTTP events | URL | Coverage varies by platform and agent version — **verify, do not assume** |

### Path 2 — Web filtering / web security module

Separate from Deep Visibility. A category-based URL filter that inspects and enforces
on web traffic in its own right.

**It does see HTTPS hostnames.** It does not need to decrypt to do so — SNI in the TLS
ClientHello is cleartext, and an endpoint network extension reads it directly. Some
deployments go further with local TLS interception, which yields full URL paths.

This is the stronger tool for browser-based AI use, and it is an **enforcement** point,
not just telemetry. Three things to confirm in your console before designing around it:

1. **Is there a Generative AI / AI Tools URL category?** If yes, use it instead of the
   hand-maintained domain lists in section 9. A vendor-maintained category tracks new
   AI services without you editing rules, and it blocks as well as alerts. This would
   be the single biggest win in this whole pack.
2. **Does its telemetry reach Deep Visibility as queryable events?** This is the crux
   and it is genuinely separate from question 1. Vendors commonly keep web-filter logs
   in their own log stream and console view, *not* in the EDR hunting schema. If the
   events don't land in DV, you can see and block AI domains in the web filter but you
   **cannot write STAR rules against them** — STAR only evaluates DV events. That
   changes where each rule in this pack has to live.
3. **Hostname only, or full URL path?** Hostname-level duplicates what DNS already
   gives you (and DNS additionally attaches the originating process). Full URL paths
   are a genuine step up and would let you distinguish, say, a ChatGPT share link from
   an interactive session.

If the answers are "yes / yes / hostname or better," then sections 9-11 should be
implemented as web filter policy rather than STAR DNS rules — the filter is not blinded
by DoH, and it can block. Keep the STAR DNS rules only for the non-browser process case
in section 10, where the originating-process field is the whole point.

## RC-8.1/8.2/8.3 — Tiered DNS policy — tier the domains, don't flat-list them

A single rule matching 30 AI domains produces one undifferentiated alert stream and
gets muted in a week. Split by what you'd actually do about it.

### Tier A — High-risk jurisdiction / data residency

Highest severity. Small list, near-zero legitimate use in most Western enterprises,
and the one your legal and compliance teams care about.

```
event.type = "DNS Resolved"
AND event.dns.request in contains anycase (
  "deepseek.com", "deepseek.ai",
  "moonshot.cn", "kimi.moonshot.cn",
  "tongyi.aliyun.com", "dashscope.aliyuncs.com",
  "yiyan.baidu.com", "wenxin.baidu.com",
  "chatglm.cn", "bigmodel.cn",
  "01.ai", "lingyiwanwu.com",
  "hunyuan.tencent.com",
  "minimaxi.com", "minimax.chat"
)
```

### Tier B — AI proxies and aggregators

These matter disproportionately: they route to arbitrary backend models, so a single
allowed domain becomes a tunnel to any provider including Tier A. Treat presence of
these as a policy-evasion signal, not ordinary shadow AI.

```
event.type = "DNS Resolved"
AND event.dns.request in contains anycase (
  "openrouter.ai", "poe.com", "together.ai", "replicate.com",
  "groq.com", "fireworks.ai", "anyscale.com", "deepinfra.com",
  "novita.ai", "hyperbolic.xyz", "targon.com", "requesty.ai",
  "litellm.ai", "helicone.ai", "portkey.ai"
)
```

### Tier C — Unsanctioned mainstream consumer AI

Your bulk volume. Scope this to groups where AI use is out of policy — finance, legal,
HR, clinical, anyone handling regulated data — rather than fleet-wide.

```
event.type = "DNS Resolved"
AND event.dns.request in contains anycase (
  "chatgpt.com", "openai.com", "oaiusercontent.com",
  "claude.ai", "anthropic.com",
  "gemini.google.com", "aistudio.google.com",
  "perplexity.ai", "grok.com", "x.ai",
  "copilot.microsoft.com",
  "mistral.ai", "chat.mistral.ai",
  "character.ai", "janitorai.com", "chub.ai"
)
AND agent.group.name in anycase ("Finance", "Legal", "HR", "Clinical")
```

### Tier D — AI browsers and agentic tools

Newer category, worth its own rule. These browse and act autonomously on the user's
behalf, so a single approval decision has much wider blast radius than a chat window.

```
event.type = "DNS Resolved"
AND event.dns.request in contains anycase (
  "comet.perplexity.ai", "dia.computer", "arc.net",
  "browser-use.com", "browserbase.com",
  "manus.im", "genspark.ai", "flowith.io",
  "multion.ai", "adept.ai", "induced.ai"
)
```

## RC-8.4 — High-signal rule — non-browser process calling an AI API

If you deploy exactly one rule from Part 2, make it this one. It strips out ordinary
web browsing and leaves scripts, agents, CI jobs, and applications programmatically
calling AI APIs — which is where bulk data movement actually happens.

```
event.type = "DNS Resolved"
AND event.dns.request in contains anycase (
  "api.anthropic.com", "api.openai.com", "api.x.ai",
  "generativelanguage.googleapis.com", "api.mistral.ai",
  "api.deepseek.com", "api.groq.com", "api.cohere.ai",
  "openrouter.ai", "api.together.xyz", "api.perplexity.ai",
  "bedrock-runtime", "openai.azure.com"
)
AND NOT src.process.name in anycase (
  "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
  "Google Chrome", "Safari", "firefox", "Microsoft Edge", "Arc"
)
```

Tighten further by excluding your sanctioned integration hosts by endpoint name or
group, so your own AI-enabled applications don't fire it.

## RC-11.1 — Sanctioned-vendor, unsanctioned-account

The uncomfortable gap: if you license Claude Enterprise or ChatGPT Enterprise,
`claude.ai` and `chatgpt.com` are allowed domains. **DNS cannot distinguish a corporate
SSO session from a personal free account on the same domain.** Same hostname, same IPs.

STAR cannot close this. The controls that can:

- **SSO/IdP enforcement** — require SAML sign-in, disable password auth on the tenant
- **SWG with tenant-restriction headers** — OpenAI and Anthropic both support enterprise
  header injection that blocks non-corporate tenants at the proxy
- **Browser enterprise policy** — profile separation, block personal-profile sign-in

Note this gap explicitly in your policy doc rather than implying STAR covers it.

## RC-8 anti-pattern — IP-based rules — don't

Tempting to add `IP Connect` rules for AI provider IP ranges. It does not work:

- Every major AI service sits behind Cloudflare, Fastly, or Azure Front Door on IP
  space shared with millions of unrelated sites — false positives are unbounded
- Those ranges rotate with no notice, so the rule silently decays to zero coverage

The one legitimate use of `IP Connect` here is section 13.

## RC-9.1/9.2 — DoH blind spot — close this first

**DNS-over-HTTPS breaks every rule in sections 9–11.** When a browser resolves domains
via its own encrypted DoH resolver, the agent's DNS provider never sees the query and
generates no `DNS Resolved` event. Chrome and Edge use DoH automatically when the
configured resolver supports it; Firefox enables it by default in many regions.

You see a TLS connection to 1.1.1.1:443 and nothing else. Your AI DNS rules go quiet
and it looks like clean results.

### Detect browsers bypassing corporate DNS

```
event.type = "IP Connect"
AND dst.port.number = 443
AND dst.ip.address in (
  "1.1.1.1", "1.0.0.1",
  "8.8.8.8", "8.8.4.4",
  "9.9.9.9", "149.112.112.112",
  "94.140.14.14", "94.140.15.15",
  "208.67.222.222", "208.67.220.220",
  "76.76.2.0", "76.76.10.0"
)
AND src.process.name in anycase (
  "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
  "Google Chrome", "Microsoft Edge", "firefox", "Safari", "Arc"
)
```

This is one of the few places IP matching is correct — public resolver IPs are stable
and unambiguous.

### Also catch DoH by hostname, where classic DNS is still used to find the resolver

```
event.type = "DNS Resolved"
AND event.dns.request in contains anycase (
  "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
  "dns.google", "dns.quad9.net", "doh.opendns.com",
  "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard.com"
)
```

### The actual fix

Detection here is a stopgap. Resolve it with policy:

- **Chrome/Edge:** set `DnsOverHttpsMode = "off"` via group policy or MDM
- **Firefox:** `network.trr.mode = 5` (explicit disable) via enterprise policy
- **Network:** block outbound 853/tcp (DoT) and public resolver IPs on 443 at the firewall

Until DoH is disabled by policy, **treat your AI DNS coverage as partial and say so
when you report on it.** A clean dashboard with DoH enabled is a false negative, not
a result.

## Enforcement — Firewall Control

Detection tells you it happened. If the goal is prevention, SentinelOne's Firewall
Control module is the lever, applied per-group.

Two caveats before you plan around it:

1. **Confirm domain/FQDN rule support in your agent version.** Firewall Control has
   historically been strongest on process, protocol, port, direction, and IP/CIDR.
   Domain-based rules are the thing to verify in your console before designing a
   policy that depends on them — and section 12 explains why the IP fallback fails
   for CDN-fronted AI services.
2. **Process-based blocking works well and is version-independent.** Blocking outbound
   for `ollama.exe`, `claude.exe`, `ChatGPT.exe`, `Cursor.exe` is reliable and needs no
   domain support. It won't touch browser-based use.

Realistic split of responsibility:

| Control point | Blocks | Doesn't block |
|---|---|---|
| S1 Firewall Control (process) | Desktop AI apps, local runtimes, CLI tools | Anything in a browser tab |
| S1 Web Filtering (URL category) | Browser AI use, by category or domain | Personal accounts on sanctioned domains; prompt content |
| S1 STAR (Part 1) | Nothing — detection only | — |
| SWG / CASB | All of the above, plus prompt inspection and tenant restriction | Off-network endpoints without an agent |
| Browser enterprise policy | Extensions, personal profiles, DoH | Non-managed browsers |

**SentinelOne covers more of this than an EDR-only mental model suggests** — endpoint
install/execute via STAR, and browser AI use via the web filtering module. What it does
not do is prompt-level content inspection: which customer records were pasted, whether
source code left. That half needs a SWG/CASB with content policy. Position it that way to stakeholders up front, or
you will be asked six months from now why the EDR "didn't catch" someone pasting a
customer list into a chat window.

## RC-10 — Correlation — where this gets genuinely useful

Individually these are noisy. The signal is in combinations, and **STAR cannot express
them** — it evaluates single events with no aggregation or cross-event joins.

Combinations worth building in a SIEM, not in STAR:

- AI API DNS from a non-browser process, **within N minutes of** bulk file reads from
  a source repo or file share → likely code/data exfiltration to an LLM
- First-ever AI domain resolution from an endpoint in a restricted group → onboarding
  a new shadow AI user, worth a one-time conversation
- DoH bypass detected **and** AI domain resolution absent → coverage gap, not clean
- Tier B proxy domain **after** a Tier A block → deliberate policy evasion, escalate
- Same user, AI domains across 3+ endpoints → account-level pattern, not device-level

Export the S1 Deep Visibility events for these domains and event types into your SIEM
and write the correlation there. That is the layer where DNS telemetry stops being a
noisy feed and becomes an actual shadow-AI program.
