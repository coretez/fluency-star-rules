# SentinelOne STAR — Endpoint Rules

Implements `00-RULE-CONTRACT.md` families RC-1 to RC-7 and RC-9.4/9.5/9.6.
Network families are in `11-sentinelone-network.md`.

**Rule naming in the console — copy exactly:** `RC-3.1/v2 — Claude Desktop exec (metadata)`
**All rules: Alert only.** No kill/quarantine. Severity per contract.

### Field verification before you deploy

Three fields carry the hash/metadata strategy. Confirm each returns data in a DV query
before building on it — schema differs across agent versions:

| Purpose | Field used below | If it doesn't exist |
|---|---|---|
| Process image SHA-256 | `tgt.process.image.sha256` | Try `tgt.process.image.sha1`; drop to file-event hashing at install |
| Code signer | `tgt.process.publisher` | Try `tgt.process.signedStatus` + cert subject fields |
| PE OriginalFilename | `tgt.file.internalName` | **See RC-3.1/v2 note — this is the likely gap** |

---

## RC-2.1 — AI installer executed (Windows)

```
event.type = "Process Creation"
AND endpoint.os = "windows"
AND (
  tgt.process.image.path in contains anycase (
    "Claude-Setup", "AnthropicClaude", "ChatGPT-Setup", "ChatGPTSetup",
    "OllamaSetup", "LM-Studio", "LMStudio", "CursorUserSetup", "CursorSetup",
    "gpt4all-installer", "jan-win", "msty-setup", "Perplexity-Setup", "Comet-Setup"
  )
  OR src.process.cmdline in contains anycase (
    "Claude-Setup", "OllamaSetup", "CursorUserSetup", "gpt4all-installer"
  )
)
```

## RC-2.2 — AI app bundle written to /Applications (macOS)

```
event.type = "File Creation"
AND endpoint.os = "osx"
AND tgt.file.path in contains anycase (
  "/Applications/Claude.app/", "/Applications/ChatGPT.app/",
  "/Applications/Ollama.app/", "/Applications/LM Studio.app/",
  "/Applications/Cursor.app/", "/Applications/Comet.app/",
  "/Applications/gpt4all.app/", "/Applications/Msty.app/"
)
AND tgt.file.path contains anycase "Contents/Info.plist"
```

The `Info.plist` clause collapses a several-thousand-file bundle copy to ~1 event.
Without it this rule is unusable.

## RC-2.5 — Portable AI binary from user-writable path — **HIGH**

Install-evasion by construction: AI binary running from Downloads/Temp/Desktop/USB.

```
event.type = "Process Creation"
AND tgt.process.image.path in contains anycase (
  "\\Downloads\\", "\\Temp\\", "\\Desktop\\", "\\Public\\", "\\AppData\\Local\\Temp\\",
  "/Downloads/", "/tmp/", "/Volumes/", "/private/tmp/"
)
AND (
  tgt.process.name in anycase ("claude.exe","ChatGPT.exe","ollama.exe","Cursor.exe","gpt4all.exe","Comet.exe")
  OR tgt.process.image.path in contains anycase ("ollama","llama-server","llamafile","koboldcpp","lm studio")
)
```

---

# RC-3.1 — Claude Desktop execution — the four variations

The worked example. Every other RC-3.x/RC-5.x item follows this shape.

## RC-3.1/v1 — Path (IT-3)

Standard install, all versions. Blind to portable/relocated/renamed-directory.

```
event.type = "Process Creation"
AND (
  tgt.process.image.path contains anycase "\\AnthropicClaude\\claude.exe"
  OR tgt.process.image.path contains anycase "/Applications/Claude.app/Contents/MacOS/Claude"
)
AND NOT tgt.process.image.path contains anycase "Helper"
```

`NOT ... Helper` suppresses Electron GPU/Renderer children — 4-8 duplicates per launch.

## RC-3.1/v2 — Embedded metadata (IT-2) — **the rename killer**

Catches `claude.exe` renamed to anything. PE version resource travels inside the binary.

```
event.type = "Process Creation"
AND endpoint.os = "windows"
AND tgt.file.internalName in anycase ("claude.exe", "claude")
AND NOT tgt.process.image.path contains anycase "\\AnthropicClaude\\"
```

The `NOT` clause makes this fire **only on the anomaly** — right name, wrong place.
Standard installs are already covered by /v1, so this rule stays quiet until someone
renames or relocates. That is the point.

> **Verify first.** `tgt.file.internalName` is documented on File events; whether S1
> exposes PE OriginalFilename on **Process Creation** varies by agent version. If it
> does not, implement /v2 as a `File Creation` rule at install/write time instead —
> you catch the binary landing rather than running. Falcon, Sysmon (EID 1
> `OriginalFileName`) and Defender all expose it at process creation, so this
> variation ports cleanly even if S1 can't host it.

**macOS note:** `Info.plist` is a sibling file, not embedded — extract the inner Mach-O
and this metadata is gone. On macOS lean on /v4 instead (contract Part B).

## RC-3.1/v3 — Hash (IT-4)

Exact known builds anywhere on disk, under any filename. Populate from
`01-app-identity.yaml` → `apps[claude-desktop].*.sha256` after harvesting.

```
event.type = "Process Creation"
AND tgt.process.image.sha256 in (
  "<claude-win-hash-1>",
  "<claude-win-hash-2>",
  "<claude-mac-hash-1>"
)
```

Breaks on every Squirrel auto-update. Kept alive by the RC-9.4 harvest loop, and its
real payoff is RC-9.5 below.

## RC-3.1/v4 — Signer (IT-1)

Broadest and most durable. Catches versions you have never seen, including builds
released after this rule was written.

```
event.type = "Process Creation"
AND tgt.process.publisher contains anycase "Anthropic"
AND NOT tgt.process.image.path contains anycase "Helper"
```

**Deploy /v1 + /v4 first on Windows; /v4 + /v3 first on macOS.**
Dedup on `(endpoint, RC-3.1, sha256)` per 24h — one launch fires all four.

---

## RC-3.2 — ChatGPT Desktop (same four variations)

```
# /v1 path
event.type = "Process Creation"
AND (tgt.process.image.path contains anycase "\\Programs\\ChatGPT\\ChatGPT.exe"
     OR tgt.process.image.path contains anycase "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"
     OR tgt.process.image.path contains anycase "\\WindowsApps\\OpenAI.ChatGPT")
AND NOT tgt.process.image.path contains anycase "Helper"

# /v2 metadata
event.type = "Process Creation" AND endpoint.os = "windows"
AND tgt.file.internalName in anycase ("ChatGPT.exe","ChatGPT")
AND NOT tgt.process.image.path contains anycase "\\Programs\\ChatGPT\\"

# /v4 signer
event.type = "Process Creation"
AND tgt.process.publisher contains anycase "OpenAI"
AND NOT tgt.process.image.path contains anycase "Helper"
```

## RC-3.4 — AI-native IDE — **MEDIUM/HIGH**

Higher risk than a chat client: reads and transmits source code.

```
event.type = "Process Creation"
AND (
  tgt.process.image.path in contains anycase (
    "\\Programs\\cursor\\Cursor.exe", "/Applications/Cursor.app/Contents/MacOS/Cursor",
    "\\Windsurf\\Windsurf.exe", "/Applications/Windsurf.app/",
    "/Applications/Zed.app/Contents/MacOS/zed"
  )
  OR tgt.process.publisher in contains anycase ("Anysphere", "Exafunction", "Codeium")
)
AND NOT tgt.process.image.path contains anycase "Helper"
```

## RC-3.6 — Unsigned binary carrying AI metadata — **HIGH**

Impostor or tampered build. Not shadow AI — treat as malware triage.

```
event.type = "Process Creation"
AND endpoint.os = "windows"
AND tgt.file.internalName in contains anycase ("claude","chatgpt","ollama","cursor","copilot")
AND tgt.process.signedStatus != "signed"
```

---

## RC-5.1 / 5.2 — Local inference runtime executed & serving

```
event.type = "Process Creation"
AND (
  tgt.process.cmdline in contains anycase (
    "ollama serve", "ollama run", "llama-server", "lms server start",
    "--host 0.0.0.0", "text-generation-webui", "vllm serve"
  )
  OR tgt.process.image.path in contains anycase (
    "\\Programs\\Ollama\\ollama.exe", "/usr/local/bin/ollama",
    "llama.cpp", "llamafile", "koboldcpp"
  )
)
```

## RC-5.3 — Inference API exposed off-host — **HIGH**

Unauthenticated LLM API reachable from the LAN. The one local-AI finding that is a
genuine security issue rather than a policy one.

```
event.type = "IP Connect"
AND event.network.direction = "INCOMING"
AND dst.port.number in (11434, 1234, 8080, 5000, 7860, 8000)
AND src.process.name in contains anycase ("ollama","lm studio","llama-server","python")
AND NOT src.ip.address in ("127.0.0.1", "::1")
```

## RC-5.4 — Model weights written to disk

```
event.type = "File Creation"
AND tgt.file.path in contains anycase (".gguf", ".safetensors", ".ggml", ".pth")
```

Add a size floor if your console supports it — real weights are >1GB.

---

## RC-6.1 / 6.2 — AI SDK install & coding CLI execution

```
event.type = "Process Creation"
AND (
  tgt.process.cmdline in contains anycase (
    "@anthropic-ai/claude-code", "@openai/codex", "aider-chat",
    "pip install openai", "pip install anthropic", "pip install litellm",
    "pip3 install openai", "pip3 install anthropic",
    "npm install openai", "npm install @anthropic-ai/sdk",
    "brew install ollama", "ollama.com/install.sh", "gh copilot"
  )
  OR tgt.process.name in anycase ("aider", "codex", "ollama", "llm")
)
```

Known FP source: `tgt.process.name = "claude"` and `"llm"` collide with unrelated
binaries. Excluded here deliberately — cover Claude Code via cmdline instead.

## RC-6.5 — AI API key written to disk — **HIGH**

Programmatic use plus a credential-hygiene finding in one.

```
event.type = "Process Creation"
AND tgt.process.cmdline in contains anycase (
  "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY",
  "GEMINI_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY", "sk-ant-"
)
```

## RC-7.3 — AI-native browser — **HIGH**

Agentic: acts on the user's behalf, so far wider blast radius than a chat window.

```
event.type = "Process Creation"
AND (
  tgt.process.image.path in contains anycase (
    "\\Perplexity\\Comet\\Application\\Comet.exe",
    "/Applications/Comet.app/", "/Applications/Dia.app/"
  )
  OR tgt.process.publisher in contains anycase ("Perplexity")
)
AND NOT tgt.process.image.path contains anycase "Helper"
```

---

# RC-9.4 / 9.5 / 9.6 — the rules the dictionary exists for

## RC-9.4 — Hash drift (inventory maintenance, not an alert)

Known signer, known metadata, **unknown hash** → new version shipped. Severity Low,
routed to a harvest queue, not to analysts.

```
event.type = "Process Creation"
AND tgt.process.publisher in contains anycase ("Anthropic","OpenAI","Anysphere","Ollama","Perplexity")
AND NOT tgt.process.image.sha256 in (
  "<all-known-hashes-from-01-app-identity.yaml>"
)
AND NOT tgt.process.image.path contains anycase "Helper"
```

Output feeds step 4 of the harvest loop in `01-app-identity.yaml`. Signer match is the
guardrail — never auto-append a hash on filename alone.

## RC-9.5 — Relocated known binary — **HIGH**

**This is the payoff for maintaining hashes at all.** Known-good SHA-256 running from
an unexpected path: someone copied or renamed a known AI binary. Unlike everything else
in this pack, this is not policy noise — it is deliberate evasion.

```
event.type = "Process Creation"
AND tgt.process.image.sha256 in (
  "<all-known-hashes-from-01-app-identity.yaml>"
)
AND NOT tgt.process.image.path in contains anycase (
  "\\AppData\\Local\\AnthropicClaude\\",
  "\\AppData\\Local\\Programs\\ChatGPT\\",
  "\\AppData\\Local\\Programs\\Ollama\\",
  "\\AppData\\Local\\Programs\\cursor\\",
  "/Applications/"
)
```

Hash-only inventory tells you what is installed. This turns the same dictionary into a
detection: identity confirmed, location wrong.

## RC-9.6 — Renamed binary — **HIGH**

Metadata says one thing, filename says another.

```
event.type = "Process Creation"
AND endpoint.os = "windows"
AND tgt.file.internalName in contains anycase ("claude","chatgpt","ollama","cursor","comet")
AND NOT tgt.process.name in contains anycase ("claude","chatgpt","ollama","cursor","comet")
```

Same `tgt.file.internalName` caveat as RC-3.1/v2 — verify availability on Process
Creation events, else port to Sysmon/Falcon/Defender where it is guaranteed.

---

## Deployment order

| Wave | Rules | Why |
|---|---|---|
| 1 | RC-2.1, RC-2.2, RC-3.1/v1, RC-3.1/v4, RC-5.1 | Low volume, high signal, builds the inventory |
| 2 | RC-9.4 harvest → populate `sha256` in the YAML | Nothing downstream works until the dictionary is seeded |
| 3 | RC-3.1/v3, RC-9.5, RC-9.6, RC-2.5, RC-3.6 | The evasion detections — need wave 2 first |
| 4 | RC-6.x, RC-7.x, RC-5.3 | Developer and browser surface |
| 5 | `11-sentinelone-network.md` (RC-8, RC-9.1/9.2) | Highest volume, needs DoH policy fixed first |

**Wave 2 is a hard gate.** RC-3.1/v3, RC-9.5 and RC-9.6 all reference hash lists that
are empty until you harvest. Deploying them before wave 2 gives you rules that match
nothing and a dashboard that looks clean.
