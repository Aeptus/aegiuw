# Aegiuw

> Remote Browser Isolation that forks at the edge of your network.

Aegiuw protects users from phishing and Adversary-in-the-Middle (AitM) attacks by
making a single decision on every outbound HTTPS connection: **is this domain
trusted?**

- **Trusted** → the connection is bridged straight to the network card. The native
  browser connects normally, with a latency tax of `<15ms` (NFR-4.1).
- **Unknown / suspicious** → the connection is intercepted and the page is rendered
  in a disposable, headless cloud browser. Only the rendered output is streamed back
  to a read-only local viewer. Credentials physically cannot reach the attacker,
  because typing into password fields is severed inside the sandbox (FR-3.2).

This is the well-established **Remote Browser Isolation (RBI)** pattern, with two
distinguishing pieces: a local SNI-based traffic *fork* and a *keyboard-disconnect*
on credential-harvesting forms.

---

## Status

🚧 **Early scaffold.** The repository structure, build systems, and component
boundaries are in place. Core logic is stubbed with clear `TODO`s tied to PRD
requirement IDs (e.g. `FR-2.1`). See [`docs/PRD.md`](docs/PRD.md) for the full
product spec.

## Architecture

Three layers, deliberately decoupled:

| Layer | Component | Stack | Lives in |
|-------|-----------|-------|----------|
| 1. Local agent | `aegis-daemon` | Native Rust (Win/macOS/Linux) | `crates/aegis-daemon` |
| — risk logic | `aegis-core` | Pure Rust (lib, WASM-friendly) | `crates/aegis-core` |
| 2. Edge router | `aegis-router` | TypeScript on Cloudflare Workers | `workers/aegis-router` |
| 3. Sandbox | `aegis-cage` | Cloudflare Browser Rendering | (driven by the router) |

```
 native browser ──► aegis-daemon ──┬─(trusted)──► NIC ──► internet
 (port 443 via TUN)                │
                                   └─(unknown)──► aegis-router (Worker)
                                                      └──► ephemeral sandbox
                                                              └─► read-only stream ──► local viewer
```

## Repository layout

```
.
├── crates/
│   ├── aegis-core/     # pure risk heuristics: Levenshtein, context, SNI parsing, verdicts
│   └── aegis-daemon/   # privileged background agent (TUN, fork logic) — depends on aegis-core
├── workers/
│   └── aegis-router/   # Cloudflare Worker: stateless traffic controller + sandbox orchestration
├── docs/
│   └── PRD.md          # product requirements (source of the FR-/CR-/NFR- IDs referenced in code)
└── .github/workflows/  # CI for both the Rust and Worker stacks
```

## Quickstart

### Local agent (Rust)

```bash
cargo build            # build the workspace
cargo test             # run aegis-core unit tests
cargo run -p aegis-daemon
```

### Edge router (Cloudflare Worker)

```bash
cd workers/aegis-router
npm install
npm run typecheck      # tsc --noEmit
npm run dev            # local Worker via wrangler

# To deploy you must first create the bound resources and paste their IDs
# into wrangler.jsonc (see the comments in that file):
#   npx wrangler kv namespace create LOCAL_SAFE_CACHE
#   npx wrangler r2 bucket create aegis-quarantine-vault
npm run deploy         # wrangler deploy  (FR-1.1: single-command edge deploy)
```

## Known caveats (truth-in-labeling)

These are real-world constraints the PRD's prose glosses over; they shape the
implementation, not whether it's possible.

- **Encrypted ClientHello (ECH):** SNI extraction (FR-1) silently fails when a
  connection uses ECH, which encrypts the server name. Such connections fall back
  to the isolate path or a separate policy — they cannot be classified by SNI.
- **"`<1ms`" verification:** the sub-millisecond figure (CR-1.1) is the in-isolate
  `crypto.subtle.verify` time only. Wall-clock latency for the daemon includes the
  network round trip to the edge (tens of ms).
- **Sandbox streaming:** Cloudflare Browser Rendering exposes Puppeteer/CDP +
  screencast, not a turnkey "KasmVNC vector pipeline." FR-3.1's stream is a
  screencast-over-WebSocket that this project builds on top of CDP.
- **Residential proxy masquerading (CR-2.2):** commercial-only, and requires legal /
  Terms-of-Service review before shipping — routing traffic through residential
  proxies to defeat bot detection commonly violates provider terms.

## Licensing

The **Core Engine** (`crates/`, `workers/aegis-router/`) is licensed under
[Apache 2.0](LICENSE). The **Aegis-Enterprise** commercial layer (billing, warm
pools, managed threat intel, SIEM streaming) is distributed under separate
commercial terms. See [`NOTICE`](NOTICE).
