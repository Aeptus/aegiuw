# Aegiuw build roadmap

Bottom-to-top phased build plan. Each layer is a coherent unit of work with the decisions from [`DECISIONS.md`](./DECISIONS.md) baked in. Layers below must be solid before layers above ride on them.

> **Status snapshot (2026-05-28):** Layer 0 complete. Layers 1–10 outlined with concrete "done" criteria.

---

## Layer 0 — Foundations ✅ complete

Monorepo, Cargo workspace, Worker scaffold, CI (Rust + Worker), **AGPL-3.0-or-later** license, README, PRD, decision register, and the full `aegis-*` → `aegiuw-*` rename.

**Done:** `cargo test`, `cargo clippy -D warnings`, and `tsc --noEmit` all green.

---

## Layer 1 — Navigation capture (the bottom: "identification of link clicks")

**Goal:** detect an outbound web navigation and identify its target.

**Components:**
- macOS Network Extension (`NEAppProxyProvider`) — first platform per **B9**.
- `aegiuw-core::sni` — bounds-checked TLS ClientHello parser.
- `aegiuw-core::quic_initial` — QUIC Initial-packet SNI parser (per **C15**).
- Optional WebExtension (Chrome / Firefox / Safari) that supplies the exact URL + opener context (per **C13** / **C16**).
- HTTP/80 host extraction (per **C18**).

**Decisions baked in:**
- Opaque-TCP fork + WebExtension URL-assist; no local CA (**C13**).
- ECH-unreadable connections → isolate by default (**C14**).
- Intercept both TCP and UDP 443 (**C15**).
- Top-level navigations only; subresources ignored (**C17**).
- FR-2.3 PPID detection deprioritized; WebExtension supplies launch context (**C16**).

**Done:** the daemon observes a real Chrome/Safari/Firefox navigation and emits `{host, scheme, protocol, source(extension|tcp|quic), launch_context_if_known}` for both TLS and QUIC connections.

---

## Layer 2 — Local risk engine 🟡 partly scaffolded

**Goal:** decide Native-vs-Isolate locally, in microseconds, with no API call.

**Components:**
- `allowed_cache.json` — ed25519-signed, monotonically versioned, atomic-update (per **D20**).
- Tranco top-10k brand list bundled (**D21**).
- Unicode confusables + punycode fold-down before Levenshtein (**D23**).
- High-abuse-TLD list as offline newly-registered proxy (**D24**).
- `aegiuw-core::verdict` — already scaffolded; deny-by-default folding.

**Decisions baked in:**
- Threshold ≤ 2, no per-org tunability (**D22**).
- Newly-registered domain check uses edge-side RDAP cache; offline fallback = high-abuse-TLD list (**D24**).
- Fail-open with warning when edge unreachable (**D25**).

**Done:** given `{host, scheme, launch_context}`, the daemon emits a `Verdict` with the allow-cache consulted, all four heuristics combined, and the policy correctly fail-safed.

---

## Layer 3 — Fork & transport

**Goal:** act on the verdict at the network layer within the < 15 ms budget (NFR-4.1).

**Components:**
- Native path: transparent TCP splice straight to the NIC, no decryption (**E26**).
- Isolate path: marshal `{target, verdict, context}` to the edge over HTTPS POST; long-lived WebSocket per active session (**E29**).
- Browser-extension-cancel handoff for clean isolate-path UX (**E30**).
- Per-OS implementation: Network Extension / WFP / TUN (**E27**).
- Dual-stack IPv4 + IPv6 (**E28**).
- VPN coexistence + split-tunnel for localhost / RFC1918 / `.local` (**E31** / **E32**).

**Done:** safe domains pass through transparently with the < 15 ms tax met; unknown domains divert cleanly to the worker; coexists with at least one corporate VPN client without conflict.

---

## Layer 4 — Edge router

**Goal:** stateless edge controller turning isolate requests into sandbox sessions.

**Components:**
- `/isolate` endpoint (already scaffolded; currently 501 stub).
- KV reader with org-namespaced schema (**F33**).
- Region selection via `services_jurisdiction` (**F34**).
- Per-token rate limiting (**F35**).
- Daemon↔router auth: HMAC (OSS) / JWT (commercial) (**F36** / **L60**).
- `/contribute` endpoint accepting signed allow/block votes; consensus aggregation (**F37**).

**Done:** `/isolate` accepts a daemon request, validates auth, looks up org rules, allocates a sandbox, returns a connection handle.

---

## Layer 5 — Ephemeral sandbox

**Goal:** blank-profile headless Chromium that renders the untrusted target and self-destructs.

**Components:**
- Cloudflare Containers as the runtime (**G38**).
- ClamAV-bundled image for the download scrubber (**G41**).
- Lifecycle wiring: 5-min idle timeout, 30-min hard cap (**G42**).
- Teardown on viewer disconnect — vaporize container + RAM (FR-3.3).
- OSS queue for the 120-concurrent cap (**G40**).

**Done:** a URL renders in an isolated container; closing the viewer destroys the session within 2 s; per-session cost is on budget (**G43**).

---

## Layer 6 — Interactive read-only stream

**Goal:** pipe the rendered page to the local viewer at < 150 ms input-to-pixel latency.

**Components:**
- WebRTC peer connection daemon ↔ sandbox container (**H48**).
- H.264 video stream, adaptive 500 kbps–2 Mbps, 30 fps (**H45** / **H46**).
- Router acts as signaling only — no media bytes through the worker (**H48**).
- **Accessibility tree side channel** mirroring CDP `Accessibility.getFullAXTree` — the differentiator (**H49** / **J56**).
- Pointer/click input forwarded to the sandbox.

**Done:** user sees and mouses through a live page in the local viewer; a screen reader reading the side channel narrates the page contents.

---

## Layer 7 — Credential lockout

**Goal:** typing into credential fields is physically impossible in the sandbox.

**Components:**
- CDP `DOM` + `Input` instrumentation in the sandbox to detect focus on sensitive fields by `type` + `autocomplete` (**I50**).
- **Server-side keystroke relay** that drops keystrokes targeted at sensitive fields (**I51**).
- Paste/clipboard blocked across the sandbox (**I52**).
- Per-field decisions; non-sensitive fields permitted in-sandbox (**I50**).
- Blocked-typing toast UX with regular-browser escape (**I54** / **B12**).

**Done:** a fake login page renders in the sandbox; the password field is clickable but no keystrokes ever reach the DOM; a user can dismiss into the regular browser if they explicitly choose.

---

## Layer 8 — Local viewer UX

**Goal:** the desktop "protected mode" experience non-technical users see.

**Components:**
- Native webviews per OS — WKWebView / WebView2 / WebKitGTK (**J55**).
- Inline education + permanent "Why is this page protected?" explainer (**J56**).
- WCAG 2.2 AA component library.
- Local per-user audit log of every isolation decision (JSONL, exportable, never leaves the device by default) (**J56** / **M70**).
- Close-to-vaporize wiring with the sandbox (FR-3.3).

**Done:** a non-technical user can complete a full isolation interaction (link click → protected view → close) without reading any documentation, and a screen-reader user can do the same.

---

## Layer 9 — Managed threat intel (open-core seam)

**Goal:** zero-hour AitM feed with paywalled sync that degrades gracefully.

**Components:**
- Aggregated feed from OpenPhish + PhishTank (OSS); Spamhaus / Netcraft (commercial) (**K57**).
- AES-256-GCM with rotating daily keys; 10-min cron pulling delta updates; signed manifest (**K58**).
- 403 → graceful fallback to local Levenshtein (**K59** reframe: OSS-only is plenty safe).

**Done:** licensed clients get fresh intel; unlicensed clients degrade silently to local heuristics with no security loss, only marginal optimization loss.

---

## Layer 10 — Commercial / customer management (the top)

**Goal:** monetize, manage seats, enforce billing.

**Components:**
- OS-keystore device keypair (Secure Enclave / TPM / TPM2 / encrypted file) (**L60**).
- Device JWT with 60 s validity + 30 s skew tolerance (**L61**).
- Stripe per-seat subscription at $1.30/seat/month, 14-day trial, annual discount (**L62**).
- Org onboarding: server keypair → enrollment token → device cert exchange (**L63**).
- Seat enforcement: unique device-cert count; block new enrollments over cap (**L64**).
- Stripe webhook handler with sig verify + idempotency + 7-day grace (**L65**).
- Durable Object warm pool sized at `min(N, ceil(0.1 × seats))` (**L66**).
- SIEM streaming in OCSF format to Splunk / Datadog / S3 / syslog (**L68**).
- Self-hosted-commercial + fully-managed tiers (**L69**).
- Customer-managed-logging tier as enterprise privacy differentiator (**M71**).
- *(Explicitly excluded from v1: residential proxy masquerading — **L67**.)*

**Done:** a customer signs up via self-serve checkout, deploys to N devices, hits the cap, and a payment failure correctly grace-periods then deactivates within 7 days.

---

## Cross-cutting tracks (run in parallel with layers)

**T1. Rename `aegis-*` → `aegiuw-*`.** ✅ Done (commit `b13ae67`). All crates, worker, identifiers, env bindings, and prose now use `aegiuw`.

**T2. License switch to AGPL-3.0-or-later.** ✅ Done (commit `819ac3f`). Canonical AGPL-3.0 text from gnu.org installed as `LICENSE`; per-file SPDX headers added; `NOTICE` updated; workspace `license` field flipped.

**T3. Distribution & installers** — macOS .pkg, Windows .msi, Linux .deb/.rpm/AUR/Flatpak, brew tap, auto-update, MDM profiles (**N78** / **O82–O85**).

**T4. Shared types via WASM** — compile `aegiuw-core` to WASM for use in the worker (**N76**).

**T5. Test infrastructure** — ClientHello/QUIC fixtures, sandbox E2E via Playwright, cargo-fuzz on parsers (**N81**).

**T6. Privacy & compliance** — DPA template, sub-processor list, SOC 2 prep, telemetry opt-in plumbing (**M70–M74**).

---

## Suggested next implementation step

The narrowest valuable next slice that unblocks meaningful progress without depending on any of the **TBC** items is **Layer 1 — SNI parsing**. It's pure logic in `aegiuw-core::sni`, no privileges, no Cloudflare, no rename impact, no license impact. Implementing it gives the daemon the first piece of real "see the wire" capability.
