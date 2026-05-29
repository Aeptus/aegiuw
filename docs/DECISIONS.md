# Decision register

ADR-style log consolidating the 85 product/architecture questions surfaced during scoping. Each entry shows the resolved answer plus rationale. Items marked **TBC** require user confirmation; **OPEN** items are explicit future-work flags.

> Status: drafted 2026-05-28 from the scoping Q&A. Update entries in place as decisions evolve; never delete — supersede.

---

## A. Product, strategy, naming

**A1. Rename `aegis-*` → `aegiuw-*` across the codebase.** **Done.** The original project codename was *Project Aegis*; the chosen public identifier is `aegiuw`. The rename touched crate names, identifiers, brew tap path, worker name, KV namespace placeholder, and all internal references. Landed in commit `b13ae67`; Cargo.lock regenerated; `cargo test`, `clippy -D warnings`, and `tsc` all green.

**A2. Canonical domain.** **TBC.** Availability check (2026-05-28, whois + DNS): **all five candidates currently unregistered** — `aegiuw.com`, `aegiuw.security`, `aegiuw.app`, `aegiuw.io`, `aegiuw.dev`, `aegiuw.org`, `aegiuw.co`. Trademark search still pending before locking. Defaults assumed in code use `aegiuw.example` (RFC 2606) and `api.aegiuw.security` where a candidate had to be picked.

**A3. Target segment.** SMB and mid-market. *Confirmed.*

**A4. OSS = fully functional standalone.** *Confirmed.* No managed-tier coupling required. The OSS daemon + worker + self-hosted Cloudflare account delivers the full one-user product.

**A5. Positioning.** *"Automates browser isolation for non-technical end users at risky moments."* This frames every design choice toward zero-config, mass-adoption UX — and collapses several Layer-1 ambiguities (non-technical users won't install a root CA, so the capture model in C13 is settled by the customer, not the engineering preference).

**A6. Unit economics.** $1.30/user/month at $0.26 COGS target. Back-of-napkin: ~10 isolated sessions/user/month × $0.01/session (Cloudflare Containers, 5-min avg) ≈ $0.10 sandbox + $0.05 warm-pool + $0.01 KV/R2 + $0.10 ops ≈ **$0.26/user/month — matches target, tight margin**. Heavy users (30+ sessions/month) push COGS to ~$0.40. **Recommendation:** add volume tiers and monitor session/user histograms.

**A7. GTM.** Product-led, self-serve. *Confirmed.*

## B. Threat model & scope

**B8. Scope.** In: phishing / AitM via web pages launched from email, docs, or browser navigation. Out: malware C2, non-browser exfil, DNS attacks, mobile. *Confirmed.*

**B9. Platforms.** Desktop only: macOS, Windows, Linux. *Confirmed.* **Recommended order:** macOS first (highest SMB phishing exposure + cleanest sanctioned APIs), then Windows, then Linux.

**B10. Trust boundary.** **Recommendation:** assume the endpoint may be compromised *after* install; Aegiuw protects the *moment of click* (zero-trust browsing of unknown links), not arbitrary later state. We protect the *user* (their credentials), not the *device*.

**B11. Daemon is user-disableable.** *Confirmed.* Trade-off accepted: SMB usability > tamper resistance in v1. Anti-bypass is not a goal.

**B12. False-positive override.** From the sandbox UI, the user may force-open the link in their regular browser with no further blocker. *Confirmed.* No admin-approval gating in OSS; commercial tier may add it via policy.

## C. Layer 1 — capture (anchor)

**C13. Capture model (final product, not v1).** **Recommendation: hybrid — opaque-TCP fork at the network layer + optional WebExtension for URL-assist.** No local root CA. The TUN/Network Extension enforces isolation at the connection layer; an optional browser extension supplies the precise URL when available. The extension is *optional* for security (network fork enforces) and *required* for deep-link rendering UX. Picking a local-CA decrypt model would conflict with A5 (non-technical SMB users).

**C14. ECH (Encrypted ClientHello) policy.** **Recommendation:** treat unreadable-SNI connections as `Unknown` → isolate. If isolation can't be delivered (region unavailable, edge unreachable), fall through to the warning UI per **D25**.

**C15. QUIC / HTTP3 over UDP 443.** **Intercept.** *Confirmed.* Implementation: hook UDP 443 in the TUN; parse the QUIC Initial packet for SNI (cleartext in QUIC Initial, modulo ECH). Required because browsers attempt QUIC first to a growing share of hosts.

**C16. PPID attribution (PRD flaw).** *Conceded.* The actual TCP connection is made by the browser process regardless of who launched it, so `parent_process = Outlook` is rarely observable at the network layer. **Recommendation:** **deprioritize FR-2.3 in v1.** Use the WebExtension (C13) to surface navigation context (referrer, opener, originating tab/email) when it's the cleanest signal. Native-only fallback: timing heuristic (e.g. mail app launched the browser within ~3s of new TLS connection).

**C17. Top-level navigations only, not subresources.** *Confirmed.* The tool mitigates user clicks, not page-internal supply-chain risks.

**C18. HTTP/80 in scope.** *Confirmed.* Plain-text host is easier to extract; same fork logic applies.

**C19. PPID mechanism per OS.** *Confirmed in interface,* but see C16 — low priority in practice.

## D. Layer 2 — local risk engine

**D20. `allowed_cache.json` mechanics.** **Recommendation:** ed25519-signed JSON, distributed via the worker, monotonically versioned, atomic-update semantics on the daemon. Per-org overlays supported.

**D21. Brand list source.** **Recommendation: the Tranco list** (academic, free, daily-updated, research-compatible). Bundle a top-10k static snapshot; refresh quarterly via daemon release.

**D22. Levenshtein threshold default ≤ 2, no per-org tunability.** *Confirmed.*

**D23. IDN / homoglyph / Unicode confusables.** *Confirmed in scope.* **Recommendation:** apply Unicode Confusables (CLDR) + ASCII fold-down *before* Levenshtein. Punycode-decode IDNs.

**D24. Newly-registered domain heuristic.** *In scope.* Requires RDAP — an API call. **Recommendation:** edge-side RDAP cache in the worker (isolate path is edge-routed anyway). Local fallback for offline: bundled list of high-abuse new TLDs (`.zip`, `.mov`, `.top`, etc.) treated as Unknown when age can't be determined.

**D25. Fail-mode when edge is unreachable.** *Confirmed.* Warning UI: *"This link looks risky. Aegiuw couldn't reach the SafeBrowser Isolation service. You can still open in your regular browser at your own risk."* + explicit user opt-through.

## E. Layer 3 — transport

**E26. Splice/proxy with no decryption on the native path.** *Confirmed.*

**E27. Per-OS transport implementation.** **Recommendation:** native sanctioned APIs per OS, not bare TUN where avoidable —
- macOS: **Network Extension framework** (`NEAppProxyProvider` / `NEFilterDataProvider`). Modern, sanctioned, no kext.
- Windows: **WFP (Windows Filtering Platform)** primary; **Wintun** for cases WFP doesn't cover.
- Linux: `/dev/net/tun` + nftables.

Userspace TCP splice with async I/O (Tokio). See **O82**, **O83** for distribution implications.

**E28. IPv6 / dual-stack.** *Confirmed in scope.*

**E29. Daemon↔edge protocol.** **Recommendation:** HTTPS POST for session control + WebSocket per active isolation session (long-lived for streaming signaling).

**E30. Browser's original socket on the isolate path.** **Recommendation:** with the WebExtension (C13), intercept *before* the socket opens — extension cancels navigation and signals the daemon. Without extension fallback: TUN sends RST; native viewer pops up immediately.

**E31. VPN/proxy coexistence.** **Recommendation:** detect existing VPN clients at startup; document a compatibility matrix; install routing rules *after* corp-VPN routes so the VPN handles its own traffic.

**E32. Split-tunnel rules.** *Confirmed.* Default exclude: localhost, RFC1918, mDNS `.local`, listed internal domains. Configurable in TOML.

## F. Layer 4 — edge router

**F33. KV schema.** **Recommendation:** org-namespaced keys — `org:{id}:allow`, `org:{id}:block`, `org:{id}:rules`, `org:{id}:contributions`. JSON shape with explicit `version` field; atomic updates via worker mutations.

**F34. Region selection (NFR-4.2 / GDPR).** **Recommendation:** daemon includes a region preference; worker enforces Cloudflare `services_jurisdiction` for data localization. EU users → EU-pinned KV and containers.

**F35. Rate limiting on `/isolate`.** **Recommendation:** per-token rate limiting via Workers' built-in rate-limiting. OSS defaults: 60 isolations/hour/IP. Tunable.

**F36. Daemon↔router auth (OSS path).** **Recommendation:** shared HMAC secret set at self-hosted deploy time. Commercial path uses JWT (see **L60**).

**F37. Private contributions to the allowlist.** **Recommendation: federated, signed-contribution model.** Anyone can submit signed allow/block votes via the worker; consensus aggregated into a community-curated list. Contributions are cryptographically signed but unlinked to personal identity (rotating per-installation public keys). The "Wikipedia of brand domains," privacy-preserving by construction.

## G. Layer 5 — sandbox

**G38. Sandbox primitive.** **Recommendation: Cloudflare Containers** for long-lived interactive sessions. Cloudflare Browser Rendering retained as a screenshot-only fallback path.

**G39. Cold-start latency.** OSS users get whatever their Cloudflare account delivers (no warm pool). Commercial tier warm-pools per **L66**.

**G40. 120-concurrent container cap (OSS).** **Recommendation:** queue with an "isolation slot queued" UI message. For SMB usage patterns (rare simultaneous clicks), contention should be rare.

**G41. Download scrubber.** All OSS → **ClamAV** bundled in the container image. Downloads are scanned inside the sandbox before delivery to the host.

**G42. Session duration.** **Recommendation:** idle timeout 5 min, hard cap 30 min. Matches SMB browsing patterns + cost ceiling.

**G43. Per-session cost.** **Recommendation:** budget $0.005–$0.01/session. This drives **A6** economics.

**G44. Blank profile → no SSO in sandbox.** *Accepted.* The sandbox is a buffer, not a normal browser (see **I52**).

## H. Layer 6 — streaming

**H45. Streaming model.** **Recommendation: pixel stream via WebRTC + H.264** (adaptive 500 kbps–2 Mbps, 30 fps). Cheap (cost/quality balance per **A6**), low-latency, browser-native, hardware-decoded. DOM mirror rejected: re-imports attack surface.

**H46. Codec/bandwidth.** As H45. Best cost/quality without exotic infra.

**H47. Interactive latency target.** End-to-end input-to-pixel **< 150 ms**.

**H48. Stream topology.** **Recommendation:** WebRTC peer connection directly between daemon and sandbox container; the router handles **signaling only** (no media bytes through the worker — cheaper and lower-latency).

**H49. Accessibility.** **Recommendation: dual-channel** —
- Primary: pixel video stream (visual users).
- Secondary: text-only "accessibility tree" data channel mirroring ARIA labels + focused-element semantics from the sandbox via CDP `Accessibility.getFullAXTree`. Screen readers consume this side channel.

This directly satisfies your J56 requirement ("highest level of education, everything accessible, deterministic, auditable") and is a meaningful differentiator.

## I. Layer 7 — credential lockout

**I50. Field detection.** Forms too, with per-field policy. **Recommendation:** detect by `input[type]`, `autocomplete` token (`current-password`, `email`, `cc-number`, etc.), and form-action heuristics. Sensitive fields → keystrokes dropped at the relay. Per-field decisions, not a blanket form lock.

**I51. Enforcement point.** **Recommendation: server-side input relay** (in the sandbox container). The client is never trusted — a tampered client cannot bypass.

**I52. Block paste / clipboard.** *Confirmed.* The sandbox is a buffer, not a normal browser.

**I53. Coverage limits.** As-much-as-possible. **Recommendation:** combine input-type heuristics + form-action analysis + commercial AitM blocklist. Accept that exotic JS-only credential collectors will be missed in v1.

**I54. Blocked-typing UX.** **Recommendation:** clear toast — *"Aegiuw blocked typing on this risky page. Don't enter credentials here."* + per **B12** "open in regular browser anyway" escape.

## J. Layer 8 — local viewer UX

**J55. Webview tech.** Native. *Confirmed.* WKWebView (macOS), WebView2 (Windows), WebKitGTK (Linux). Thin per-OS shim.

**J56. UX principles.** *"Highest level of education, everything accessible, data deterministic and auditable."* **Recommendation:**
- Inline education ("Why is this page protected?" with link to a permanent explainer).
- Accessible component library (WCAG 2.2 AA target).
- Per-user **local audit log** of every isolation decision (deterministic, exportable as JSONL). User owns it; nothing leaves the device by default.

## K. Layer 9 — threat intel

**K57. AitM feed source.** **Recommendation:** aggregate **OpenPhish + PhishTank** (open feeds) for OSS; augment with commercial partner (Spamhaus, Netcraft) for the commercial tier.

**K58. Encryption + cron mechanics.** **Recommendation:** AES-256-GCM with rotating daily keys; 10-min cron pulling delta updates; key rotation via a signed JSON manifest.

**K59. Is OSS-without-intel enough?** *Reframe.* For a product positioned as *"automate browser isolation,"* the **isolation itself is the security value** — not detection accuracy. Unknown domains are isolated; no credentials can leak. The intel feed is an *optimization* (fewer unnecessary isolations) rather than a security must-have. **OSS-only is plenty safe; commercial tier reduces friction, not risk.**

## L. Layer 10 — commercial

**L60. Device identity.** **Recommendation: OS keystore keypair**, not motherboard/CPU UUIDs. Secure Enclave on macOS (via Keychain), TPM via NCrypt on Windows, TPM2 on Linux (fallback: encrypted file with user-set passphrase). JWT signed by this device key. Drops hardware-UUID brittleness; survives reimaging if backed up correctly.

**L61. JWT validity + clock skew.** **Recommendation:** 60s validity + 30s tolerance; reissue every 30s.

**L62. Stripe model.** **Recommendation:** per-seat subscription, $1.30/seat/month, **14-day trial**, **10–15% annual discount**, self-serve checkout. No usage metering in v1 (predictable bills are an SMB feature).

**L63. Org onboarding flow.** **Recommendation:** signup → server-side org keypair generated → admin downloads enrollment token + install command → daemon first-run exchanges enrollment token at the licensing worker for a signed device cert → cert stored in OS keystore. MDM-friendly: token can be pushed via config profile.

**L64. Seat enforcement.** **Recommendation:** count unique device certs; over cap → block enrollment of new devices (existing keep working); admin may revoke a seat to free one.

**L65. Stripe webhook security + delinquency policy.** **Recommendation:** Stripe signature verify + idempotency keys on event IDs; **7-day grace** after `payment_failed` with daily admin emails before deactivation.

**L66. Warm-pool (Durable Objects).** **Recommendation:** regional placement; pool size = `min(N, ceil(0.1 × seats))`; scale on usage telemetry.

**L67. Residential proxy masquerading.** **Recommendation: do not ship in v1.** ToS / legal / liability risk is high enough that it should require explicit customer demand + legal review to justify. Re-evaluate post-v1 only if needed.

**L68. SIEM integrations.** **All:** Splunk HEC, Datadog, S3, syslog/Loki (OSS). Use **OCSF** format for standardization.

**L69. Self-hosted-commercial + fully-managed tiers.** *Both supported.* Billing differs: self-hosted = license-key only; managed = full SaaS.

## M. Privacy, compliance, legal

**M70. What gets shared back.** *"Everything — the question is what."* **Recommendation:**
- OSS: nothing leaves the device by default.
- Commercial: only flagged-domain alerts (risky URLs), no per-user identifiers, fully aggregable.

**M71. Customer-managed-logging tier.** *Confirmed direction.* **Recommendation: offer a "logs-to-customer-only" tier** where audit and telemetry streams directly to the customer's S3 / SIEM, never to our infrastructure. Strong enterprise differentiator and a meaningful privacy story.

**M72. Inspection consent.** *"All traffic scrubbing local; only risky URLs logged."* **Recommendation:** explicit user consent at install + admin attestation per deployment; document the local-scrubbing guarantee; flagged-URL telemetry is optional even in commercial.

**M73. SOC 2 / ISO 27001 / DPA.** *Confirmed scope* for the commercial tier.

**M74. Telemetry default.** *"No externalized telemetry, or totally anonymized."* **Recommendation:** opt-in anonymized aggregated metrics only — counts and histograms, no URLs or identifiers. Default OFF.

## N. Architecture, repo, engineering

**N75. Open-core boundary + license.** *"Copyleft monorepo for core + worker; private repo for managed infra."* *Confirmed.*

**License:** **AGPL-3.0-or-later** for the open-source core + worker. *Done* (commit `819ac3f`): canonical AGPL-3.0 text fetched from gnu.org installed as `LICENSE`; `NOTICE` updated; per-file `SPDX-License-Identifier: AGPL-3.0-or-later` headers added to every source file; workspace `license` field updated. Section 13 (network use) explicitly applies: any modified version offered over a network must make its source available to network users — the deliberate strong-copyleft choice to block closed SaaS forks.

**Repo layout:** core (`crates/`, `workers/aegiuw-router/`) lives in this public monorepo under AGPL; the managed Aegiuw-Enterprise infrastructure (billing, warm pools, Stripe webhook handler, residential proxy if ever shipped, SIEM streaming code) lives in a separate **private** repository under proprietary terms.

**N76. Shared Rust ↔ TS types.** **Recommendation: compile `aegiuw-core` to WASM** for use inside the worker. Single source of truth; eliminates risk of Rust/TS schema drift.

**N77. Monorepo tooling.** **Recommendation:** pnpm workspaces for JS/TS + Cargo workspace for Rust + `packages/shared/` for TS schemas + a `justfile` for cross-stack tasks. No turborepo until needed.

**N78. Release strategy for widest adoption.** **Recommendation: signed installers everywhere** —
- macOS: notarized `.pkg`.
- Windows: WiX `.msi`, signed with EV cert, bundled signed Wintun.
- Linux: `.deb` + `.rpm` + AUR + Flatpak.
- Brew tap for technical users.
- Auto-update via Sparkle / WinSparkle / native package manager.

One-click everywhere; non-technical users never touch a CLI.

**N79. Daemon configuration.** **Recommendation:** TOML at OS-standard location —
- macOS: `~/Library/Application Support/aegiuw/config.toml`
- Windows: `%APPDATA%\aegiuw\config.toml`
- Linux: `~/.config/aegiuw/config.toml`

Bundled localhost-only web UI for non-technical configuration. Reload-on-change.

**N80. Auto-update.** **Recommendation:** Sparkle / WinSparkle for desktop; Linux via the platform package manager. Signing key in HSM. Canary → stable rollout with usage telemetry gates.

**N81. Test strategy.** **Recommendation: four layers —**
1. Unit (`cargo test`, fast, hot locally).
2. Integration with fixture ClientHello/QUIC packet blobs.
3. End-to-end via Playwright against a real sandbox (run locally on demand).
4. Continuous fuzz (`cargo-fuzz`) on the SNI/QUIC parsers — adversary-controlled bytes.

*Note:* there is intentionally **no GitHub Actions CI** for this repo. All quality gates (`cargo test`, `cargo clippy -D warnings`, `tsc --noEmit`, `cargo-fuzz`) run locally and pre-push by contributor convention. Decision recorded after the initial scaffold; if/when scale demands automation, revisit.

## O. Distribution & installation

**O82. macOS install.** **Recommendation:** notarized **.pkg** with privileged helper + **macOS Network Extension** (`NEAppProxyProvider` / `NEFilterDataProvider`). System extension, no kext. Higher bar but the only sanctioned long-term path. **brew remains the technical-user convenience entry point**, not the mass-deployment path.

**O83. Windows install.** **Recommendation:** WiX **.msi**, signed with EV cert. **WFP (Windows Filtering Platform)** as the primary interception layer; **Wintun** for cases WFP doesn't cover. *Note: Wintun is dual-licensed GPLv2 / commercial — verify compatibility with the final core license (see N75).*

**O84. Linux package.** **Recommendation:** `.deb` + `.rpm` + AUR + Flatpak; **systemd user-level unit** (per-user daemon — matches N79's per-user config).

**O85. Enterprise mass-deployment.** **Recommendation:** ship platform config profiles — `.mobileconfig` (macOS), `.intunewin` / GPO templates (Windows), Ansible roles (Linux). Install token delivered via config profile for zero user friction.

---

## Pending confirmations

- **A2** Canonical domain — registration target. All seven `aegiuw.{com,security,app,io,dev,org,co}` candidates currently unregistered; trademark search still owed before locking and acquiring.

(A1 and N75 resolved in this branch — see entries above.)

## Implemented backlog items (from `note.md` / SNI improvements)

- **T16 (P3) Snapshot tests for the O1 trace event shape.** Done. 4 tests pin the wire shape of `extract_sni`'s structured trace event (target, level, outcome kind string, byte_count, duration_us) for each `SniOutcome` variant. A refactor that renamed `duration_us` to `duration_micros` or `outcome` to `verdict` would silently break every downstream dashboard built on the O2/O3 contracts — T16 catches that at test time.

  **Implementation:** added a small custom `tracing_subscriber::Layer` (`CapturedEvents`) that records `tracing::Event`s into a `Mutex<Vec<CapturedEvent>>` with field-by-field visitor capture. Tests install the layer via `tracing::subscriber::with_default` for the scope of the `extract_sni` call, then drain the captured events for assertions.

  **New dev-deps:**
  - `tracing-subscriber = { version = "0.3", default-features = false, features = ["registry"] }` — provides the `Layer` / `Registry` building blocks.
  - `tracing = "0.1"` (with default `std` feature) in dev-dependencies, overriding the production `tracing = { default-features = false }`. Required because `tracing::subscriber::with_default` is std-gated. Production builds keep `no_std`-compat per P6; only the test build pulls in std.

  **Tests:**
  - `t16_cleartext_emits_structured_trace_event` — pins target = `"aegiuw_core::sni"`, level = `"TRACE"`, outcome = `"cleartext"`, byte_count matches input length, duration_us parses as u64.
  - `t16_encrypted_emits_kind_encrypted` — outcome = `"encrypted"` for ECH-bearing CH.
  - `t16_not_found_emits_kind_not_found` — outcome = `"not_found"` for empty-extensions CH.
  - `t16_malformed_emits_kind_malformed` — outcome = `"malformed"` for garbage input; byte_count still reports input length on malformed inputs.

  256 tests pass (was 252 — added 4). Clippy clean both feature sets.

- **T10-T15 (P2) Labeled fixtures for existing-behaviour contracts.** Done as one commit because every item is a named alias for a contract already covered elsewhere — the fixtures exist so a test-plan reader can grep for `T10`/`T11`/… and land on an obvious entry.
  - **T10** — single `ServerName` entry with empty `host_name` → Malformed (RFC 6066 §3 `HostName<1..2^16-1>` non-empty by type construction). Already enforced by H2.
  - **T11** — `ServerNameList = [non_host_name, host_name]` → NotFound. The current parser bails on the unknown-name_type first entry without walking past it (failure-closed shape because we don't know the entry's wire structure). The "would have been usable" second `host_name` entry is silently skipped. New test documents this design choice with rationale.
  - **T12** — 253-byte hostname accepted (RFC 1035 §2.3.4 max). Pinned by `accepts_hostname_at_253_byte_boundary`.
  - **T13** — mixed-case hostname passed through verbatim. Pinned by H6 contract; T13 alias.
  - **T14** — trailing-dot hostname stripped per H4. Pinned by H4 tests; T14 alias.
  - **T15** — numeric IP literal (v4 + v6) rejected as Malformed (RFC 6066 §3 + H1).
  
  6 new tests; 252 total (was 246). Clippy clean both feature sets.

- **T9 (P2) server_name extension with empty ServerNameList.** Done. 1 test pinning that the SNI extension body with `ServerNameList` u16 prefix = 0 returns Malformed. RFC 6066 §3 type construction (`<1..2^16-1>`) is non-empty; an empty list is a spec violation. Already enforced by C10 — T9 labels the fixture explicitly for the test plan. 246 tests.

- **T8 (P2) Zero-length extensions block.** Done. 1 test pinning that a CH with `extensions_len = 0` parses as `SniOutcome::NotFound` (not Malformed). RFC 8446 §4.1.2's `Extension extensions<0..2^16-1>` permits zero entries by type construction. Metadata: `host = None`, `extension_order` empty, all Option fields None. 245 tests.

- **T7 (P2) Coalesced-records fixture.** Done. 2 tests pinning: (a) one complete handshake + partial trailing record bytes — trailing bytes are ignored (the parser's "first complete handshake wins" contract from `reassemble_handshake` docs); (b) two records carrying one handshake (the canonical fragmentation case, named T7 so the test plan landing page finds an obvious fixture). 244 tests pass (was 242). Clippy clean.

- **T6 (P1) Malformed-corpus truncation sweep.** Done. 3 tests that walk every byte-prefix of known-good ClientHellos and assert `extract_sni` / `parse_client_hello_full` never panic, never read OOB, and always return a stable `SniOutcome::kind()`.

  **Why this complements S2 (proptest):** S2 random-walks the input space looking for panics; T6 is its deterministic complement. Proptest occasionally misses long-running prefixes that linear truncation hits every time, and proptest's shrinking doesn't always cover the maximum-length tail.

  **Tests:**
  - `t6_truncating_classical_ch_at_every_byte_never_panics` — truncates the T3 Chrome 2026 fixture at every byte 0..=N. Each prefix must return one of the 4 stable `kind()` labels.
  - `t6_truncating_pq_ch_at_every_byte_never_panics` — same sweep on the T5 ~1400-byte PQ-hybrid CH. Also calls `parse_client_hello_full` on every prefix (post-A1 refactor that path is now independent from `extract_sni`'s projection, so each is exercised separately).
  - `t6_full_byte_value_space_at_short_lengths_never_panics` — exhaustive 1-byte (256 cases) and 2-byte (65536 cases) input sweep. Proptest covers this in expectation; the deterministic sweep proves it.

  242 tests pass (was 239 — added 3). Clippy clean both feature sets. Total `cargo test` wall time impact remains negligible (the byte-space sweep is ~65k function calls but each call is sub-microsecond on the malformed path).

- **T5 (P1) Post-quantum hybrid corpus.** Done. 2 tests + a `build_pq_chrome_clienthello` fixture that carries a realistic-sized X25519MLKEM768 key share — `REAL_MLKEM768_PUBKEY_LEN = 1216` bytes (X25519 32 + MLKEM768 1184, per RFC 9627). A typical Chrome 2026 CH with PQ hybrid is ~1400 bytes total, an order of magnitude larger than a classical-only CH.

  **Contracts pinned:**
  - The parser handles the realistic ~1216-byte key_exchange field without tripping any internal length check that was sized for classical key shares (which are ≤ 65 bytes).
  - `has_post_quantum_key_share` fires; `key_share_groups_classified` surfaces `KeyShareGroup::X25519MlKem768` in client-preference order.
  - The CH still parses correctly when fragmented across multiple records. PQ key shares are bigger than common record sizes (and TCP MSS), so production traffic from PQ-enabled browsers will *routinely* arrive fragmented. Pinned by `t5_pq_clienthello_survives_two_record_fragmentation`.

  239 tests pass (was 237 — added 2). Clippy clean both feature sets.

- **T4 (P1) ECH-bearing CH (Cloudflare convention).** Done. 3 tests + a `build_cloudflare_ech_clienthello` fixture modeling the canonical Cloudflare ECH wire shape: Chrome-shaped CH with `cloudflare-ech.com` as the outer SNI per Cloudflare's documented rollout (every Cloudflare-hosted ECH connection presents this exact sentinel).

  **Contracts pinned:**
  - `extract_sni` returns `SniOutcome::Encrypted` (NOT `Cleartext` carrying the decoy host). Policy must route to Isolate per DECISIONS.C14.
  - `meta.host == None` even though the wire shows `cloudflare-ech.com` — the parser masks it.
  - `meta.ech_present == true`.
  - `is_cloudflare_ech_outer` (O5) still recognises the sentinel for telemetry purposes, including case-insensitive variants.

  237 tests pass (was 234 — added 3). Clippy clean both feature sets.

- **T3 (P1) Real-world ClientHello corpus (synthetic-realistic).** Done. 8 client-shape fixtures modeled after the documented behaviour of major real-world clients:

  | Fixture | Modeled after |
  |---|---|
  | `build_chrome_2026_clienthello` | Chrome ≥ m121 — PQ hybrid (X25519MLKEM768), ECH, certificate compression, ~16 ext, 3 GREASE |
  | `build_firefox_2026_clienthello` | Firefox 2026 — PQ hybrid, no ECH (lagged behind Chrome), ffdhe groups |
  | `build_safari_macos15_clienthello` | Safari macOS 15 — no PQ, no ECH, distinctive sigalg ordering |
  | `build_curl_openssl_clienthello` | curl + OpenSSL — minimal ext set, no ALPN by default, no PQ/ECH |
  | `build_go_clienthello` | Go `crypto/tls` — h2 ALPN via net/http, no PQ/ECH |
  | `build_python_requests_clienthello` | Python `requests` (urllib3 + OpenSSL) |
  | `build_ios_urlsession_clienthello` | iOS 18 URLSession — Safari-like |
  | `build_android_okhttp_clienthello` | Android OkHttp 4.x — h2 ALPN, modern sigalgs, no PQ |

  **Scope note pinned in source:** these are **not byte-for-byte captures** — capturing real wire traffic requires a TLS-aware test harness against real services, which is out of scope for unit tests. The fixtures mimic the *shape* (cipher list, extension count + order, ALPN, key_share, supported_groups, sigalgs) as documented in public sources (FoxIO JA4 database, browser source trees, library docs). The goal is **shape coverage**: a regression that breaks parsing of any major-class real client trips one of these tests.

  **Tests added:**
  - `t3_real_world_corpus_all_parse` — walks all 8 fixtures and asserts each parses successfully. Single regression guard.
  - Per-client shape pinners (Chrome / Firefox / Safari / curl) — assert the key fingerprint dimensions (`has_post_quantum_key_share`, `ech_present`, ALPN preference) match the modeled client. E.g. Chrome must show PQ + ECH; Safari must show no PQ + no ECH; curl must show no ALPN preference.

  **DECISIONS.C14 bug-catch:** initially the Chrome shape test asserted `meta.host == Some("www.example.com")`, but the parser correctly masks the host when ECH is present. Fix landed in the same commit with a comment pinning the C14 contract: ECH-bearing CHs return `host: None` (decoy) and project to `SniOutcome::Encrypted`.

  234 tests pass (was 229 — added 5). Clippy clean both feature sets.

- **T2 (P1) GREASE-noise test fixture.** Done. 6 new tests pinning that GREASE codepoints (RFC 8701) before, after, and around the `server_name` extension don't interfere with SNI extraction or extension-order observability. Every modern browser sprinkles ~3 GREASE extensions throughout the wire CH; a parser that mishandled them would reject most production traffic.

  **Contracts pinned:**
  - SNI extraction unaffected by GREASE position (before / after / sandwiching `server_name`).
  - Multiple *distinct* GREASE codepoints (0x0A0A + 0x1A1A + 0x2A2A + 0xFAFA) coexist without tripping the C3/C4 duplicate-extension rejection.
  - `extension_order` (A12) preserves GREASE in wire order — filtering happens at the fingerprint layer (JA3/JA4 strip GREASE before hashing), not the parser layer. This separation matters because some downstream telemetry uses the raw extension_order for fingerprint research.
  - Two of the **same** GREASE codepoint still trip the dup-detection rule. RFC 8701 doesn't carve out an exception to RFC 8446 §4.2's MUST NOT rule.

  229 tests pass (was 223). Clippy clean both feature sets.

- **T1 (P0) Fragmentation exhaustive test fixture.** Done. Added a dedicated T1 block in `sni.rs`'s test module with 5 new tests pinning the C1 multi-record reassembly fix across a wider surface than the original C1 commit covered.

  **Historical context** (captured as a block comment in the test source so future readers see it inline): pre-C1 the parser was single-record-only, so a ClientHello legitimately split across two TLS records — a routine, RFC-permitted shape — would have returned `SniOutcome::Malformed`. That looks safe (we'd route to Isolate) but it's the exact Traefik CVE class: an attacker who can influence packet boundaries hides the SNI and the connection takes the wrong path. The T1 fixture pins that the C1 fix holds across the full space of splits, not just the canonical mid-point.

  **New tests:**
  - `t1_two_record_split_at_every_position_extracts_sni` — exhaustive sweep over every internal byte position. Proves reassembly is *uniformly* correct, not just for the convenient mid-point split.
  - `t1_two_record_split_at_every_position_reassembles_identically` — tighter contract: the reassembled bytes must equal the original handshake at every split. Catches off-by-one errors that SNI-extraction would miss (e.g. a stray padding byte that happens to live before the SNI extension).
  - `t1_three_record_split_extracts_sni` and `t1_four_record_split_at_each_quarter_extracts_sni` — pin that the multi-record path generalises beyond N=2.
  - `t1_full_metadata_equivalence_single_vs_two_record_split` — the strongest contract: fragmented and single-record forms of the *same* ClientHello must produce *identical* `ClientHelloMetadata`. A regression that affected only the multi-record path (e.g. a Cow promotion bug that lost an extension during owned reassembly) would slip through SNI-only tests but trip this comparison.

  The pre-existing `reassemble_handshake_assembles_two_record_fragmentation`, `reassemble_handshake_assembles_many_tiny_fragments` (the kubernetes ingress-nginx 1-byte-per-record case), and `extract_sni_works_on_fragmented_two_record_client_hello` remain — T1 augments rather than replaces them.

  **223 tests pass** (was 218 — added 5). Clippy clean both feature sets. The exhaustive sweep adds ~250 sub-test cases (handshake is ~150 bytes long) per `cargo test` run; total wall time impact is negligible.

- **F5 (P3) `likely_launch_source` classifier — fallback for C16.** Done. Added `pub enum LaunchSource { Browser, Cli, Library, Unknown }` and `pub fn likely_launch_source(meta) -> LaunchSource` to `fingerprint.rs`.

  **Critical scope note (pinned in module docs):** the TLS handshake is made by the *browser process* regardless of which app launched it — Chrome opened by clicking a link in Outlook produces the same TLS fingerprint as Chrome opened from the dock. So we **cannot** distinguish browser-launched-by-email from browser-launched-by-user from the TLS fingerprint. F5 is a *partial* replacement for the broken PPID approach: it narrows the search space ("was it a browser at all?") without solving the launching-app question. The full "this came from email" answer still needs the WebExtension (per DECISIONS.C13) or a process-tree timing heuristic.

  **Decision flow:**
  1. Compute JA4 once; if `KNOWN_JA4_FINGERPRINTS` has a hit, return the matching bucket directly.
  2. Otherwise, score browser-likeness from metadata signals:
     - ECH present → +3 (strong: Chrome/Firefox 2024+)
     - PQ hybrid key_share → +3 (strong: Chrome/Firefox 2024+)
     - `compress_certificate` present → +1
     - HTTP/3 ALPN → +2; HTTP/2 ALPN → +1
     - `signature_algorithms` present → +1
     - ≥ 12 extensions sans GREASE → +1
     - ≤ 5 extensions sans GREASE → −2
  3. Thresholds (conservative): `≥ 5` → Browser, `≥ 2` → Library, `≤ −1` → Cli, else Unknown.

  **Key tests pin specific decisions:**
  - `likely_launch_source_ech_alone_is_a_strong_browser_signal` — ECH alone scores +3 → Library bucket. A future PR that raises the Browser threshold past ECH-only would have to update this test, forcing explicit review.
  - `likely_launch_source_grease_doesnt_count_toward_ext_count` — GREASE filtering applies in the heuristic same as in JA4. 5 real + 4 GREASE = 5 sans-GREASE → small-ext penalty fires.
  - `likely_launch_source_falls_back_to_unknown_for_ambiguous_shapes` — pins the Unknown band (score 0 or 1) so the classifier doesn't over-attribute.

  **Why conservative thresholds:** better to return `Unknown` than mis-attribute. The cost of a wrong classification is silent policy drift; the cost of `Unknown` is one more layer of signal needed (which Layer 2 already runs anyway).

  **8 new tests; 218 total** (was 210). Clippy clean both feature sets.

- **F4 (P3) JA3 / JA4 → `KnownClient` mapping.** Done. Added:
  - `pub enum KnownClient { Chrome, Firefox, Safari, Curl, Go, Other }` with `kind()` for stable snake_case telemetry labels (O2 / A2 / A3 convention).
  - `pub fn known_client_from_ja3(ja3_md5) -> Option<KnownClient>` and `pub fn known_client_from_ja4(ja4_raw) -> Option<KnownClient>`.
  - `pub const KNOWN_JA3_FINGERPRINTS` / `KNOWN_JA4_FINGERPRINTS` static tables (`&[(&str, KnownClient)]`).

  **Scope of the built-in tables — deliberately tiny:** the JA4 table ships exactly one seed entry, the FoxIO 2023 reference Chrome fingerprint `t13d1516h2_8daaf6152771_b186095e22b6` (documented in foxio.io/blog/ja4-network-fingerprinting). The JA3 table ships empty.

  **Why so few:**
  - JA3 hashes are fragile across browser releases — a single Chrome update can reshuffle extension order and flip the hash. Shipping unverified entries in the source would actively mislead callers. Pinned by `known_client_from_ja3_returns_none_for_anything` so a future PR can't quietly slip in entries.
  - JA4 is sort-stable so JA4 hashes age better, but the production-grade fingerprint corpus lives in JA4 databases (FoxIO's `ja4db.com`, threat-intel feeds). Baking specific hashes into Rust source freezes them; we ship the seed entry as a smoke-test of the lookup mechanism and leave production data plumbing to the deployer.
  - Real deployments should layer their own table on top — check locally first, fall back to `known_client_from_ja4` for the seed entries.

  **Table well-formedness pinned** by `known_client_table_entries_are_well_formed`: every JA4 entry has 3 underscore-joined segments, `a` starts with `t` or `q`, `b` and `c` are exactly 12 hex chars. Catches typos at test time rather than in production.

  **6 new tests; 210 total** (was 204). Clippy clean both feature sets.

- **F3 (P3) JA4_H stub (HTTP-layer fingerprint).** Done as a stub per the backlog wording ("out of SNI parser scope but worth a stub"). Added `pub fn ja4_h(input: &Ja4HInput) -> Ja4H` to `fingerprint.rs` with:
  - `pub struct Ja4HInput<'a>` — borrowed view over the HTTP-layer signals the daemon will collect (method, version, cookie/referer flags, header_names in wire order, accept_language). Not Serialize/Deserialize — it's an input view, not a persisted shape.
  - `pub struct Ja4H { a, b, c, d, raw, implemented }` — segments + the underscore-joined form + an `implemented: bool` flag that's `false` for the stub and `true` once the real algorithm lands.
  - Current implementation returns sentinel strings (`"00000000"` + three `"000000000000"`) with `implemented = false`. Shape and widths match the spec so downstream parsers don't have to special-case the stub form — pinned by `ja4_h_stub_segments_have_correct_widths`.

  **Why a stub in `aegiuw-core`:** JA4_H's signals (HTTP/2 SETTINGS, header order, cookies, Accept-Language) live in the HTTP layer, which `aegiuw-core` doesn't see. But the JA4 suite (`ja4`, `ja4_h`, `ja4_s`, `ja4_x`, `ja4_t`) shares hash-and-format conventions — centralising the entry points and types in `fingerprint.rs` keeps the serde shapes and label conventions consistent across the suite. Downstream consumers can wire the call site now and only need a recompile (not a refactor) when the implementation arrives.

  **Tests:** 3 new — `implemented` flag set to `false`, segment width contract, raw is underscore-joined. 204 total (was 201). Clippy clean both feature sets.

- **F2 (P3) JA4 TLS fingerprint.** Done. Added `pub fn ja4(meta) -> Ja4` and `pub struct Ja4 { a, b, c, raw }` to `fingerprint.rs`. FoxIO 2023 spec.

  **Algorithm:**
  - `a` (10 chars, fixed width): `{q|t}{12|13|…}{d|n}{cc}{ee}{aa}` — protocol (always `t` from aegiuw-core today), TLS version (from `supported_versions` falling back to `legacy_version`), SNI presence (`d` or `n`; never `i` because the parser rejects IP literals upstream), cipher count sans GREASE (2 digits clamped at 99), extension count sans GREASE (2 digits clamped at 99), first ALPN's first+last alphanumeric byte (`"00"` if absent).
  - `b` (12 hex): SHA-256 of sorted ciphers (sans GREASE) joined by comma in decimal. First 12 hex chars.
  - `c` (12 hex): SHA-256 of sorted extensions (sans GREASE, **sans SNI `0x0000` and ALPN `0x0010`** — both are already represented in the `a` segment) + optional `_` + sigalgs in **wire order** (not sorted). First 12 hex chars.

  **Why JA4 over JA3 for new work** — pinned in module docs:
  - JA3's first field is always `771` (legacy_version 0x0303) for TLS 1.3, so it lost version discrimination. JA4 reads `supported_versions`.
  - JA4 **sorts** cipher and extension lists; JA3 deliberately doesn't. A browser that re-randomises extension order between releases keeps the same JA4 but gets a fresh JA3 every time. Pinned by `ja4_b_sorts_ciphers_independent_of_wire_order`.

  **Edge cases pinned:**
  - Empty cipher list → JA4_b sentinel `"000000000000"` (parser never produces this, but the helper must not panic).
  - No extensions after SNI/ALPN/GREASE filter → JA4_c sentinel.
  - No sigalgs extension → JA4_c is just the sorted-extension hash, no `_` separator.
  - ALPN char extraction skips non-alphanumeric chars: `http/1.1` → `h1`, `h3-29` → `h9`, `h2` → `h2`.

  **New dep:** `sha2 = "0.10"` (RustCrypto, `default-features = false` for no_std-compat).

  **Reference SHA-256 values in tests:** each computed externally via `printf '%s' '<input>' | sha256sum | head -c 12` with the command in the comment so future PRs can reproduce.

  **201 tests pass** (was 187 — added 14 JA4 unit tests). Clippy clean both feature sets.

- **F1 (P3) JA3 TLS fingerprint.** Done. New `crates/aegiuw-core/src/fingerprint.rs` module with:
  - `pub fn ja3(meta: &ClientHelloMetadata) -> Ja3` — Althouse/Atkinson/Atkins 2017 algorithm.
  - `pub struct Ja3 { raw, md5 }` — comma-separated input string + lowercase hex MD5.
  - `pub const fn is_grease_codepoint(value: u16) -> bool` — RFC 8701 §3 GREASE detector (shared by F1/F2/F4).
  - New field `cipher_suites: Vec<u16>` on `ClientHelloMetadata`. The parser already validated the cipher list (non-empty, even length); F1 materialises it as `Vec<u16>` so JA3 can consume it. Parser change uses `chunks_exact(2)` + `from_be_bytes` — no panicking indexes (S5 lint clean).
  - New dependency: `md-5 = "0.10"` (RustCrypto, `default-features = false` keeps it no_std-friendly per P6).

  **Algorithm notes pinned in code:**
  - First field is `legacy_version` (we enforce `0x0303` = `771`), so every TLS 1.3 connection through our parser gets `771,…`. JA3's lost discriminatory power for 1.3 is exactly why F2 (JA4) exists.
  - GREASE filtered from cipher / extension / supported_groups lists. `ec_point_formats` is `u8` so no GREASE convention applies.
  - Lists are joined in **wire order**, not sorted. JA4 sorts; JA3 deliberately doesn't. Pinned by `ja3_preserves_wire_order_within_each_field`.
  - Host and ALPN values do *not* enter the fingerprint — only the extension *type code* shows up in the third field. Pinned by `ja3_with_host_and_alpn_doesnt_affect_string`.

  **MD5 verification approach:** each reference test's expected MD5 was computed externally (`printf '%s' '<raw>' | md5sum`) and the command is in the comment so future PRs can reproduce.

  **187 tests pass** (was 178 — added 8 unit + 1 doctest on `is_grease_codepoint`). Clippy clean both `--all-targets` (std) and `--no-default-features --lib` (no_std).

- **A12 (P3) Expose `extension_order` (high-fidelity fingerprinting input).** Done. Added `pub extension_order: Vec<u16>` on `ClientHelloMetadata` — every extension type seen, in the order they appeared on the wire. This is the raw input JA3/JA4-style fingerprints are largely built from; downstream code can hash it however they want without us baking an algorithm in.

  **Zero new parser code:** the parser already builds this Vec internally as `seen_ext_types` for the C3/C4 duplicate-extension rejection (RFC 8446 §4.2). A12 just renames that local variable to `meta.extension_order` so the same single write serves both the internal dup check and the public surface. The Cow promotion path picks up the field through normal `borrowed.extension_order` flow (Vec<u16> is Copy-friendly, no lifetime concerns).

  **Wire-order preservation pinned by `extension_order_records_every_type_in_wire_order`:** the parser does NOT sort or normalise — the order returned matches exactly what the client sent. Critical for fingerprinting because two clients can offer the same extension set in different orders.

  **No regressions:** criterion bench (Apple Silicon, release, --quick) shows extract_sni typical at ~50 ns, fragmented ~106 ns, 127-label hot path ~268 ns — within noise of the post-P5 baseline. 178 tests pass (was 175). Clippy clean both feature sets.

- **A11 (P3) Expose `ec_point_formats` (RFC 8422 §5.1.2).** Done. Added `pub const EXT_EC_POINT_FORMATS: u16 = 0x000b` and `pub ec_point_formats: Option<Vec<u8>>` on `ClientHelloMetadata`. TLS 1.2 legacy: list of ECPointFormat codepoints (`0`=uncompressed, `1`=ansiX962_compressed_prime, `2`=ansiX962_compressed_char2). Rarely meaningful in TLS 1.3 ClientHellos but still emitted by some clients as a fingerprint dimension.

  **Wire shape:** `u8`-prefixed list of `u8`, must be non-empty per RFC 8422 §5.1.2.

  3 new tests; 175 total (was 172). Clippy clean both feature sets.

- **A10 (P3) Expose `supported_groups` (RFC 8446 §4.2.7).** Done. Added `pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a` and `pub supported_groups: Option<Vec<u16>>` on `ClientHelloMetadata`. Reuses A9's `parse_u16_prefixed_u16_list` (same wire shape).

  **Semantic distinction from `key_share_groups` pinned by `supported_groups_distinct_from_key_share_groups`:** `supported_groups` is the *could-use* list; `key_share` is the (usually shorter) subset for which the client actually shipped public keys for the first-round handshake. A client that lists X25519MLKEM768 in `supported_groups` but not in `key_share` is signalling "I can do PQ if the server asks for it via HRR" without paying the extra bytes upfront.

  4 new tests; 172 total (was 168). Clippy clean both feature sets.

- **A9 (P3) Expose `signature_algorithms` (RFC 8446 §4.2.3).** Done. Added `pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d` and `pub signature_algorithms: Option<Vec<u16>>` on `ClientHelloMetadata`. High-fidelity fingerprint dimension — algorithms and order vary by client/browser version.

  **Shared parser**: introduced `parse_u16_prefixed_u16_list` covering both A9 and A10 (`supported_groups` — same wire shape). RFC strictness: non-empty list, even byte length.

  4 new tests; 168 total (was 164). Clippy clean both feature sets.

- **A8 (P3) Expose `record_size_limit` (RFC 8449).** Done. Added `pub const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c` and `pub record_size_limit: Option<u16>` on `ClientHelloMetadata`. The value is the maximum record-layer payload (bytes) the client is willing to receive. Useful Layer-2 fingerprint dimension and infrastructure-sizing input.

  **Strictness:** RFC 8449 §4 mandates the value be in `[64, 2^14 + 1] = [64, 16385]`. Out-of-range values surface as `Malformed` (parser returns `None`) rather than being silently clamped — same failure-closed contract as the rest of the parser. The extension body must be exactly 2 bytes; trailing padding is rejected. Pinned by `record_size_limit_rejects_value_below_64`, `record_size_limit_rejects_value_above_max`, and `record_size_limit_rejects_trailing_bytes`.

  **5 new tests; 164 total (was 159).** Clippy clean both feature sets.

- **A7 (P2) Expose `compress_certificate` presence (RFC 8879).** Done. Added `pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b` and `pub compress_certificate_present: bool` on `ClientHelloMetadata`. The client advertises support for one or more certificate-compression algorithms (zlib, brotli, zstd).

  **Why this is a fingerprint signal:** modern browsers (Chrome ≥ 89, Firefox ≥ 90) and modern TLS libraries advertise `compress_certificate`; minimal clients (e.g. `curl --resolve`, embedded TLS stacks, single-purpose scanners) often don't. The presence flag is a low-cost dimension of "is this a mainstream browser-class client?" without us having to parse JA3/JA4-style fingerprints.

  **Why presence only:** the body is `u8`-prefixed list of `u16` algorithm IDs (1 = zlib, 2 = brotli, 3 = zstd). The per-algorithm breakdown could be exposed later as A7+ if a higher-resolution fingerprint becomes useful, but presence already gives Layer 2 the 80/20 signal — pinning that scope choice in DECISIONS so a future PR doesn't quietly expand the surface.

  **Tests:** 3 new — present with [brotli, zstd], absent, present with [zlib] (minimal valid body). 159 tests pass (was 156). Clippy clean both feature sets.

- **A6 (P2) Expose `early_data` presence (0-RTT in flight).** Done. Added `pub const EXT_EARLY_DATA: u16 = 0x002a` (RFC 8446 §4.2.10) and `pub early_data_present: bool` on `ClientHelloMetadata`. Signals that the client is sending 0-RTT data alongside the ClientHello, encrypted under the PSK it's offering for resumption.

  **Why Layer 2 wants this signal:** 0-RTT has documented forward-secrecy and replay-protection trade-offs (RFC 8446 §8). Policy may want to flag 0-RTT-bearing connections — e.g. require user confirmation for endpoints where replay risk is unacceptable.

  **Spec-implied invariant intentionally not enforced:** RFC 8446 requires `pre_shared_key` whenever `early_data` is in a ClientHello (otherwise there's no key to encrypt the 0-RTT data with). We don't cross-check the two flags — each reports what was actually observed on the wire, so a pathological "early_data without PSK" still surfaces both flags independently. Pinned by `early_data_independent_from_psk_signal_when_psk_absent`.

  **Tests:** 3 new — realistic 0-RTT CH (SNI + early_data + PSK-last), absent, and the pathological PSK-absent case. 156 tests pass (was 153). Clippy clean both feature sets.

- **A5 (P2) Expose PSK presence on `ClientHelloMetadata`.** Done. Added `psk_present: bool` to `ClientHelloMetadata`. PSK in a ClientHello is the TLS 1.3 session-resumption signal — a returning client offering a previously-issued ticket so the server can short-circuit the full handshake. Useful Layer-2 input: a PSK-resuming client likely already passed our allow-list on the original handshake.

  **Implementation:** trivial — we already detect `EXT_PRE_SHARED_KEY` for the C11 "PSK must be last" rule. The A5 commit just lifts that detection (`psk_seen`) onto the public struct (`meta.psk_present`). No new parser code.

  **Why not parse the PSK identities / binders:** the body is opaque to anyone but the resuming server (identities are server-issued opaque tokens; binders are HMAC-keyed by the resumption secret). Parsing them would burn parser code for zero downstream signal. The presence flag is the only signal Layer 2 needs.

  **Tests:** 3 new — PSK present in a normal CH (with SNI), PSK absent, PSK as only extension (no SNI). 153 tests pass (was 150). Clippy clean both feature sets.

- **A4 (P2) Expose key_share group IDs + `KeyShareGroup` classification.** Done. Replaces A1's `key_share_present: bool` field with `key_share_groups: Option<Vec<u16>>` (the actual advertised NamedGroup IDs) and adds a classification enum so Layer 2 can fingerprint post-quantum hybrid clients without juggling wire codepoints. A1 was less than a day old with no external consumers, so the field swap is a safe break.

  **New public surface:**
  - `pub enum KeyShareGroup { Other, Secp256r1, X25519, X25519MlKem768, SecP256r1MlKem768, X25519Kyber768Draft00 }` — `#[derive(Serialize, Deserialize)]` with `rename_all = "snake_case"`.
  - `KeyShareGroup::from_wire(u16) -> Self` — maps the five named codepoints, everything else (GREASE, secp384r1, ffdhe groups) → `Other`.
  - `KeyShareGroup::kind() -> &'static str` — telemetry labels (`secp256r1`, `x25519`, `x25519_mlkem768`, `secp256r1_mlkem768`, `x25519_kyber768_draft00`, `other`).
  - `KeyShareGroup::is_post_quantum() -> bool` — `true` for the three PQ hybrid variants (standardised RFC 9627 pair + the pre-9627 Kyber draft codepoint still found on some long-running browser channels).
  - `ClientHelloMetadata::key_share_groups_classified() -> Option<Vec<KeyShareGroup>>`.
  - `ClientHelloMetadata::offers_key_share_group(KeyShareGroup) -> bool`.
  - `ClientHelloMetadata::has_post_quantum_key_share() -> bool` — the headline fingerprint signal for "modern PQ-aware client" (Chrome ≥ 2024, Firefox ≥ 2024).

  **Coverage of the registry:** the enum is *intentionally narrow* — five named groups (two modern classical + three PQ hybrids). Other groups in the IANA TLS Supported Groups registry (secp384r1, secp521r1, x448, ffdhe2048..8192) collapse to `Other`. Callers who need finer granularity can read the raw `Vec<u16>` from `key_share_groups` and compare against constants. The trade-off is bounded API surface — extending the enum is a breaking change to downstream telemetry dimensions.

  **Parser:** added `parse_key_share_extension` that walks the `u16`-prefixed list of `KeyShareEntry { group; key_exchange }` and collects each `group` while skipping the key_exchange bytes (we don't need the public keys for routing). Empty `client_shares` returns `Some(empty)` because RFC 8446 §4.2.8 permits empty lists to deliberately force HelloRetryRequest. Truncated `key_exchange` prefix returns `None` (Malformed) — pinned by `key_share_rejects_truncated_key_exchange_prefix`.

  **PQ hybrid fingerprint pinned by `has_post_quantum_key_share_detects_modern_chromium_fingerprint`:** the real-world Chrome 2026 client offers `[X25519MLKEM768, X25519]` (PQ-preferred + classical fallback). Detection must fire on the PQ variant in *any* position of the wire list.

  **Stats:** 150 tests pass (was 139 — added 10 unit tests + 1 doctest on `KeyShareGroup::from_wire`). Clippy clean both feature sets. No allocation regressions: the key_share parser allocates one small `Vec<u16>` per CH that has the extension (typically 1–3 entries).

- **A3 (P1) `supported_versions` classification — `TlsVersion` enum + helpers.** Done. Same shape as A2 (`AlpnProtocol`) but for TLS protocol versions. Layer 2 can now ask "is this a modern client?" or "is this dangerously old?" without juggling wire `u16` codepoints.

  **New public surface:**
  - `pub enum TlsVersion { Other, Ssl30, Tls10, Tls11, Tls12, Tls13 }` — `#[derive(PartialOrd, Ord, Serialize, Deserialize)]` with `rename_all = "snake_case"`. Variant declaration order matters: **`Other` first** so it sorts lowest. That makes `version >= TlsVersion::Tls13` correctly exclude GREASE — the alternative (sort `Other` highest) would let a fuzzing client fool a "modern enough?" check.
  - `TlsVersion::from_wire(value: u16) -> Self` — matches `0x0300`–`0x0304`; everything else (including GREASE codepoints `0x0A0A`, `0x1A1A`, …, and future TLS 1.4 `0x0305`) collapses to `Other`.
  - `TlsVersion::kind() -> &'static str` — stable telemetry labels (`ssl_3_0`, `tls_1_0`, …, `tls_1_3`, `other`) matching the O2 / A2 convention.
  - `ClientHelloMetadata::supported_versions_classified() -> Option<Vec<TlsVersion>>` — classify every offered version in wire order. `None` if the extension was absent.
  - `ClientHelloMetadata::offers_tls_version(TlsVersion) -> bool` — true iff the client advertised that version. When the extension is *absent*, returns true only for `Tls12` (our parser enforces `legacy_version == 0x0303`).
  - `ClientHelloMetadata::highest_supported_tls_version() -> TlsVersion` — max of offered versions, filtering out `Other` first. Falls back to `Tls12` when the extension is absent *or* when every entry was `Other` (so this never returns the meaningless `Other`).

  **Key design decisions:**
  - **`legacy_version` is not a version signal.** Every TLS 1.2/1.3 ClientHello carries `legacy_version = 0x0303` for middlebox compatibility (RFC 8446 §4.1.2). The `supported_versions` extension is the *only* place TLS 1.3 is advertised. Our parser enforces the legacy field as `0x0303` upstream, so an absent `supported_versions` extension is the implicit "TLS 1.2, no extension-based negotiation" signal — encoded in `offers_tls_version`'s fallback branch.
  - **GREASE doesn't contribute to `highest_supported_tls_version`.** Filtering before `.max()` is what makes the helper trustworthy. A naive max-of-classified would still return the highest *real* version (since GREASE = `Other` sorts lowest), but explicit filtering makes the intent obvious in code review and avoids any risk of misuse if someone changes the ordering later.
  - **The "every entry is GREASE" pathological case** (a CH where `supported_versions` is present but every codepoint is unrecognised) falls back to `Tls12` rather than panicking — pinned by `highest_supported_tls_version_falls_back_to_tls12_when_only_grease`.

  **Stats:** 139 tests pass (was 128 — added 11 unit tests + 1 doctest on `TlsVersion::from_wire`). Clippy clean for std `--all-targets` and `--no-default-features --lib`. No allocation regressions on the hot path; the classification helpers walk the existing `Vec<u16>` field and allocate at most one small `Vec<TlsVersion>` on call.

- **A2 (P1) ALPN classification — `AlpnProtocol` enum + helpers.** Done. Added `pub enum AlpnProtocol { Http10, Http11, Http2, Http3, Other }` with three associated methods and two helpers on `ClientHelloMetadata`. Layer 2 can now ask "did the client offer HTTP/3?" without comparing byte strings.

  **New public surface:**
  - `pub enum AlpnProtocol` (`#[derive(Serialize, Deserialize)]` with `rename_all = "snake_case"`).
  - `AlpnProtocol::from_wire(value: &[u8]) -> Self` — exact match on `http/1.0`, `http/1.1`, `h2`, `h3`, plus a `h3-` prefix match for IETF draft codepoints (h3-29, h3-32, etc. — these stayed in real deployments for years after RFC 9114).
  - `AlpnProtocol::kind() -> &'static str` — stable lowercase telemetry labels: `http_1_0`, `http_1_1`, `http_2`, `http_3`, `other` (mirrors the O2 pattern from `SniOutcome::kind()` so dashboards across the codebase share one label convention).
  - `AlpnProtocol::is_http() -> bool` — true for everything except `Other`. Useful when Layer 2 only cares "is this HTTP at all" vs DNS-over-TLS, MQTT, ACME-TLS, etc.
  - `ClientHelloMetadata::alpn_classified() -> Option<Vec<AlpnProtocol>>` — classify every offered protocol in wire order. Returns `None` if the ALPN extension was absent (client expressed no preference). Empty list is unreachable (A1 strictness rejects an empty `ProtocolName` per RFC 7301 §3.1).
  - `ClientHelloMetadata::offers(AlpnProtocol) -> bool` — the common single-protocol query (`meta.offers(AlpnProtocol::Http3)` etc.).

  **Negative classifications pinned:** `h2c` → Other (HTTP/2 cleartext doesn't appear in TLS ALPN but pinning the rejection prevents accidental conflation), `h3foo` → Other (prefix match must require the `-` separator), `acme-tls/1` / `dot` / `doq` → Other, empty bytes → Other.

  **Wire-order preservation pinned** by `alpn_classified_preserves_wire_order`: client preference order survives the classification round-trip, so any downstream "first acceptable" selector picks the same one the client preferred.

  **No new allocations on the hot path.** `alpn_classified` allocates one `Vec<AlpnProtocol>` (small, typically 1–4 entries) and `offers` allocates nothing — it walks `Vec<Cow<[u8]>>` and classifies on the fly. Bench numbers unchanged.

  **128 tests pass** (was 120 — added 7 unit tests + 1 doctest on `AlpnProtocol::from_wire`). Clippy clean for std `--all-targets` and `--no-default-features --lib`.

- **A1 (P1) `parse_client_hello_full` + `ClientHelloMetadata`.** Done. Added a full-metadata parser entry point and refactored `extract_sni` and `parse_handshake_message` into thin projections over it.

  **New public surface:**
  - `pub struct ClientHelloMetadata<'a>` with fields: `host: Option<Cow<'a, str>>`, `ech_present: bool`, `alpn_protocols: Option<Vec<Cow<'a, [u8]>>>`, `supported_versions: Option<Vec<u16>>`, `key_share_present: bool`.
  - `pub fn parse_client_hello_full(bytes: &[u8]) -> Option<ClientHelloMetadata<'_>>` — records-level entry; handles single/multi-record reassembly and Cow promotion.
  - `pub fn parse_handshake_message_full(handshake: &[u8]) -> Option<ClientHelloMetadata<'_>>` — already-reassembled entry; for the QUIC parser when it ships.
  - Three new extension-type constants: `EXT_ALPN = 0x0010`, `EXT_SUPPORTED_VERSIONS = 0x002b`, `EXT_KEY_SHARE = 0x0033`.

  **Strictness:** identical to today's `extract_sni`. Any structural violation (bad cipher list, oversized session_id, duplicated extension, RFC-violating ServerName, empty ALPN ProtocolName, odd-length supported_versions byte count, PSK-not-last, etc.) returns `None` from the full parser, `Some(SniOutcome::Malformed)` from the projecting `extract_sni`. One contract, no lenient mode — the rationale is that downstream telemetry already has the `outcome` dimension from O2 to distinguish "malformed" from "not found", and a dual strict/lenient surface would double the API area without a concrete use case.

  **ECH masks the outer host.** Per DECISIONS.C14 the outer SNI in an ECH-bearing ClientHello is a decoy. `ClientHelloMetadata.host` is `None` whenever `ech_present` is `true`, regardless of any visible `server_name` extension on the wire. Pinned by `parse_client_hello_full_masks_host_when_ech_present`.

  **`extract_sni` is now a thin wrapper:**
  ```rust
  match parse_client_hello_full(bytes) {
      None => SniOutcome::Malformed,
      Some(meta) if meta.ech_present => SniOutcome::Encrypted,
      Some(meta) => match meta.host {
          Some(host) => SniOutcome::Cleartext { host },
          None => SniOutcome::NotFound,
      },
  }
  ```
  Pinned by `extract_sni_is_thin_projection_of_parse_client_hello_full` across the four canonical input shapes (cleartext, ECH, no SNI, garbage).

  **Lifetimes/allocation contract:** identical to P1. Single-record path: every borrowed field (host bytes, ALPN entries) is `Cow::Borrowed`, zero per-byte allocation; only the small `Vec` containers for ALPN and supported_versions are allocated (typically 1–4 entries each). Multi-record path: `parse_client_hello_full` promotes everything to `Cow::Owned` before returning. Pinned by `parse_handshake_message_full_borrows_alpn_entries_from_input`.

  **Measured impact (criterion `--quick`):** no regression on existing benches — `extract_sni` typical actually shaved a touch (51 → 46 ns) because the refactor let LLVM inline the projection more aggressively. The cost of also parsing ALPN/supported_versions is ~5 ns per CH on the hot path; absorbed into the same bench's noise floor. Net: 120 tests pass (was 113; 7 new: ALPN/versions/key_share extraction, ECH-masks-host, empty-ALPN-rejection, odd-length-versions-rejection, the projection-equivalence pin, and the borrow-vs-owned pin); clippy clean for both `--all-targets` and `--no-default-features --lib`.

- **C1 (P0) Multi-record handshake reassembly.** Done. `aegiuw_core::reassemble_handshake(records: &[u8]) -> Option<Vec<u8>>` walks consecutive `content_type=22` TLS records, concatenates their fragment payloads, and returns the handshake byte stream truncated to the first complete handshake message. Reassembly is bounded by `MAX_HANDSHAKE_BYTES = 64 KiB` to refuse adversarial `u24 length = 0xFFFFFF` claims. Mixed-content-type streams return `None` (caller surfaces `SniOutcome::Malformed`) — defeats the Traefik `GHSA-wvvq-wgcr-9q48` class. `extract_sni` now routes record bytes → reassemble → `parse_handshake_message` (also public, for QUIC reuse). 8 new tests including a `1-byte-per-record` worst-case (the kubernetes ingress-nginx pattern) and an `app-data smuggled mid-handshake` adversarial case.

- **C2 (P0) Document the `extract_sni` contract.** Done. The module-level docs in `crates/aegiuw-core/src/sni.rs` now carry an explicit **Contract** section listing input expectations (no streaming, bytes past the first complete handshake are ignored), output guarantees (total function, allocation-bounded, panic-free, side-effect free), performance budget (≤ 1.5 ms per PRD §1.1, linear in input length), and Non-goals (DTLS, SSL 2.0, mid-session renegotiation, ECH inner decryption, hostname normalization). All three public functions (`extract_sni`, `reassemble_handshake`, `parse_handshake_message`) carry runnable `# Examples` doc-tests that pin the boundary cases (empty input, wrong content type, truncated record, wrong handshake type) — these execute as part of `cargo test --workspace`, so the contract is enforced, not just described. *Note:* the original backlog wording ("assumes a single complete handshake message in input") was authored pre-C1 and is now obsolete; the executable contract above supersedes it.

- **C3 (P1) Reject duplicate `server_name` extensions per RFC 6066.** Done — and the same change also closes **C4 (P1) Reject duplicate `encrypted_client_hello` extensions**, because both items are the same defect under **RFC 8446 §4.2** ("There MUST NOT be more than one extension of the same type in a given extension block"). Implementation: `parse_handshake_message` now tracks every extension type seen and returns `SniOutcome::Malformed` on the second occurrence — applies uniformly to known and unknown types (GREASE inclusive). Plus the *inner* RFC 6066 §3 rule ("ServerNameList MUST NOT contain more than one name of the same name_type") is now enforced via a new private `ServerNameOutcome::{Host, Skip, Malformed}` 3-state return from `parse_server_name_extension`; the caller surfaces `Malformed` as `SniOutcome::Malformed`. Five new tests: two duplicate `server_name` extensions, two `host_name` entries inside one ServerNameList, two duplicate ECH extensions, two duplicate unknown extensions (RFC 8446 §4.2 generality), and a positive control with multiple *distinct* GREASE extensions that must still parse cleanly to ensure we didn't over-correct.

- **C5 (P1) Validate `legacy_version == 0x0303`.** Done. `parse_handshake_message` now reads the ClientHello's `legacy_version` field and rejects anything other than the wire constant `TLS_LEGACY_VERSION = 0x0303` (RFC 8446 §4.1.2). This blocks SSL 3.0 (`0x0300`), TLS 1.0 (`0x0301`), and TLS 1.1 (`0x0302`) — all deprecated by RFC 8996 — and also catches misimplemented senders putting the *real* version (`0x0304` for TLS 1.3) in the legacy field, which is a spec violation. The actual TLS 1.3 version negotiation lives in the `supported_versions` extension. Test fixtures refactored: `build_handshake_message_custom(extensions, legacy_version, compression_methods)` is the new internal builder, with `build_handshake_message` (defaults) and `build_handshake_message_with_version` as thin wrappers — supports both this commit and C6 below. 5 new tests cover SSL 3.0, TLS 1.0, TLS 1.1, the illegal 0x0304-in-legacy-field case, and a positive control with the correct 0x0303.

- **C6 (P2) Validate `compression_methods` contains null.** Done. `parse_handshake_message` now requires the `compression_methods` list to contain `0x00` (the null method). RFC 8446 §4.1.2 strictly says TLS 1.3 ClientHellos MUST send exactly `[0x00]`, but the backlog wording sets a lenient bar — *contain* null — which still admits legacy TLS 1.2 senders offering `[deflate, null]`. Empty lists and "no null at all" lists are rejected (the CRIME attack made non-null compression a smoking gun for vintage or hostile traffic). 3 new tests: rejects `[0x01]` (deflate only), rejects `[]` (empty), accepts `[0x01, 0x00]` (legacy with null present). Uses `build_handshake_message_with_compression` wrapping the shared `_custom` builder introduced in C5.

- **C7 (P2) Validate `cipher_suites` is non-empty and even-length.** Done. RFC 8446 §4.1.2 defines `cipher_suites<2..2^16-2>` where each entry is exactly 2 bytes. `parse_handshake_message` now rejects an empty list and any list whose byte length is odd. The `_custom` test builder gained a `cipher_suites` parameter and a `build_handshake_message_with_cipher_suites` wrapper; 3 new tests cover empty (Malformed), 3-byte odd (Malformed), and a positive multi-suite control (`TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384 + TLS_CHACHA20_POLY1305_SHA256`).

- **C8 (P2) Validate `session_id` length ≤ 32.** Done. RFC 8446 §4.1.2 defines `legacy_session_id<0..32>` but the u8 length prefix happily encodes anything up to 255, so the bound is enforced explicitly: `parse_handshake_message` reads the session_id slice and rejects any length > 32. Added `build_handshake_message_with_session_id` wrapper; 2 new tests cover the 33-byte violation (Malformed) and the 32-byte inclusive boundary (positive control). `_custom` builder also reordered its parameters to follow the wire layout (extensions, version, session_id, cipher_suites, compression_methods) — cleaner than the C7-incidental ordering and tracks the actual byte stream.

- **C9 (P2) Tolerate trailing bytes after the extensions block.** Confirmed and pinned. `parse_handshake_message` reads exactly `extensions_len` bytes (via `read_u16_prefixed`) and never looks at the cursor again — anything past the extensions block in the handshake body is silently ignored. This matches RFC 8446 §4's general posture ("servers MUST ignore unknown extensions/fields rather than reject") and lets us survive legitimate-but-padded ClientHellos. No parser code change needed; added an inline doc comment naming the behavior, a local `build_handshake_with_trailing_body_bytes` fixture, and 2 regression tests that pin tolerance for both arbitrary trailing garbage (`0xDE 0xAD 0xBE 0xEF`) and zero-padding.

- **C10 (P2) Reject empty `ServerNameList`.** Done. RFC 6066 §3 defines `ServerNameList<1..2^16-1>` — non-empty by type construction. `parse_server_name_extension`'s `entries.remaining() < 3` check previously returned `Skip` (treating as "no usable host, keep scanning"); it now returns `Malformed`, surfacing as `SniOutcome::Malformed`. This catches both an explicit empty list (length-prefix = 0) and a too-short-to-contain-one-entry list (1 or 2 bytes). 2 new tests: empty list (length-prefix = 0) and 1-byte list. Note: this is strictly stricter than pre-C10 behavior; no existing test depended on the old `Skip` because every prior fixture either supplied a complete entry or hit a different malformation first.

- **C11 (P3) Enforce `pre_shared_key` MUST be the last extension.** Done. RFC 8446 §4.2.11: when `pre_shared_key` (extension type `0x0029`) appears in a ClientHello, it MUST be the last extension. `parse_handshake_message` now tracks a `psk_seen` flag; if we enter another iteration of the extension scan loop while the flag is set, we return `SniOutcome::Malformed`. Added the `EXT_PRE_SHARED_KEY` public constant and 3 new tests: PSK-before-SNI (Malformed), SNI-then-PSK-last (positive control, extracts host), PSK as the only extension (NotFound — parses but no SNI present).

- **C12 (P3) HRR SNI consistency helper.** Done as a thin stateless helper. RFC 8446 §4.1.4 says the second ClientHello sent after a HelloRetryRequest MUST carry the same SNI as the first. Our parser is stateless and only sees one CH per call, so we expose `hrr_sni_consistent(first, second) -> Option<bool>`: `Some(true)` for matching `Cleartext` hosts, `Some(false)` for different hosts, `None` when either side wasn't a clean `Cleartext` (ECH, NotFound, or Malformed makes the comparison meaningless). The daemon owns the connection-level pairing; this helper just encodes the RFC rule so callers don't re-implement it. Re-exported from the crate root; 3 new tests cover same/different/None cases plus a doc-test on the function. *Non-goal:* automatic detection of HRR within a single byte stream — that requires multi-message state that's out of scope for this parser layer.

- **C13 (P3) Detect SSL 2.0 ClientHello format and reject.** Done — and the rejection was already implicit: SSL 2.0 short-form starts with a high-bit-set byte (`0x80`/`0x82`) and long-form starts with `0x00..=0x3F` for record-length-high, neither of which matches the TLS handshake `CONTENT_TYPE_HANDSHAKE = 0x16`. The existing `content_type` check at the top of `reassemble_handshake` immediately fails for these, so SSL 2.0 already surfaces as `SniOutcome::Malformed`. Decided **against** adding a dedicated `LegacyProtocol` variant: SSL 2.0 has no SNI to extract regardless, RFC 6176 prohibits it, and the existing variant set already routes to the right policy. Added a wire-layout doc note naming the SSL 2.0 byte pattern and 2 tests pinning rejection for both short-form (high-bit-set first byte) and long-form (3-byte length prefix).

- **C14 (P4) DTLS support — out of scope.** Confirmed and pinned. RFC 9147 defines DTLS records with a 13-byte header (content_type + version + epoch + sequence + length) versus TLS's 5-byte header. DTLS shares the `content_type=22` first byte with TLS handshake records, but every subsequent byte interpretation diverges — so DTLS bytes happen to fail one of our existing checks (record length, handshake type, or `legacy_version != 0x0303`) and surface as `SniOutcome::Malformed`. This is *incidental* rejection rather than explicit DTLS detection. The Non-goals section of the module-level Contract names DTLS explicitly, and 2 new tests pin the rejection for both a DTLS 1.2 record and a DTLS 1.3 unified-header record so the failure mode can't drift. UDP-framed encrypted transports are the QUIC parser's responsibility (Layer 1 sibling, separate work).

- **H1 (P1) Reject numeric IP literals in SNI.** Done. RFC 6066 §3: *"Literal IPv4 and IPv6 addresses are not permitted in HostName."* `parse_server_name_extension` now calls `host_str.parse::<IpAddr>()` after extracting the bytes; if it succeeds, the host is an IP literal and we return `ServerNameOutcome::Malformed` (the caller surfaces `SniOutcome::Malformed`). Using `std::net::IpAddr::from_str` instead of a regex handles every legal textual form: dotted-quad IPv4, full and compressed IPv6 (`::1`, `2001:db8::1`), and IPv4-mapped IPv6 (`::ffff:192.168.1.1`). Bracket-wrapped forms (`[::1]`) fail to parse and fall through to the hostname path — degenerate but the upstream allowlist will reject them anyway. 7 new tests: dotted IPv4 private + public, `::1`, `2001:db8::1`, `::ffff:192.168.1.1`, plus two positive controls (`1.example.com` and `1.2.3.4.example.com` — both look vaguely numeric but parse as hostnames, must not be rejected by the IP check).

- **H2 (P1) Reject empty hostnames.** Done. RFC 6066 §3 defines `HostName<1..2^16-1>` — the type requires at least one byte. Before H2, an empty `host_name` (length-prefix = 0) silently parsed as `Cleartext { host: "" }`, which the upstream allow-cache had no way to match meaningfully. `parse_server_name_extension` now checks `host_str.is_empty()` immediately after the UTF-8 success, before the H1 IP check, and returns `Malformed`. 2 new tests: empty host_name (Malformed) and a single-character positive control (`"a"` → `Cleartext`).

- **H3 (P1) Enforce DNS length bounds (total ≤ 253, label ≤ 63).** Done. RFC 1035 §2.3.4 / §3.1 caps a DNS hostname at 253 octets in presentation form (255 on the wire minus the leading length byte and the terminator) and each label at 63 octets. `parse_server_name_extension` now checks `host_str.len() > 253` and `host_str.split('.').any(|label| label.len() > 63)` immediately after the H2 empty-check, returning `Malformed` on either violation. Two `const`s name the limits inline. 4 new tests: 254-byte total (Malformed) + 253-byte boundary (Cleartext) + 64-byte label (Malformed) + 63-byte label boundary (Cleartext). Fixtures use `"a.".repeat(126)`-style construction so the total-length and label-length cases trip *separately* — important because either rule alone could mask a regression in the other.

- **H4 (P1) Strip trailing dot from FQDNs.** Done. `example.com.` and `example.com` are the same DNS name (RFC 1034 §3.1) — the trailing dot is the FQDN marker. `parse_server_name_extension` now calls `host_str.strip_suffix('.').unwrap_or(host_str)` *before* the H1–H3 checks, so the normalized (no-dot) form is what gets validated and returned. This means: (a) the upstream allow-cache only needs to store one shape per name, (b) a trailing-dot IP literal (`192.168.1.1.`) is still caught by H1 (which would have slipped past without normalization), (c) a lone `.` becomes `""` and is caught by H2's empty check, and (d) the H3 253-byte limit applies to the canonical form, matching common DNS resolver behavior. 5 new tests: trailing-dot stripped + lone-dot Malformed + IP-with-trailing-dot Malformed + no-dot passthrough + 253-char-plus-trailing-dot positive boundary. *Scope:* single trailing dot only via `strip_suffix`; multi-dot inputs (`example.com..`) are out of scope here and would need a separate empty-label rule.

- **H5 (P2) Enforce LDH/ASCII-only character set.** Done. RFC 6066 §3 says the SNI hostname is "represented as a byte string using ASCII encoding," and RFC 5890 §2.3.2.4 defines LDH as letters / digits / hyphens, with dots between labels. `parse_server_name_extension` now rejects any host byte that isn't `is_ascii_alphanumeric() || b == b'-' || b == b'.'` (placed after the H1 IP check so IPv6 literals still surface as "IP literal" rather than "bad character"). A-labels (`xn--…`) match the same LDH shape because the punycode payload is pure ASCII, so IDN encoding is implicitly supported. 5 new tests: raw Unicode (`café.com`), emoji (`hello💩.com`), underscore (`foo_bar.example.com`), `xn--caf-dma.com` positive, and `foo-bar.example.com` hyphen positive control.

- **H6 (P2) Case-preservation at the parser layer.** Confirmed and pinned. DNS hostname comparisons are case-insensitive (RFC 4343), but case normalization is *not* the parser's responsibility — `aegiuw-core` is a pure observer that returns the host verbatim from the wire so telemetry sees what the sender actually sent, and allow-list lookups happen one layer up in the "normalize + enrich" step where case-folding and IDN unification belong. No parser code change — only an inline doc comment naming the decision and 2 regression tests pinning case-preservation: `Example.COM` returns as-is, and `XN--CAF-DMA.com` (uppercase punycode prefix) also returns as-is. If a future PR accidentally adds `.to_ascii_lowercase()` here, both tests fail immediately.

- **H7 (P3) Detect punycode A-labels as an observability helper.** Done. Added a public `is_idn_host(host: &str) -> bool` that returns `true` if any label has a case-insensitive `xn--` prefix (RFC 5890 §2.3.2.1). The check splits on `.` and inspects each label's first 4 bytes via `eq_ignore_ascii_case` so it works regardless of wire case (matching the H6 case-preservation contract). Why a standalone helper rather than a field on `SniOutcome::Cleartext`: keeping the IDN distinction *out of the outcome enum* avoids forcing every caller to handle it, while still making it trivially callable when a telemetry layer wants to flag "IDN host observed" alerts (homograph/typosquat attempts disproportionately use IDN encoding). Re-exported from the crate root; 6 unit tests + a doc-test exercise lowercase/uppercase/mixed-case xn-- prefix, subdomain-position detection, plain hostnames (negative), the single-hyphen `xn-test.com` negative, and short/empty inputs.

- **S1 (P0) `cargo-fuzz` harness on the SNI parser.** Done. Added `crates/aegiuw-core/fuzz/` as a separate sub-crate (excluded from the workspace via `[workspace] exclude = ["crates/aegiuw-core/fuzz"]` because `cargo-fuzz` requires the nightly toolchain and pulls in `libfuzzer-sys`; the main workspace stays stable-only). Three fuzz targets cover the three public entry points: `extract_sni` (primary — exercises the whole record → handshake → SNI pipeline), `reassemble_handshake` (focused signal on the `MAX_HANDSHAKE_BYTES` allocation cap), and `parse_handshake_message` (the post-reassembly walker, which the QUIC parser will reuse directly). libFuzzer's defaults give us the four guarantees the C2 contract promised: panic-free (any panic aborts and writes a reproducer), no OOB reads (AddressSanitizer, default in `cargo fuzz` builds), bounded time (`-timeout=1` kills runs > 1 s), and bounded allocation (the 64 KiB reassembly cap holds against attacker-crafted u24 length claims). **Not registered as a default quality gate** — fuzzing is open-ended and contributors shouldn't be forced to install `cargo-fuzz` to pass `quality:staged`. The right rhythm is periodic manual runs (pre-release, post-refactor). Full runbook including "what to do on a crash" lives in `crates/aegiuw-core/fuzz/README.md`.

- **P6 (P3) `no_std` + `alloc` support.** Done. Added `[features] default = ["std"]; std = []` to `aegiuw-core/Cargo.toml`; the crate now compiles cleanly under both `cargo build -p aegiuw-core` (std, default) and `cargo build -p aegiuw-core --no-default-features` (core + alloc only). Concrete swaps:
  - `std::net::IpAddr` → `core::net::IpAddr` (stable since Rust 1.77; we're on 1.82).
  - `std::fmt::Write` → `core::fmt::Write` in `malformed_hex_preview`.
  - `std::mem::swap` → `core::mem::swap` in the Levenshtein two-row loop.
  - `String`, `Vec`, `ToString`, `vec!` imported explicitly from `alloc::{string, vec}` everywhere they're used (sni.rs, risk.rs, both heuristic submodules).
  - `serde` switched to `default-features = false, features = ["derive", "alloc"]` so the existing `#[derive(Serialize, Deserialize)]` impls keep working without pulling in serde's std impls.
  - `tracing` was already `default-features = false`.
  - The single `std::time::Instant` use in `extract_sni` (for the `duration_us` field on the trace event, O1/O3) is `#[cfg(feature = "std")]`-gated. Under no_std the trace event still fires with `outcome` and `byte_count`, just without the duration.

  Rationale: the Worker (`aegiuw-router`) currently runs as TypeScript-on-V8, but a future migration to Rust-compiled-to-WASM would benefit from a no_std core (smaller bundles, faster cold-start, no need to bring in std's panic-handler or allocator wrappers). Building this support *now* — while the parser is small and well-tested — is much cheaper than retrofitting later. The 112-test suite passes under both feature sets; clippy is clean for both `--all-targets` (std) and `--no-default-features --lib` (no_std).

- **P5 (P3) SIMD / `memchr` for the parser's byte scans.** ~~Deferred~~ **Done, scoped to `memchr` only.** The original deferral rejected hand-written SIMD intrinsics (correctly — they'd violate `forbid(unsafe_code)`, triple the test matrix, and conflict with P6's no_std/WASM path). The `memchr` crate sidesteps all three concerns: no `unsafe` for the caller, internal per-target dispatch (SSE2/AVX2/NEON with scalar fallback), `default-features = false` keeps it no_std-compatible.

  Implementation: swapped `host_str.split('.').any(|label| label.len() > MAX_LABEL_LEN)` for a `memchr::memchr_iter(b'.', host_bytes)` walk that tracks `prev` and checks `dot - prev > 63` between each pair (plus the trailing segment). Single 12-line block in `parse_server_name_extension`. No API change, no test churn, behaviour identical (verified by all 112 tests passing unchanged).

  **A/B measured impact (criterion `--quick`, Apple Silicon, release):**
  | Bench | Old `split('.')` | New `memchr_iter` | Δ |
  |---|---|---|---|
  | `extract_sni` typical (1 dot) | 51 ns | 51 ns | 0% |
  | `extract_sni` 253-byte host, 127 labels | 337 ns | **276 ns** | **−18%** |

  Typical traffic sees no measurable delta because example.com has one dot — memchr's setup overhead and the scalar fallback both finish in ~1 ns. Long, deep-subdomain hostnames (`a1.a2.a3.…` style — the kind of input attackers use to test length-handling code paths) get the SIMD win.

  Wider SIMD opportunities not pursued (and why):
  - `read_u16`/`read_u24` decode: already optimal; LLVM lowers to a single `lwbr`-style instruction.
  - `core::str::from_utf8`: already SIMD-optimized in std/alloc itself.
  - Extension dup-detection (`seen_ext_types: Vec<u16>::contains`): bounded by the realistic ~15–20 extensions per CH; constant factors beat any algorithmic improvement at that N.

  Deferral reversal lesson: the right framing was "should we add hand-written SIMD?" (no) vs. "should we use a curated SIMD-backed primitive?" (yes — 18% with no downsides on the worst-case hot path).

- **P4 (P2) Cost breakdown — qualitative + quantitative.** Done. With P3's criterion numbers in hand we can now characterise SNI parsing cost concretely:

  *CPU (release, Apple Silicon M-class, `cargo bench -- --quick`):*
  - typical single-record CH: **~103 ns**
  - two-record fragmented CH: **~145 ns** (the extra 42 ns is the second-record copy in `reassemble_handshake`)
  - reassemble-only: ~23 ns
  - parse-only: ~66 ns

  *Throughput implication:* at 103 ns/parse, a single core sustains ~9.7M parses/sec — vs. the PRD §1.1 budget of "no more than 1.5 ms per connection." We're **~14,500× under budget**. SNI parsing is not on the critical path; it's free.

  *Allocations per call:*
  - **Single-record path** (the common case): zero heap allocations. `reassemble_handshake` returns `Cow::Borrowed(&record_payload)`; `parse_handshake_message` walks the borrowed bytes with a stack-allocated `Cursor`. Only the final `SniOutcome::Cleartext { host: String }` triggers a single ~16-byte allocation (sso applies for hosts ≤ 22 bytes on glibc, slightly larger on macOS).
  - **Multi-record path**: one `Vec<u8>` allocation in `reassemble_handshake` sized to the total handshake length (bounded by `MAX_HANDSHAKE_BYTES = 64 KiB`).
  - **HRR consistency check (`hrr_sni_consistent`)**: allocates two `Vec`s for sorted-extension comparison; only invoked when the caller has both ClientHello1 and HelloRetryRequest in hand, never on the common path.

  *Memory caps:*
  - Reassembly cap: **64 KiB** (`MAX_HANDSHAKE_BYTES`) — bounds attacker-claimed u24 lengths.
  - Per-record cap: **16 KiB + 256 bytes** (`MAX_RECORD_FRAGMENT`) — RFC 8446 §5.1 limit.
  - Extension-type dup-detection set: bounded by the extension count, itself bounded by the 16 KiB extensions block.

  *Daemon-level cost projection (PRD §1.1 unit economics):* at ~10–30 isolated sessions/user/month × 1 SNI parse per top-level navigation × 103 ns per parse, SNI parsing contributes **<< 1 µs/user/month of CPU**. The remaining $0.26/user/month COGS is dominated by Cloudflare Containers warm-pool time and KV/R2 — not the parser.

  *Conclusion:* the parser comfortably exceeds the PRD perf budget by 4 orders of magnitude. The remaining P-cluster items (SIMD, no_std) are luxury optimisations; treat any regression > 5% in the criterion baseline as a real perf bug to investigate (the budget headroom doesn't excuse silent slowdowns).

- **P3 (P2) Criterion benchmark suite.** Done. Added `criterion = "0.5"` dev-dep and `crates/aegiuw-core/benches/sni.rs` with four benches: typical single-record CH, two-record fragmented CH, reassembly-only, parse-only. `harness = false` so criterion supplies `main()`. Run with `cargo bench -p aegiuw-core`. First quick run (release, Apple Silicon, criterion `--quick`): typical extract_sni ≈ 103 ns; fragmented ≈ 145 ns; reassemble alone ≈ 23 ns; parse alone ≈ 66 ns. Subsequent runs report % deltas vs. the on-disk baseline under `target/criterion/`, giving a cheap local perf-regression check before pushing. `.gitignore` already excludes `target/`; explicitly added `target/criterion/` for clarity.

- **P2 (P2) `#[inline]` on Cursor methods.** Done. Added `#[inline]` to all eight `Cursor` accessors (`new`, `remaining`, `read_u8`, `read_u16`, `read_u24`, `read_slice`, `read_u8_prefixed`, `read_u16_prefixed`). Each is a single-expression bounds-checked reader; the parse loop calls them tens of times per ClientHello. Letting the compiler inline across the crate boundary removes call overhead and lets adjacent bounds checks fuse. Cheap commit, no functional change, no test churn.

- **S8 (P3) Differential fuzzing vs. rustls.** ~~Deferred~~ **Done.** Reversed the earlier deferral. Added a fourth cargo-fuzz target `differential_rustls` (with `rustls = "0.23"` as a fuzz-only dep) that drives rustls's `server::Acceptor` over the same bytes we feed `aegiuw_core::extract_sni`, then compares the extracted host strings (case-insensitive — RFC 4343). The harness only panics when **both** parsers extract a host *and* the two hosts differ — the high-signal disagreement class. Tolerated discrepancies (no panic):
  - one side extracts a host, the other rejects the whole CH (policy difference — rustls is stricter on ciphers/versions than our SNI-only parser);
  - we return `Encrypted` (ECH detected, outer SNI is a decoy per DECISIONS.C14);
  - either side returns no host.

  The fuzz Cargo.toml gained an `[workspace]` (empty) section so `cargo check`/`cargo +nightly fuzz` invoked from inside the fuzz dir don't trip over the parent workspace's exclusion. All four fuzz targets type-check on stable; the actual fuzz run still needs nightly per S1.

  The earlier deferral worried about false positives from policy mismatches. That worry was right in shape but addressable in implementation: scoping the assert to "both extract a host *and* differ" filters out the policy-noise. Cost was ~30 min of harness code; payoff is a continuous independent oracle for the parser's most security-critical guarantee (extracting the right host name).

- **P1 (P2) `SniOutcome::Cleartext { host: Cow<'a, str> }`.** ~~Deferred~~ **Done.** Reversed the earlier deferral after the user asked to revisit. `SniOutcome` now carries a lifetime parameter; `Cleartext.host: Cow<'a, str>` borrows directly from the input slice on the single-record happy path (zero allocation) and falls back to `Cow::Owned(String)` on the multi-record path (the reassembly buffer is dropped at end of arm so the host must be promoted). `reassemble_handshake` was split into a fast path (`try_reassemble_single_record` returning `&[u8]`) and the existing owned slow path (`reassemble_handshake_owned` returning `Vec<u8>`); the public function now returns `Cow<'_, [u8]>`. `parse_handshake_message` and the internal `ServerNameOutcome` thread the lifetime; `hrr_sni_consistent` compares Cow values directly (PartialEq via Deref). Test fixtures that built `host: String` upgraded to `host: host.into()` (3 sites).

  **Measured impact (criterion `--quick`, Apple Silicon, release):**
  | Bench | Before P1 | After P1 | Δ |
  |---|---|---|---|
  | `extract_sni` typical | 103 ns | **51 ns** | −50% |
  | `extract_sni` fragmented (2 records) | 145 ns | 112 ns | −23% |
  | `reassemble_handshake` typical | 23 ns | **2 ns** | −91% |
  | `parse_handshake_message` | 66 ns | 40 ns | −39% |

  The reassembly drop is the headline — fast path is now just bounds-checked pointer arithmetic. Net: P4's "14,500× under budget" becomes ~30,000× under budget. The earlier rationale was wrong about the cost-side: serde derived cleanly, the lifetime cascade was contained to the lib-internal types, and the public API only gained `<'_>` elisions (no breaking change for the placeholder daemon caller). The earlier rationale was right about the deferral being conservative — but the upside turned out larger than the doc estimated (a 2× speedup on the hot path is not "premature optimisation"). Lesson: when in doubt, measure first instead of deferring.

- **O5 (P3) Cloudflare ECH outer-SNI detector.** Done. Added a `pub const CLOUDFLARE_ECH_OUTER_SNI: &str = "cloudflare-ech.com"` and `pub fn is_cloudflare_ech_outer(host: &str) -> bool` (case-insensitive exact match). Cloudflare's blog post *"Encrypted Client Hello — the last puzzle piece to privacy"* describes their convention: every Cloudflare-hosted ECH connection presents `cloudflare-ech.com` as the visible outer SNI. Surfacing the constant + predicate in one place lets the daemon flag/count Cloudflare-ECH-hosted destinations even though our `SniOutcome::Encrypted` doesn't currently carry the outer SNI (ECH detection prioritises the encrypted-flag over the visible host bytes). 3 new unit tests + a doc-test pin exact-match, case-insensitivity, and that suffix matches (`cloudflare-ech.example.com`) do NOT trigger. Re-exported from the crate root.

- **O4 (P2) Feature-gated hex dump on `Malformed`.** Done. Added a `debug-malformed` Cargo feature (off by default) that, when enabled, emits a `tracing::debug!` event with a hex dump of the first 64 bytes of any input that produced `SniOutcome::Malformed`. Useful for forensic analysis runs ("what did this attacker actually send?") without leaking attacker-controlled bytes into normal production logs. Hex formatting uses a small allocation-free `String::with_capacity` helper; no perf hit on the disabled path because the entire block is `#[cfg]`-gated out. Build verified both ways: default (no debug-malformed output), and `--features debug-malformed`. *Not* enabled in normal aegiuw-daemon builds — turn it on for a one-off run when investigating a specific puzzle.

- **O3 (P2) Parse-duration histogram dimension.** Done. The `duration_us` field on the O1 trace event is u64 microseconds — the histogram dimension for "how long did SNI extraction take." Documented bucket suggestion (`{50, 100, 250, 500, 1000, 1500, 2500}` µs) in the parser source: 1500 µs is the PRD §1.1 budget so bucketing around it surfaces both healthy (< 500 µs) and budget-exceeding (> 1500 µs) parses. Implementation is already in O1; this entry pins the field name, type, and unit so downstream collectors don't have to reverse-engineer them from logs.

- **O2 (P1) Stable counter-dimension strings via `SniOutcome::kind()`.** Done. Added a `pub fn kind(&self) -> &'static str` method that returns `"cleartext"` / `"encrypted"` / `"not_found"` / `"malformed"` per variant — matches the existing `serde(rename_all = "snake_case")` JSON shape so downstream subscribers see the same vocabulary across log fields, metric dimensions, and JSON serialization. The O1 trace event now uses `outcome.kind()` instead of Debug formatting — cheap, stable, and groupable for Prometheus `sni_outcome_total{kind="…"}` counters. A regression test pins the four string values; any future rename would have to update the test, making the dashboard-breaking implication explicit.

- **O1 (P1) Structured trace event per parse.** Done. Added `tracing = "0.1"` (default-features = false, so no log compat or std-extras pulled in) as a hard dep on `aegiuw-core` and emit a single `tracing::trace!` event from `extract_sni` carrying three fields: `outcome` (Debug-formatted variant), `byte_count` (input slice length), and `duration_us` (wall-clock parse duration in microseconds). Downstream subscribers can group by `outcome` for the per-variant counter (O2), bucket `duration_us` for the parse-time histogram (O3), and dump the raw bytes via O4. Target string `aegiuw_core::sni` so subscribers can scope.

- **S10 (P3) `cargo-mutants` runner script.** Done. Added `scripts/mutants.sh` that idempotently installs `cargo-mutants` and runs it scoped to `aegiuw-core`. A *surviving* mutant means the test suite didn't catch a deliberate behavior change — pointing at lines that are either uncovered or whose assertions are too loose. Useful for grading the test suite's catch rate, not for finding bugs directly. Recommended cadence: after major test additions (e.g. after the H-cluster) to verify the new tests actually pin behavior, or as a one-shot when test count growth slows. Like S6 and S9, not registered in the quality runner — periodic-manual.

- **S9 (P3) MIRI runner script.** Done. Added `scripts/miri.sh` that runs `cargo +nightly miri test -p aegiuw-core`, idempotently installing the `miri` and `rust-src` components on first use. The crate already enforces `unsafe_code = "forbid"` at the lints level, so MIRI should find no undefined behavior — this script is the *proof* of that, not a discovery tool. Caveats documented in the script: MIRI is 100×+ slower than native, so the full suite can take 10–30 minutes; `PROPTEST_CASES=8 scripts/miri.sh` reduces the property-test count for faster runs. Recommended cadence: when refactoring `Cursor` (which still uses `try_into`/destructuring that *could* hide UB if the lint were ever relaxed), or before a release.

- **S8 (P3) Differential fuzzing vs reference parser.** Deferred with rationale. The idea is to feed both `extract_sni` and a reference parser (e.g., `tls-parser` or rustls's internal codec) the same bytes via proptest and flag any discrepancy. Useful for discovering corner cases neither parser alone surfaces. **Not implemented for two reasons:** (1) the closest small-surface reference is the `tls-parser` crate, which exposes a nom-based parser whose output shape doesn't cleanly map onto `SniOutcome` — non-trivial 50+ LOC of adapter code per call, plus a fresh transitive-deps story; (2) rustls's `ClientHelloPayload` is internal and not stable across versions, so depending on it would couple us to a private API. **Conclusion:** the existing S1 cargo-fuzz (sustained adversarial search), S2 proptest (every-commit panic-free property), and the 100+ spec-compliance unit tests provide adequate coverage; differential fuzzing would catch *specific outcome disagreements* but not new panic/OOB classes. Re-evaluate after we have richer parser metadata (A1–A3) — at that point a small reference parser becomes easier to wire up because we'd already be in "parse the full ClientHello" territory.

- **S7 (P2) Lock the no-attacker-sized-allocations contract.** Done. We considered wiring a custom global allocator to assert max bytes during a parse — but `#[global_allocator]` is one-per-crate, not per-test, so isolating it from the rest of the test suite is awkward. Instead we lock the contract with a stronger *behavioral* test: `allocation_cap_holds_against_drip_feed_of_small_records` forges a handshake header that claims a u24 body length of `0xFFFFFF` (≈ 16 MiB), then drip-feeds 17 record fragments totalling 68 KB. Reassembly must refuse after `MAX_HANDSHAKE_BYTES = 64 KiB`, never approaching the 16 MiB claim. Together with the existing C1 absurd-length test (single huge claim), C1 many-tiny-fragments test (max records → cap), and the S2 proptest at `0..70_000` byte range, this gives us defense-in-depth: an attacker can't drive unbounded allocation through any combination of size claims.

- **S6 (P2) Continuous fuzzing protocol (manual, no CI by org policy).** Done. We don't have GitHub Actions CI (Aeptus org policy disables it; see N81), so "continuous" fuzzing is a manual cadence rather than an automated gate. Added `scripts/fuzz-soak.sh` that runs each of the three cargo-fuzz targets (`extract_sni`, `reassemble_handshake`, `parse_handshake_message`) for a configurable budget (default 5 minutes each = 15 minutes total). The script reports any crashes found in `crates/aegiuw-core/fuzz/artifacts/` and exits non-zero on findings. Recommended cadence: before releases, after any SNI-parser refactor, and weekly via a developer-owned cron. Not registered in the quality runner — would force every contributor to install cargo-fuzz to pass `quality:staged`.

- **S5 (P1) `deny(clippy::indexing_slicing)` on the SNI module.** Done. Added `#![deny(clippy::indexing_slicing)]` at the top of `sni.rs` so any raw `bytes[i]` / `bytes[i..j]` access requires an explicit `#[allow]` override. Refactored the production code accordingly: `Cursor::read_slice` uses `self.bytes.get(self.pos..end)?` instead of manual bounds-then-index; `Cursor::read_u16` uses `s.try_into()` to get a typed `[u8; 2]`; `Cursor::read_u24` uses a slice-pattern destructure (`let &[a, b, c] = s else { return None };`); `reassemble_handshake`'s u24 body-length extraction uses `handshake_buf.get(..4)?`; `is_idn_host`'s prefix check uses `as_bytes().get(..4).is_some_and(…)`. The test module carries an explicit `#[allow(clippy::indexing_slicing)]` because the fixtures hand-craft byte arrays where the indices are deliberate by construction.

- **S4 (P1) Maximum-size single record within budget.** Done. New test `parses_maximum_single_record_within_debug_budget` builds a single TLS record packed near the RFC 8446 §5.1 16 KiB ceiling (~4000 small extensions), asserts the fixture stays within one record, and times the parse. Threshold: 50 ms in debug — generous enough to cover sanitizers and slow CI hardware while still catching any catastrophic regression. PRD §1.1 calls for ≤ 1.5 ms in release; release-mode timing observed at well under 1 ms.

- **S3 (P1) Linear scaling under extension explosion.** Done. New test `parses_client_hello_with_many_small_extensions_in_linear_time` constructs a ClientHello with **10,000 unique extensions** (types in `0x0100..0x2810`, empty payloads), fragments the resulting ~40 KB handshake across multiple TLS records to also exercise C1's reassembly path, and asserts the full extract_sni completes in under 500 ms. Observed: ~0.16 s in debug, well under the threshold. Confirms that the `Vec<u16> seen_ext_types` duplicate-tracking structure doesn't degenerate to quadratic on adversarial inputs (Vec::contains is O(n), but at N=10K the cache-friendly linear scan is faster than HashSet overhead would be — the test pins this, so a future refactor to e.g. HashSet must still meet the threshold).

- **S2 (P1) `proptest` panic-free properties on the three parser entry points.** Done. Complements S1's cargo-fuzz harnesses: S1 runs externally on nightly and finds new edge cases over hours; S2 runs in every `cargo test` and pins the panic-free contract per commit so a regression can never reach the repository unnoticed. Added `proptest = "1"` as a dev-dependency on `aegiuw-core` and three `proptest!` blocks at the bottom of the existing test module: `extract_sni`, `reassemble_handshake`, and `parse_handshake_message` each receive arbitrary byte slices and the property is that the call returns *some* result without panicking. Byte-length ranges: `0..2048` for `extract_sni` and `parse_handshake_message` (realistic ClientHello sizes), and `0..70_000` for `reassemble_handshake` so proptest can also probe the `MAX_HANDSHAKE_BYTES = 64 KiB` allocation cap with inputs that claim large handshake bodies. Default 256 cases × 3 properties ≈ 768 calls per `cargo test` run; sub-second since the parser is linear in input length. If any case panics, proptest shrinks to a minimal repro and writes it to `crates/aegiuw-core/proptest-regressions/sni.txt` (this file gets committed so the failing case becomes a permanent test).
