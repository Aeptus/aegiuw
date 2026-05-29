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

- **S5 (P1) `deny(clippy::indexing_slicing)` on the SNI module.** Done. Added `#![deny(clippy::indexing_slicing)]` at the top of `sni.rs` so any raw `bytes[i]` / `bytes[i..j]` access requires an explicit `#[allow]` override. Refactored the production code accordingly: `Cursor::read_slice` uses `self.bytes.get(self.pos..end)?` instead of manual bounds-then-index; `Cursor::read_u16` uses `s.try_into()` to get a typed `[u8; 2]`; `Cursor::read_u24` uses a slice-pattern destructure (`let &[a, b, c] = s else { return None };`); `reassemble_handshake`'s u24 body-length extraction uses `handshake_buf.get(..4)?`; `is_idn_host`'s prefix check uses `as_bytes().get(..4).is_some_and(…)`. The test module carries an explicit `#[allow(clippy::indexing_slicing)]` because the fixtures hand-craft byte arrays where the indices are deliberate by construction.

- **S4 (P1) Maximum-size single record within budget.** Done. New test `parses_maximum_single_record_within_debug_budget` builds a single TLS record packed near the RFC 8446 §5.1 16 KiB ceiling (~4000 small extensions), asserts the fixture stays within one record, and times the parse. Threshold: 50 ms in debug — generous enough to cover sanitizers and slow CI hardware while still catching any catastrophic regression. PRD §1.1 calls for ≤ 1.5 ms in release; release-mode timing observed at well under 1 ms.

- **S3 (P1) Linear scaling under extension explosion.** Done. New test `parses_client_hello_with_many_small_extensions_in_linear_time` constructs a ClientHello with **10,000 unique extensions** (types in `0x0100..0x2810`, empty payloads), fragments the resulting ~40 KB handshake across multiple TLS records to also exercise C1's reassembly path, and asserts the full extract_sni completes in under 500 ms. Observed: ~0.16 s in debug, well under the threshold. Confirms that the `Vec<u16> seen_ext_types` duplicate-tracking structure doesn't degenerate to quadratic on adversarial inputs (Vec::contains is O(n), but at N=10K the cache-friendly linear scan is faster than HashSet overhead would be — the test pins this, so a future refactor to e.g. HashSet must still meet the threshold).

- **S2 (P1) `proptest` panic-free properties on the three parser entry points.** Done. Complements S1's cargo-fuzz harnesses: S1 runs externally on nightly and finds new edge cases over hours; S2 runs in every `cargo test` and pins the panic-free contract per commit so a regression can never reach the repository unnoticed. Added `proptest = "1"` as a dev-dependency on `aegiuw-core` and three `proptest!` blocks at the bottom of the existing test module: `extract_sni`, `reassemble_handshake`, and `parse_handshake_message` each receive arbitrary byte slices and the property is that the call returns *some* result without panicking. Byte-length ranges: `0..2048` for `extract_sni` and `parse_handshake_message` (realistic ClientHello sizes), and `0..70_000` for `reassemble_handshake` so proptest can also probe the `MAX_HANDSHAKE_BYTES = 64 KiB` allocation cap with inputs that claim large handshake bodies. Default 256 cases × 3 properties ≈ 768 calls per `cargo test` run; sub-second since the parser is linear in input length. If any case panics, proptest shrinks to a minimal repro and writes it to `crates/aegiuw-core/proptest-regressions/sni.txt` (this file gets committed so the failing case becomes a permanent test).
