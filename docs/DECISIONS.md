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
