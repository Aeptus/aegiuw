# Product Requirement Document (PRD)

**Project Codename:** Project Aegiuw (Version 2.5) — repository name **Aegiuw**
**Document Status:** Production Ready
**Licensing Model:** Core Engine (AGPL-3.0-or-later) + Commercial Extension (proprietary SaaS Layer)
**Target Unit Economics:** End-User Price: $1.30 / user / month | Target COGS: $0.26 / user / month | PTIVR (Profit Margin): 80%

> This document is the canonical source for the requirement IDs (`FR-*`, `CR-*`,
> `NFR-*`) referenced throughout the codebase. Code stubs cite these IDs so the
> spec and implementation stay traceable.

---

## Section 1: System Architecture & Components

Project Aegiuw splits the compute and security verification pipelines into three
distinct architectural layers to maximize local device performance and utilize
Cloudflare's serverless edge.

### 1.1 Local End-User Daemon (`aegiuw-daemon`)

- **Technical Stack:** Native Rust (compiled for x86_64 and ARM64 across Windows, macOS, Linux).
- **System Privilege:** Persistent background daemon (systemd on Linux, launchd on macOS, Windows Service on Windows) with elevated network configuration privileges.
- **Network Hooking Mechanism:** Instantiates a native Virtual Network Interface (TUN loopback driver). The daemon configures host OS routing tables to push all outbound port 443 (HTTPS) traffic through this virtual interface.
- **Sub-Millisecond Parsing Engine:**
  - Inspect the initial raw TCP packets of any outbound request to extract the Server Name Indication (SNI) header from the unencrypted TLS Client Hello payload.
  - Parsing must complete in ≤ 1.5 ms.
- **The Fork Logic:**
  - **Condition A (Native Path):** If the extracted domain exists in the local cryptographically signed `allowed_cache.json`, the daemon transparently bridges the TCP stream directly to the physical NIC. The native browser establishes a normal connection.
  - **Condition B (Isolate Path):** If the domain is unknown, newly registered, or flags heuristic risks, the daemon intercepts the connection, drops the native packets, and marshals the target URL into an encrypted HTTPS POST stream forwarded to the Cloudflare Worker interface.

### 1.2 Serverless Edge Router (`aegiuw-router`)

- **Technical Stack:** Cloudflare Workers on V8 Isolate infrastructure, TypeScript.
- **Routing Logic:** Stateless traffic controller. Ingests requests from `aegiuw-daemon`, appends telemetry, reads the organization's rules out of Cloudflare KV, and orchestrates session deployment via the Cloudflare Browser Run API.

### 1.3 Ephemeral Secure Sandbox Container (`aegiuw-cage`)

- **Technical Stack:** Cloudflare Browser Run API + custom V8-compiled KasmVNC pipeline.
- **Mechanism:** Spins up an instant, headless instance of Chromium inside a stateless Cloudflare Container.
- **State Isolation:** Completely blank profile block. Zero visibility into the host machine's cookie files, saved tokens, local storage, or historical browser fingerprints.

---

## Section 2: Functional Requirements (Open Source Engine)

### 2.1 Developer Installation & Setup Simplicity

- **FR-1.1 (Single-Command Infrastructure Deployment):** The repository must include a pre-configured, production-ready `wrangler.jsonc`. Open-source users deploy the full edge routing infrastructure to their personal Cloudflare accounts via `wrangler deploy`.
- **FR-1.2 (Local Agent Bootstrapping):** Distributable via native package managers:
  - macOS: `brew install aegiuw/tap/aegiuw-daemon`
  - Linux/Windows: `cargo install aegiuw-daemon`

### 2.2 Local Dynamic Risk Engine (No-API Heuristics)

To prevent the "Cold Start Whitelist Trap" (thousands of safe sites blocked), the
Rust agent runs localized mathematical heuristics in parallel:

- **FR-2.1 (Levenshtein Distance Check):** Check the SNI domain string against a localized dictionary of the world's top 10,000 corporate domains and the company's internal domains. If the target domain has a Levenshtein edit distance ≤ 2 relative to a primary brand (e.g. `micr0soft.com`, `paypa1-security.com`), it fails validation.
- **FR-2.3 (Context Application Tracking):** Query the OS process tree to identify the Parent Process ID (PPID) that triggered the outbound web call. If the request originated from an email application (Outlook, Apple Mail) or a document reader (Adobe Acrobat) AND the target domain is not in the local safe cache, the link is categorized as high-risk.

### 2.3 Visual Stream & The Read-Only Lockout Interface

- **FR-3.1 (Vector Graphical Compression):** The Worker captures graphical layout updates of the headless browser container, compresses them into structural HTML5 drawing coordinates, and pipes them securely over local WebSockets back to a lightweight Webview container frame on the user's desktop.
- **FR-3.2 (The Automated Keyboard Disconnect):** The background script inside the container monitors the DOM. If an unverified domain renders input fields matching credential-harvesting attributes (e.g. `<input type="password">` or forms tracking email string inputs):
  - **Enforcement:** the worker cuts the data-transmission pipeline for the keyboard event listeners mapped to that session window.
  - **UX:** the page remains visually interactive (mouse + click), but the user is blocked from typing or pasting into those text fields. No credential payload can transmit back to the attacker's server.
- **FR-3.3 (State Vaporization):** Closing the local webview tab immediately sends an asynchronous termination payload to the Worker, destroying the active container instance and clearing all volatile RAM.

---

## Section 3: Commercial Subscription Infrastructure (Aegiuw-Enterprise)

A decoupled layer managing monetization, automated token authentication, and
infrastructure scaling for customers on the managed $1.30/user/month subscription.

### 3.1 Edge Cryptographic Billing Engine

Uses Asymmetric Web Crypto Verification at the Edge to avoid database round trips.

```
[ Local Rust Daemon ] ──(Presents Device JWT)──► [ Aegiuw Commercial Cloud Worker ]
                                                          │
                   ┌──────────────────────────────────────┴───────────────────────────┐
                   ▼ (Signature Valid & Under Seat Cap)                                 ▼ (Signature Fails / Expired)
     [ Boot Warm Container Pool ]                                          [ Serve 403 Payment Required Screen ]
    (Via Cloudflare Durable Objects)
```

- **CR-1.1 SaaS Seat Enforcement (Hardware-Bound JWTs):**
  - **Registration Pipeline:** On seat purchase via website checkout (Stripe Billing Gateway), an automated backend worker maps an Organization ID to an asymmetric public signing key pair.
  - **Device Token Claim:** On corporate installation, the Rust daemon generates a unique local hardware fingerprint by hashing the motherboard UUID, CPU serial sequence, and Organization ID.
  - **Verification Execution:** Each isolate call includes a short-lived (60-second expiry) JWT signed locally by the host machine.
  - **Sub-Millisecond Clearance:** The commercial Worker validates the signature via `crypto.subtle.verify` against the customer's public key in global memory. If the signature matches, the timestamp is valid, and the hardware hash is registered within the company's Stripe seat limit, the sandbox opens.
- **CR-1.2 Self-Hosted Threat Feed Paywall (The Intel Sync):**
  - **Encrypted Storage Bucket:** A master Cloudflare KV database holds real-time zero-hour definitions of active AitM phishing proxy networks, encrypted with a rotating daily symmetric key.
  - **Sync Cron Task:** A Cron Trigger on the customer's self-hosted worker queries `https://api.aegiuw.security/v1/intel-sync` every 10 minutes.
  - **Gatekeeper Verification:** The licensing worker checks the license token against the active Stripe billing registry. If paid, it returns the current day's decryption key; if unpaid/delinquent, it returns `403 Forbidden`, causing the client to fall back to basic local Levenshtein formulas.

### 3.2 Enterprise Scaling & Extension Capabilities ("The Superpowers")

- **CR-2.1 (Durable Object Warm-Pooling):** Standard Cloudflare accounts cap concurrent Browser Run containers at 120. The commercial layer routes through Durable Objects that multiplex a pre-warmed pool of browser threads, bringing container execution delays to `<300ms`.
- **CR-2.2 (Residential Proxy Masquerading):** Masks the sandboxed browser's profile and routes outbound container traffic through automated residential proxy loops to avoid CAPTCHAs / Turnstile. *(Requires legal/ToS review before shipping.)*
- **CR-2.3 (Automated Stripe Webhook Sync):** An independent webhook handler listens for Stripe webhooks (`invoice.payment_failed`, `customer.subscription.deleted`) and instantly modifies the customer's cryptographic activation status in global Cloudflare KV, enforcing immediate system-wide deactivation for delinquent accounts.
- **CR-2.4 (SIEM/SOC Telemetry Log Streaming):** The commercial router pipes structured event JSON streams to customer security infrastructure (Splunk, Datadog, AWS S3) for enterprise audit tracking and incident response.

---

## Section 4: Non-Functional Requirements & Compliance

- **NFR-4.1 (Performance Budget):** Safe domains routed natively through the local virtual TUN interface must face an additive network latency tax of `<15ms`.
- **NFR-4.2 (Data Sovereignty Boundary):** Routing must enforce Cloudflare's Regional Services rules. For EU endpoints, all container executions, worker processes, and volatile memory allocations must reside strictly within EU-based data centers (GDPR).

---

## Section 5: Architecture Platform Blueprint

The open-source repository ships with the `wrangler.jsonc` bindings to Cloudflare's
serverless edge primitives (Browser Run, KV whitelist cache, R2 quarantine vault).
See [`workers/aegiuw-router/wrangler.jsonc`](../workers/aegiuw-router/wrangler.jsonc).
