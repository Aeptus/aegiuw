// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * aegis-router — the stateless edge traffic controller (PRD §1.2).
 *
 * Responsibilities (most still TODO at this scaffold stage):
 *  - ingest isolate requests from `aegis-daemon` (Condition B, §1.1),
 *  - read org rules from KV (`LOCAL_SAFE_CACHE`),
 *  - boot an ephemeral blank-profile sandbox via the Browser Rendering binding
 *    (`AEGIS_CAGE`, §1.3),
 *  - stream the rendered page read-only to the local viewer and sever typing on
 *    credential fields (FR-3.1 / FR-3.2),
 *  - vaporize the container on disconnect (FR-3.3).
 */

/** Bindings declared in `wrangler.jsonc`. Regenerate richer types with `wrangler types`. */
export interface Env {
  /** Browser Rendering binding — the ephemeral Chromium sandbox (aegis-cage, §1.3).
   *  Typed loosely until `@cloudflare/puppeteer` is added with the sandbox impl. */
  AEGIS_CAGE: Fetcher;
  /** Allow-list / threat-intel cache (FR-1, CR-1.2). */
  LOCAL_SAFE_CACHE: KVNamespace;
  /** Quarantine vault for downloaded files before host exposure. */
  DOWNLOAD_SCRUBBER: R2Bucket;
}

/** Payload the daemon POSTs to `/isolate` when a domain takes the Isolate Path. */
interface IsolateRequest {
  /** The full target URL the user attempted to reach. */
  url: string;
  /** The risk level the local engine assigned (mirrors aegis-core `RiskLevel`). */
  riskLevel?: "unknown" | "suspicious" | "high_risk";
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Boot a sandbox session for an untrusted URL. Stubbed: validates the request and
 * returns 501 until the Browser Rendering pipeline lands.
 */
async function handleIsolate(request: Request, _env: Env): Promise<Response> {
  let payload: IsolateRequest;
  try {
    payload = (await request.json()) as IsolateRequest;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  if (typeof payload.url !== "string" || payload.url.length === 0) {
    return json({ error: "missing_url" }, 400);
  }

  // TODO(FR-3): use env.AEGIS_CAGE to launch a blank-profile headless Chromium,
  // navigate to payload.url, install the DOM mutation observer that severs keyboard
  // event transmission on credential fields (FR-3.2), and open a WebSocket to
  // screencast the rendered page back to the local viewer (FR-3.1). On socket close,
  // destroy the container (FR-3.3).
  return json(
    {
      error: "not_implemented",
      detail: "sandbox isolation pipeline not yet built (FR-3.x)",
      received: { url: payload.url, riskLevel: payload.riskLevel ?? "unknown" },
    },
    501,
  );
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const route = `${request.method} ${url.pathname}`;

    switch (route) {
      case "GET /health":
        return json({ status: "ok", service: "aegis-router", version: "0.1.0" });
      case "POST /isolate":
        return handleIsolate(request, env);
      default:
        return json({ error: "not_found", route }, 404);
    }
  },
} satisfies ExportedHandler<Env>;
