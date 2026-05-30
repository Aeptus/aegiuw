# Wireshark Lua dissectors for aegiuw

SNI backlog U2.

This directory ships Lua post-dissectors that let you compare aegiuw-core's
view of a TLS ClientHello against Wireshark's built-in reference dissector
side-by-side. Useful when triaging a pcap to spot-check the Rust parser
agrees with Wireshark on the SNI host.

## `aegiuw-sni-dissector.lua`

A from-scratch reimplementation of [`aegiuw_core::extract_sni`]'s parser
logic, in Lua. Runs as a Wireshark post-dissector and surfaces:

- `aegiuw_sni.outcome` — `cleartext`, `encrypted`, `not_found`, `malformed`.
- `aegiuw_sni.host` — the extracted SNI host (only set when `outcome =
  cleartext`).
- `aegiuw_sni.ech` — `true` if the ECH extension (0xfe0d) was seen.
- `aegiuw_sni.ext_count` — total extensions walked (excluding GREASE
  rejection paths).
- `aegiuw_sni.note` — diagnostic string when something failed.

It also appends a short `[aegiuw: cleartext example.com]` marker to the
packet-list Info column so disagreements with Wireshark's TLS dissection
jump out.

### Install

Drop the `.lua` file into your Wireshark personal plugins folder:

| Platform | Path |
|---|---|
| macOS | `~/.config/wireshark/plugins/aegiuw-sni-dissector.lua` |
| Linux | `~/.config/wireshark/plugins/aegiuw-sni-dissector.lua` |
| Windows | `%APPDATA%\Wireshark\plugins\aegiuw-sni-dissector.lua` |

Then restart Wireshark. Look for the "aegiuw-core SNI parser view" subtree
on any TLS packet, below the standard TLS dissection.

To surface the columns in the packet list: Edit → Preferences → Columns →
"+" → Type "Custom" → Field "aegiuw_sni.outcome" (and / or
"aegiuw_sni.host").

### Why a from-scratch reimplementation

Two reasons:

1. **Spot-check independence.** If we wrapped Wireshark's
   `tls.handshake.extensions_server_name` field we'd lose the comparison
   value — two parsers, same input, do they agree? The point of U2 is
   that disagreements should be visible. Walking the bytes ourselves
   means a parser regression in either side trips the spot-check.
2. **Wireshark TLS dissection is excellent but** sometimes filtered out
   on encrypted records (when a `tls.keylog` file is loaded, the post-
   handshake dissection takes precedence). Working from the raw payload
   bytes keeps us decoupled from Wireshark's decryption pipeline.

### Limitations

- Mirrors aegiuw-core's behaviour as of mid-2026 (C1 + H1–H6 + A1–A12 + D1–D6
  contracts). A future divergence in either side must be reflected here —
  this file is **not** auto-generated, so it can drift. If you spot a
  divergence, file an issue and fix whichever side is wrong.
- No JA3/JA4 output (kept minimal). Use `aegiuw-sni-inspect` (U1) for the
  full diagnostic dump if you need fingerprints.
- The reassembly path handles the multi-record case the same way as
  aegiuw-core (refuse mixed content-type streams, cap at
  `MAX_HANDSHAKE_BYTES = 64 KiB`).

### Testing

Lua post-dissectors can't be unit-tested cleanly without bundling
Wireshark in CI. The right validation is interactive: open a pcap,
compare the "aegiuw-core SNI parser view" subtree to Wireshark's
"Transport Layer Security → Handshake Protocol: Client Hello → Extension:
server_name → Server Name" entry. They should agree.
