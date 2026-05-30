-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- aegiuw-sni-dissector.lua — Wireshark Lua post-dissector that mirrors
-- aegiuw-core's SNI parser logic and surfaces a comparison view next to
-- Wireshark's built-in TLS dissection.
--
-- SNI backlog U2.
--
-- Purpose: spot-check `aegiuw-core` against Wireshark's reference TLS
-- dissector. The script walks the raw TCP payload bytes the same way the
-- Rust parser does, then publishes its findings in a new "aegiuw-sni"
-- column / details tree. If Wireshark and we disagree on whether SNI is
-- present (or on the host string), it's visible at a glance.
--
-- This is intentionally a from-scratch independent implementation — not
-- a wrapper around Wireshark's `tls.handshake.extensions_server_name`
-- field — because that's the whole point of a spot-check: two parsers,
-- same input, do they agree?
--
-- Install:
--   - macOS:   ~/.config/wireshark/plugins/aegiuw-sni-dissector.lua
--   - Linux:   ~/.config/wireshark/plugins/aegiuw-sni-dissector.lua
--   - Windows: %APPDATA%\Wireshark\plugins\aegiuw-sni-dissector.lua
--
-- Then restart Wireshark and look for "aegiuw-sni" in the dissection tree
-- below the TLS layer, or add the `aegiuw_sni.outcome` and
-- `aegiuw_sni.host` columns via Edit → Preferences → Columns.

local aegiuw = Proto("aegiuw_sni", "aegiuw-core SNI parser view")

local outcome_field = ProtoField.string("aegiuw_sni.outcome", "Outcome")
local host_field    = ProtoField.string("aegiuw_sni.host",    "Host")
local ech_field     = ProtoField.bool  ("aegiuw_sni.ech",     "ECH present")
local ext_count_field = ProtoField.uint16("aegiuw_sni.ext_count", "Extension count")
local note_field    = ProtoField.string("aegiuw_sni.note",    "Notes")

aegiuw.fields = { outcome_field, host_field, ech_field, ext_count_field, note_field }

-- TLS constants we recognise (same wire values aegiuw-core uses).
local CONTENT_TYPE_HANDSHAKE       = 22
local HANDSHAKE_TYPE_CLIENT_HELLO  = 1
local TLS_LEGACY_VERSION           = 0x0303
local EXT_SERVER_NAME              = 0x0000
local EXT_ENCRYPTED_CLIENT_HELLO   = 0xfe0d
local NAME_TYPE_HOST_NAME          = 0
local MAX_HANDSHAKE_BYTES          = 64 * 1024
local MAX_RECORD_FRAGMENT          = 16384 + 256
local MAX_HOSTNAME_LEN             = 253

-- Try to parse the buffer as one or more concatenated TLS records carrying
-- one handshake message; return the reassembled handshake byte string (Lua
-- string) or nil on failure. Mirrors aegiuw_core::reassemble_handshake.
local function reassemble_handshake(buf)
  local pos = 0
  local handshake = ""
  local expected_total = nil
  local len = buf:len()
  while pos < len do
    if pos + 5 > len then return nil end
    local ct = buf(pos, 1):uint()
    if ct ~= CONTENT_TYPE_HANDSHAKE then return nil end
    local frag_len = buf(pos + 3, 2):uint()
    if frag_len > MAX_RECORD_FRAGMENT then return nil end
    pos = pos + 5
    if pos + frag_len > len then return nil end
    if frag_len > 0 then
      handshake = handshake .. buf(pos, frag_len):raw()
      if #handshake > MAX_HANDSHAKE_BYTES then return nil end
      if expected_total == nil and #handshake >= 4 then
        local b0 = handshake:byte(2)
        local b1 = handshake:byte(3)
        local b2 = handshake:byte(4)
        local body = b0 * 65536 + b1 * 256 + b2
        local total = 4 + body
        if total > MAX_HANDSHAKE_BYTES then return nil end
        expected_total = total
      end
      pos = pos + frag_len
      if expected_total and #handshake >= expected_total then
        return handshake:sub(1, expected_total)
      end
    end
  end
  return nil
end

-- Parse the already-reassembled handshake. Returns a table with fields:
--   outcome     = "cleartext" | "encrypted" | "not_found" | "malformed"
--   host        = string or nil
--   ech_present = bool
--   ext_count   = integer (post-walk count, 0 if reject)
--   note        = optional diagnostic string
local function parse_handshake(hs)
  local function fail(reason)
    return { outcome = "malformed", ech_present = false, ext_count = 0, note = reason }
  end
  if #hs < 4 then return fail("handshake < 4 bytes") end
  if hs:byte(1) ~= HANDSHAKE_TYPE_CLIENT_HELLO then return fail("not a ClientHello") end
  local pos = 5 -- skip type + u24 length
  if pos + 2 > #hs then return fail("truncated legacy_version") end
  local legacy = hs:byte(pos) * 256 + hs:byte(pos + 1)
  pos = pos + 2
  if legacy ~= TLS_LEGACY_VERSION then return fail("legacy_version != 0x0303") end
  if pos + 32 > #hs then return fail("truncated random") end
  pos = pos + 32
  if pos + 1 > #hs then return fail("truncated session_id_len") end
  local sid_len = hs:byte(pos)
  pos = pos + 1
  if sid_len > 32 then return fail("session_id > 32") end
  if pos + sid_len > #hs then return fail("truncated session_id") end
  pos = pos + sid_len
  if pos + 2 > #hs then return fail("truncated cipher_suites len") end
  local cs_len = hs:byte(pos) * 256 + hs:byte(pos + 1)
  pos = pos + 2
  if cs_len == 0 or cs_len % 2 ~= 0 then return fail("cipher_suites bad") end
  if pos + cs_len > #hs then return fail("truncated cipher_suites") end
  pos = pos + cs_len
  if pos + 1 > #hs then return fail("truncated compression_methods len") end
  local cm_len = hs:byte(pos)
  pos = pos + 1
  if pos + cm_len > #hs then return fail("truncated compression_methods") end
  local found_null = false
  for i = 0, cm_len - 1 do
    if hs:byte(pos + i) == 0 then found_null = true end
  end
  if not found_null then return fail("no null compression") end
  pos = pos + cm_len
  if pos + 2 > #hs then return fail("truncated extensions_len") end
  local ext_len = hs:byte(pos) * 256 + hs:byte(pos + 1)
  pos = pos + 2
  if pos + ext_len > #hs then return fail("truncated extensions block") end
  local ext_end = pos + ext_len

  local ech_present = false
  local host = nil
  local ext_count = 0
  local seen_types = {}
  while pos + 4 <= ext_end do
    local et = hs:byte(pos) * 256 + hs:byte(pos + 1)
    local el = hs:byte(pos + 2) * 256 + hs:byte(pos + 3)
    pos = pos + 4
    if pos + el > ext_end then return fail("ext overruns block") end
    if seen_types[et] then return fail("duplicate ext type") end
    seen_types[et] = true
    ext_count = ext_count + 1
    if et == EXT_ENCRYPTED_CLIENT_HELLO then
      ech_present = true
    elseif et == EXT_SERVER_NAME then
      -- Parse server_name body.
      if el < 5 then return fail("server_name body < 5") end
      local sn_pos = pos
      local list_len = hs:byte(sn_pos) * 256 + hs:byte(sn_pos + 1)
      if list_len + 2 > el then return fail("ServerNameList overruns") end
      if list_len < 3 then return fail("ServerNameList < 3 bytes") end
      local list_end = sn_pos + 2 + list_len
      local entry_pos = sn_pos + 2
      local name_type = hs:byte(entry_pos)
      entry_pos = entry_pos + 1
      if name_type == NAME_TYPE_HOST_NAME then
        if entry_pos + 2 > list_end then return fail("host_name len truncated") end
        local host_len = hs:byte(entry_pos) * 256 + hs:byte(entry_pos + 1)
        entry_pos = entry_pos + 2
        if entry_pos + host_len > list_end then return fail("host_name overruns") end
        if host_len == 0 then return fail("empty host_name") end
        if host_len > MAX_HOSTNAME_LEN then return fail("host > 253") end
        local raw_host = hs:sub(entry_pos + 1, entry_pos + host_len)
        -- Trailing-dot strip (H4).
        if raw_host:sub(-1) == "." then raw_host = raw_host:sub(1, -2) end
        host = raw_host
      end
      -- Non-host_name first entry → Skip (host stays nil, no Malformed).
    end
    pos = pos + el
  end

  if ech_present then
    return { outcome = "encrypted", host = nil, ech_present = true, ext_count = ext_count }
  end
  if host then
    return { outcome = "cleartext", host = host, ech_present = false, ext_count = ext_count }
  end
  return { outcome = "not_found", host = nil, ech_present = false, ext_count = ext_count }
end

-- Hook into the `tls` dissector chain: any time Wireshark dissects TLS,
-- we also run our parser on the underlying TCP segment payload and add a
-- comparison subtree.
function aegiuw.dissector(buf, pinfo, tree)
  if buf:len() < 5 then return end
  -- Only run on the first ClientHello-shaped bytes; skip everything else.
  if buf(0, 1):uint() ~= CONTENT_TYPE_HANDSHAKE then return end

  local hs = reassemble_handshake(buf)
  local result
  if hs == nil then
    result = { outcome = "malformed", ech_present = false, ext_count = 0,
               note = "reassemble_handshake returned nil" }
  else
    result = parse_handshake(hs)
  end

  local subtree = tree:add(aegiuw, buf(0, buf:len()), "aegiuw-core SNI parser view")
  subtree:add(outcome_field, result.outcome)
  if result.host then
    subtree:add(host_field, result.host)
  end
  subtree:add(ech_field, result.ech_present)
  subtree:add(ext_count_field, result.ext_count)
  if result.note then
    subtree:add(note_field, result.note)
  end

  -- Append a short marker to the Info column so packet lists show the
  -- outcome alongside Wireshark's TLS summary.
  if pinfo.cols and pinfo.cols.info then
    pinfo.cols.info:append(string.format(" [aegiuw: %s%s]",
      result.outcome,
      result.host and (" " .. result.host) or ""))
  end
end

-- Register as a post-dissector so we run after Wireshark's built-in TLS
-- dissector has had a chance to mark cols.info. (If we registered as a
-- pre-dissector against TCP, we'd race with Wireshark's TLS dissection.)
register_postdissector(aegiuw)
