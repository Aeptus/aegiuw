//! SNI extraction from a raw TLS ClientHello (PRD §1.1).
//!
//! The daemon peeks at the first outbound TCP packets *before* relaying them, pulls
//! the Server Name Indication out of the (normally cleartext) ClientHello, and uses
//! that host for the fork decision. This must complete in ≤ 1.5 ms.
//!
//! Wire layout we need to walk:
//! ```text
//! TLSPlaintext record  → ContentType=handshake(22), version, length
//!   Handshake          → HandshakeType=client_hello(1), length
//!     ClientHello      → version, random[32], session_id, cipher_suites,
//!                        compression_methods, extensions
//!       Extension      → server_name(0) → ServerNameList → HostName
//! ```

/// Attempt to extract the SNI host from a TLS ClientHello byte slice.
///
/// Returns `None` when the bytes are not a ClientHello, the `server_name`
/// extension is absent, or the ClientHello is encrypted via **Encrypted
/// ClientHello (ECH)** — in which case the real SNI is not recoverable here and the
/// connection must be handled by a fallback policy rather than classified by name.
///
/// TODO(FR-1): implement the record/handshake/extension walk with strict bounds
/// checks (this parses adversary-controlled bytes — every length read must be
/// validated against the remaining buffer). Detect the `encrypted_client_hello`
/// extension (type 0xfe0d) and return `None` so callers route to the ECH fallback.
pub fn extract_sni(_client_hello: &[u8]) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_sni() {
        assert_eq!(extract_sni(&[]), None);
    }

    // TODO(FR-1): add fixtures for a real ClientHello (SNI present), a ClientHello
    // with no server_name extension, an ECH ClientHello, and truncated/malformed
    // records that must not panic or read out of bounds.
}
