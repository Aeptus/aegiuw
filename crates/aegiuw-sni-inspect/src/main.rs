// SPDX-License-Identifier: AGPL-3.0-or-later

//! `aegiuw-sni-inspect` — debug CLI for [`aegiuw_core`]'s ClientHello parser.
//!
//! SNI backlog U1.
//!
//! Reads a hex-encoded ClientHello (record-framed, the same shape we'd see
//! on the wire) and prints the four things a triager usually wants:
//!
//! 1. `extract_sni` outcome (the SNI verdict the daemon would use).
//! 2. Full `ClientHelloMetadata` (every extension field A1-A12 exposes).
//! 3. JA3 fingerprint (raw + MD5) — for indexing into threat-intel feeds.
//! 4. JA4 fingerprint (raw `a_b_c`) — modern fingerprint.
//!
//! ## Input shapes
//!
//! ```text
//! aegiuw-sni-inspect <HEX>         # hex bytes on the command line
//! aegiuw-sni-inspect --file <PATH>  # read hex (whitespace tolerated) from file
//! aegiuw-sni-inspect --stdin        # read hex from stdin
//! ```
//!
//! ## pcap → hex pipeline
//!
//! pcap support is intentionally out of scope (adds a heavy dep for a debug
//! tool). Use `tshark` to pre-extract the TLS bytes:
//!
//! ```bash
//! # Print the TLS handshake bytes of the first packet that has them.
//! tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.record \
//!   | head -1 | tr -d '\n' \
//!   | aegiuw-sni-inspect --stdin
//! ```

use std::io::Read as _;
use std::process::ExitCode;

use aegiuw_core::{
    fingerprint::{ja3, ja4, known_client_from_ja4, likely_launch_source},
    parse_client_hello_full, AlpnProtocol, KeyShareGroup, SniOutcome, TlsVersion,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let input = match parse_args(&args[1..]) {
        Ok(input) => input,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let bytes = match decode_hex(&input) {
        Ok(b) => b,
        Err(msg) => {
            eprintln!("hex decode failed: {msg}");
            return ExitCode::from(2);
        }
    };

    if bytes.is_empty() {
        eprintln!("no input bytes provided");
        return ExitCode::from(2);
    }

    println!("== aegiuw-sni-inspect ==");
    println!("input: {} bytes", bytes.len());
    println!();

    let outcome = aegiuw_core::extract_sni(&bytes);
    println!("extract_sni: {}", format_outcome(&outcome));
    println!();

    match parse_client_hello_full(&bytes) {
        None => {
            // Either Malformed (the input genuinely isn't a CH) or NotFound
            // (no SNI extension). Both are legitimate parser outputs — we
            // exit success.
            println!("parse_client_hello_full: None (input doesn't parse as a ClientHello)");
            return ExitCode::SUCCESS;
        }
        Some(meta) => {
            println!("parse_client_hello_full:");
            print_metadata(&meta);
            println!();

            let ja3 = ja3(&meta);
            println!("JA3:");
            println!("  raw: {}", ja3.raw);
            println!("  md5: {}", ja3.md5);
            println!();

            let ja4 = ja4(&meta);
            println!("JA4:");
            println!("  raw: {}", ja4.raw);
            println!("  a:   {}", ja4.a);
            println!("  b:   {}", ja4.b);
            println!("  c:   {}", ja4.c);
            if let Some(client) = known_client_from_ja4(&ja4.raw) {
                println!("  KnownClient table hit: {:?}", client);
            }
            println!();

            println!("likely_launch_source: {:?}", likely_launch_source(&meta));
        }
    }

    ExitCode::SUCCESS
}

fn parse_args(args: &[String]) -> Result<String, String> {
    match args {
        [] => Err(usage()),
        [flag] if matches!(flag.as_str(), "-h" | "--help") => Err(usage()),
        [flag] if flag == "--stdin" => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("stdin read failed: {e}"))?;
            Ok(buf)
        }
        [flag, path] if flag == "--file" => {
            std::fs::read_to_string(path).map_err(|e| format!("file read failed: {e}"))
        }
        [hex] if !hex.starts_with("--") => Ok(hex.clone()),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "aegiuw-sni-inspect — debug CLI for the aegiuw-core SNI parser (SNI backlog U1)\n\
    \n\
    USAGE:\n  \
    aegiuw-sni-inspect <HEX>\n  \
    aegiuw-sni-inspect --file <PATH>\n  \
    aegiuw-sni-inspect --stdin\n\
    \n\
    HEX is the record-framed wire bytes (same shape the daemon sees), case-\n\
    insensitive, whitespace and `0x` prefixes tolerated. Empty input is\n\
    rejected.\n\
    \n\
    pcap support is out of scope. Use `tshark -T fields -e tls.record -x` to\n\
    pre-extract a ClientHello from a pcap and pipe the hex into this tool.\n"
        .to_string()
}

/// Decode a string of hex characters into bytes. Tolerates whitespace,
/// commas, colons, and `0x` prefixes (anything not in `[0-9A-Fa-f]` is
/// stripped before pairing nibbles). Returns Err on odd nibble count or
/// invalid character after stripping.
fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(format!(
            "odd number of hex digits ({}); pairs required",
            cleaned.len(),
        ));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("invalid hex byte: {other:#04x}")),
    }
}

fn format_outcome(outcome: &SniOutcome<'_>) -> String {
    match outcome {
        SniOutcome::Cleartext { host } => format!("Cleartext {{ host: {host:?} }}"),
        SniOutcome::Encrypted => "Encrypted (ECH)".to_string(),
        SniOutcome::NotFound => "NotFound (no server_name extension)".to_string(),
        SniOutcome::Malformed => "Malformed".to_string(),
    }
}

fn print_metadata(meta: &aegiuw_core::ClientHelloMetadata<'_>) {
    print_pair("host", &format!("{:?}", meta.host));
    print_pair("ech_present", &meta.ech_present.to_string());
    print_pair("psk_present", &meta.psk_present.to_string());
    print_pair("early_data_present", &meta.early_data_present.to_string());
    print_pair(
        "compress_certificate_present",
        &meta.compress_certificate_present.to_string(),
    );
    print_pair(
        "record_size_limit",
        &format!("{:?}", meta.record_size_limit),
    );
    print_pair(
        "supported_versions",
        &format_optional_versions(meta.supported_versions.as_deref()),
    );
    print_pair(
        "highest_supported_tls_version",
        &format!("{:?}", meta.highest_supported_tls_version()),
    );
    print_pair(
        "key_share_groups",
        &format_optional_groups(meta.key_share_groups.as_deref()),
    );
    print_pair(
        "has_post_quantum_key_share",
        &meta.has_post_quantum_key_share().to_string(),
    );
    print_pair(
        "supported_groups",
        &format_optional_groups(meta.supported_groups.as_deref()),
    );
    print_pair(
        "signature_algorithms (count)",
        &format!("{:?}", meta.signature_algorithms.as_ref().map(|v| v.len()),),
    );
    print_pair(
        "ec_point_formats",
        &format!("{:?}", meta.ec_point_formats.as_deref()),
    );
    print_pair("alpn_protocols", &format_optional_alpn(meta));
    print_pair(
        "extension_order (count)",
        &meta.extension_order.len().to_string(),
    );
    print_pair(
        "cipher_suites (count)",
        &meta.cipher_suites.len().to_string(),
    );
}

fn format_optional_versions(versions: Option<&[u16]>) -> String {
    match versions {
        None => "None".to_string(),
        Some(v) => {
            let classified: Vec<TlsVersion> = v.iter().map(|&x| TlsVersion::from_wire(x)).collect();
            format!("{:?} (classified: {:?})", v, classified)
        }
    }
}

fn format_optional_groups(groups: Option<&[u16]>) -> String {
    match groups {
        None => "None".to_string(),
        Some(g) => {
            let classified: Vec<KeyShareGroup> =
                g.iter().map(|&x| KeyShareGroup::from_wire(x)).collect();
            format!(
                "{:?} (classified: {:?})",
                g.iter().map(|x| format!("{x:#06x}")).collect::<Vec<_>>(),
                classified
            )
        }
    }
}

fn format_optional_alpn(meta: &aegiuw_core::ClientHelloMetadata<'_>) -> String {
    match meta.alpn_protocols.as_deref() {
        None => "None".to_string(),
        Some(protos) => {
            let strs: Vec<String> = protos
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect();
            let classified: Vec<AlpnProtocol> =
                protos.iter().map(|p| AlpnProtocol::from_wire(p)).collect();
            format!("{:?} (classified: {:?})", strs, classified)
        }
    }
}

fn print_pair(label: &str, value: &str) {
    println!("  {label:32}{value}");
}
