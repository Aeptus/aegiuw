// SPDX-License-Identifier: AGPL-3.0-or-later

//! `aegiuw-sni-replay` — batch-replay a corpus of ClientHellos through
//! [`aegiuw_core::extract_sni`] and report an outcome histogram.
//!
//! SNI backlog U3.
//!
//! ## Input
//!
//! A text file (or stdin) with **one hex-encoded ClientHello per line** —
//! the record-framed wire bytes, the same shape `aegiuw-sni-inspect` (U1)
//! takes. Blank lines and lines beginning with `#` are ignored. Each line's
//! hex tolerates whitespace, `0x` prefixes, and `:` / `,` separators.
//!
//! ```text
//! aegiuw-sni-replay <FILE>     # one hex ClientHello per line
//! aegiuw-sni-replay --stdin    # read the corpus from stdin
//! ```
//!
//! ## Producing the corpus from a real pcap
//!
//! Direct pcap parsing is intentionally out of scope (it would pull a
//! pcap/pcapng parser plus a TCP-reassembly stack into a debug tool — see
//! the U3 DECISIONS entry). Use `tshark` to turn a capture into the
//! line-per-ClientHello corpus this tool wants:
//!
//! ```bash
//! tshark -r capture.pcap -Y 'tls.handshake.type == 1' \
//!   -T fields -e tls.record \
//!   | tr -d ':' \
//!   > clienthellos.hexlines
//! aegiuw-sni-replay clienthellos.hexlines
//! ```

use std::io::Read as _;
use std::process::ExitCode;

use aegiuw_core::{extract_sni, SniOutcome};
use aegiuw_sni_inspect::{decode_hex, OutcomeHistogram};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let corpus = match read_corpus(&args[1..]) {
        Ok(text) => text,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    let mut hist = OutcomeHistogram::default();
    for line in corpus.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match decode_hex(line) {
            Err(_) => hist.record_decode_error(),
            Ok(bytes) => {
                let outcome = extract_sni(&bytes);
                hist.record_kind(outcome.kind());
                if let SniOutcome::Cleartext { host } = &outcome {
                    hist.record_host(host);
                }
            }
        }
    }

    print_report(&hist);
    ExitCode::SUCCESS
}

fn read_corpus(args: &[String]) -> Result<String, String> {
    match args {
        [flag] if matches!(flag.as_str(), "-h" | "--help") => Err(usage()),
        [flag] if flag == "--stdin" => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("stdin read failed: {e}"))?;
            Ok(buf)
        }
        [path] if !path.starts_with("--") => {
            std::fs::read_to_string(path).map_err(|e| format!("file read failed: {e}"))
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "aegiuw-sni-replay — batch-replay ClientHellos and histogram the outcomes (SNI backlog U3)\n\
    \n\
    USAGE:\n  \
    aegiuw-sni-replay <FILE>   # one hex ClientHello per line\n  \
    aegiuw-sni-replay --stdin  # read the corpus from stdin\n\
    \n\
    Blank lines and `#` comments are ignored. Produce the corpus from a pcap with:\n  \
    tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.record \\\n    \
    | tr -d ':' > clienthellos.hexlines\n"
        .to_string()
}

fn print_report(hist: &OutcomeHistogram) {
    const BAR_WIDTH: usize = 30;
    let parsed = hist.total_parsed();

    println!("== aegiuw-sni-replay ==");
    println!(
        "input: {} lines ({} parsed, {} hex-decode errors)",
        hist.total_lines(),
        parsed,
        hist.decode_errors,
    );
    println!();

    println!("outcome histogram (of parsed):");
    print_row("cleartext", hist.cleartext, parsed, BAR_WIDTH);
    print_row("encrypted", hist.encrypted, parsed, BAR_WIDTH);
    print_row("not_found", hist.not_found, parsed, BAR_WIDTH);
    print_row("malformed", hist.malformed, parsed, BAR_WIDTH);
    println!("  {:-<54}", "");
    println!("  {:<12}{:>7}", "total", parsed);
    println!();

    println!(
        "ECH adoption (encrypted / parsed): {:.1}%",
        hist.ech_adoption_fraction() * 100.0,
    );
    println!();

    let top = hist.top_hosts(10);
    if top.is_empty() {
        println!("top cleartext hosts: (none — no Cleartext outcomes)");
    } else {
        println!("top cleartext hosts:");
        for (host, count) in top {
            println!("  {count:>7}  {host}");
        }
    }
}

fn print_row(label: &str, count: u64, total: u64, width: usize) {
    let frac = if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    };
    let filled = (frac * width as f64).round() as usize;
    let bar: String = "█".repeat(filled);
    println!("  {label:<12}{count:>7}  {:>5.1}%  {bar}", frac * 100.0);
}
