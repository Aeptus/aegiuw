// SPDX-License-Identifier: AGPL-3.0-or-later

//! Criterion benchmarks for the SNI parser (SNI backlog P3).
//!
//! Run with `cargo bench -p aegiuw-core`. Criterion writes results under
//! `target/criterion/`; the first run establishes a baseline, subsequent runs
//! report % change. PRD §1.1 budget: ≤ 1.5 ms = ≤ 1500 µs per extract_sni call.

use aegiuw_core::{extract_sni, parse_handshake_message, reassemble_handshake};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const EXT_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST_NAME: u8 = 0;

fn build_sni_extension(host: &str) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut entry = Vec::new();
    entry.push(NAME_TYPE_HOST_NAME);
    entry.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    entry.extend_from_slice(host_bytes);

    let mut list = Vec::new();
    list.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    list.extend_from_slice(&entry);

    let mut ext = Vec::new();
    ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

fn build_handshake_message(extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0xAA; 32]); // random
    body.push(0); // session_id_len
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
    body.extend_from_slice(&[0x01, 0x00]); // compression null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);

    let mut handshake = Vec::new();
    handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let body_len = body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);
    handshake
}

fn wrap_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(CONTENT_TYPE_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn typical_client_hello() -> Vec<u8> {
    let ext = build_sni_extension("example.com");
    wrap_record(&build_handshake_message(&ext))
}

fn fragmented_client_hello() -> Vec<u8> {
    let ext = build_sni_extension("example.com");
    let hs = build_handshake_message(&ext);
    let split = hs.len() / 2;
    let mut out = Vec::new();
    out.extend_from_slice(&wrap_record(&hs[..split]));
    out.extend_from_slice(&wrap_record(&hs[split..]));
    out
}

fn many_labels_hostname() -> String {
    // 126 single-char labels + "a" = 253 bytes total. Same shape as
    // `accepts_hostname_at_253_byte_boundary` test fixture. P5 dot-search
    // does its work on this kind of input.
    let mut host = "a.".repeat(126);
    host.push('a');
    host
}

fn many_labels_client_hello() -> Vec<u8> {
    let host = many_labels_hostname();
    let ext = build_sni_extension(&host);
    wrap_record(&build_handshake_message(&ext))
}

fn benches(c: &mut Criterion) {
    let typical = typical_client_hello();
    c.bench_function("extract_sni / typical single-record CH with SNI", |b| {
        b.iter(|| extract_sni(black_box(&typical)))
    });

    let fragmented = fragmented_client_hello();
    c.bench_function("extract_sni / two-record fragmented CH with SNI", |b| {
        b.iter(|| extract_sni(black_box(&fragmented)))
    });

    // P5: this fixture has 127 labels (each 1 byte). The dot-search path is
    // the one memchr accelerates; flat numbers here say "memchr is no worse";
    // a win here is the win.
    let many_labels = many_labels_client_hello();
    c.bench_function(
        "extract_sni / 253-byte host, 127 labels (P5 hot path)",
        |b| b.iter(|| extract_sni(black_box(&many_labels))),
    );

    c.bench_function("reassemble_handshake / typical single-record", |b| {
        b.iter(|| reassemble_handshake(black_box(&typical)))
    });

    let handshake = build_handshake_message(&build_sni_extension("example.com"));
    c.bench_function("parse_handshake_message / already-reassembled bytes", |b| {
        b.iter(|| parse_handshake_message(black_box(&handshake)))
    });
}

criterion_group!(sni_benches, benches);
criterion_main!(sni_benches);
