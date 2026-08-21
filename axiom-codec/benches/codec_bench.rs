//! Codec benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use axiom_codec::{Decoder, Encoder};
use axiom_types::*;

fn create_test_frame(payload_size: usize, trust_level: TrustLevel) -> Frame {
    let header = FrameHeader::new(FrameType::Intent, NodeId::from_bytes([0x42; 32]))
        .with_trust_level(trust_level)
        .with_clock(HybridClock::new(1700000000, 42))
        .with_intent(IntentHash::from_bytes([0xAB; 16]));

    let payload = vec![0xDEu8; payload_size];
    let mut frame = Frame::new(header, PayloadType::Tensor, payload);

    // Set appropriate auth
    match trust_level {
        TrustLevel::Full | TrustLevel::Sig => {
            frame.auth = Authentication::Signature(Signature::from_bytes([0x55; 64]));
        }
        TrustLevel::Compress => {
            frame.auth = Authentication::Token(SessionToken::from_bytes([0x66; 16]));
        }
        TrustLevel::Raw => {}
    }

    frame
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");

    for size in [0, 64, 1024, 4096, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64 + 62)); // payload + min header

        group.bench_function(format!("raw_{}_bytes", size), |b| {
            let frame = create_test_frame(*size, TrustLevel::Raw);
            let mut buffer = vec![0u8; size + 256];

            b.iter(|| {
                Encoder::encode(black_box(&frame), black_box(&mut buffer)).unwrap()
            });
        });

        group.bench_function(format!("sig_{}_bytes", size), |b| {
            let frame = create_test_frame(*size, TrustLevel::Sig);
            let mut buffer = vec![0u8; size + 256];

            b.iter(|| {
                Encoder::encode(black_box(&frame), black_box(&mut buffer)).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    for size in [0, 64, 1024, 4096, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64 + 62));

        group.bench_function(format!("raw_{}_bytes", size), |b| {
            let frame = create_test_frame(*size, TrustLevel::Raw);
            let mut buffer = vec![0u8; size + 256];
            let encoded_size = Encoder::encode(&frame, &mut buffer).unwrap();

            b.iter(|| {
                Decoder::decode(black_box(&buffer[..encoded_size])).unwrap()
            });
        });

        group.bench_function(format!("header_only_{}_bytes", size), |b| {
            let frame = create_test_frame(*size, TrustLevel::Raw);
            let mut buffer = vec![0u8; size + 256];
            let encoded_size = Encoder::encode(&frame, &mut buffer).unwrap();

            b.iter(|| {
                Decoder::decode_header(black_box(&buffer[..encoded_size])).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    // Simulate typical AI workload: 2048-dim f16 embedding
    let embedding_size = 2048 * 2; // 4096 bytes
    group.throughput(Throughput::Bytes(embedding_size as u64 + 62));

    group.bench_function("embedding_2048_f16", |b| {
        let frame = create_test_frame(embedding_size, TrustLevel::Compress);
        let mut buffer = vec![0u8; embedding_size + 256];

        b.iter(|| {
            let size = Encoder::encode(black_box(&frame), black_box(&mut buffer)).unwrap();
            Decoder::decode(black_box(&buffer[..size])).unwrap()
        });
    });

    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_roundtrip);
criterion_main!(benches);
