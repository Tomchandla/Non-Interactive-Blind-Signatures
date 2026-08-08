// Run:
//     RUST_MIN_STACK=8388608 cargo bench --bench blind_sig_conservative_rain
//
// Optional: override the criterion budget for the two slow phases (seconds).
//     NIBS_BENCH_SECS=45 RUST_MIN_STACK=8388608 cargo bench ...

use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use blind_signatures_conservative_rain::blind_sig_conservative_rain::NibsLowmc;
use blind_signatures_conservative_rain::derive::{
    lowmc_setup, MSG_BYTES, NONCE_BYTES, OPEN_BYTES, PKR_BYTES, SKR_BYTES,
};
use blind_signatures_conservative_rain::zk::ZKType;
use vole_rainhash_then_mayo_sys::lowmc::{LOWMC_BLOCK_BYTES, LOWMC_KEY_BYTES, LOWMC_ROUNDS};

const PARAM_SETS: &[(&str, ZKType)] = &[
    ("FV1_128", ZKType::FV1_128),
    ("FV2_128", ZKType::FV2_128),
    ("SV1_128", ZKType::SV1_128),
    ("SV2_128", ZKType::SV2_128),
];

// Number of iterations
const ITERS: u32 = 50;

// Criterion budget for keygen/issue (cheap) and for obtain/verify (~65 ms
// each, so 100 samples need well over the 5 s default).
const FAST_SECS: u64 = 5;
const SLOW_SECS_DEFAULT: u64 = 30;

fn slow_secs() -> u64 {
    std::env::var("NIBS_BENCH_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SLOW_SECS_DEFAULT)
}

struct Fixture {
    bs: NibsLowmc,
    pk: Vec<u8>,
    sk: Vec<u8>,
    pk_r: Vec<u8>,
    sk_r: blind_signatures_conservative_rain::blind_sig_conservative_rain::RecipientSk,
    epk: Vec<u8>,
    additional_r: [u8; 32],
}

fn build_fixture(zk: ZKType) -> Fixture {
    let bs = NibsLowmc::setup(zk);
    let (pk, sk) = bs.keygen_signer();
    let (pk_r, sk_r) = bs.keygen_recipient();
    let epk = bs.mayo.expand_pk(&pk);
    Fixture { bs, pk, sk, pk_r, sk_r, epk, additional_r: [0xffu8; 32] }
}

struct Timings {
    keygen_signer: f64,
    keygen_recipient: f64,
    issue: f64,
    obtain: f64,
    verify: f64,
    presig_bytes: usize,
    sig_bytes: usize,
}

fn measure(f: &mut Fixture, name: &str) -> Timings {
    for _ in 0..5 {
        let (presig, nonce) = f.bs.issue(&f.sk, &f.pk_r);
        let (m, mut sig) =
            f.bs.obtain(&f.pk, &mut f.epk, &f.sk_r, &presig, &nonce, &mut f.additional_r);
        assert!(
            f.bs.verify(&mut f.epk, &m, &mut sig, &mut f.additional_r),
            "[{name}] warm-up round-trip failed"
        );
    }

    let (mut t_ks, mut t_kr, mut t_issue, mut t_obtain, mut t_verify) =
        (0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64);
    let (mut presig_bytes, mut sig_bytes) = (0usize, 0usize);

    for _ in 0..ITERS {
        let start = Instant::now();
        let (pk, sk) = f.bs.keygen_signer();
        t_ks += start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let (_pk_r, _sk_r) = f.bs.keygen_recipient();
        t_kr += start.elapsed().as_secs_f64() * 1_000.0;

        // issue
        let start = Instant::now();
        let (presig, nonce) = f.bs.issue(&sk, &f.pk_r);
        t_issue += start.elapsed().as_secs_f64() * 1_000.0;

        // expand_pk belongs to no timed phase; do it between timers
        let mut epk = f.bs.mayo.expand_pk(&pk);

        // obtain
        let start = Instant::now();
        let (m, mut sig) =
            f.bs.obtain(&pk, &mut epk, &f.sk_r, &presig, &nonce, &mut f.additional_r);
        t_obtain += start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        assert!(f.bs.verify(&mut epk, &m, &mut sig, &mut f.additional_r));
        t_verify += start.elapsed().as_secs_f64() * 1_000.0;

        presig_bytes = presig.len(); // includes MAYO1's 24-byte salt
        sig_bytes = sig.proof.len();
    }

    let n = ITERS as f64;
    Timings {
        keygen_signer: t_ks / n,
        keygen_recipient: t_kr / n,
        issue: t_issue / n,
        obtain: t_obtain / n,
        verify: t_verify / n,
        presig_bytes,
        sig_bytes,
    }
}

fn report(name: &str, t: &Timings, setup_ms: f64) -> String {
    let rule = "─".repeat(58);
    let mut s = String::new();
    s.push_str(&format!("┌{rule}┐\n"));
    s.push_str(&format!("│ {:<56} │\n", format!("NIBS  LowMC + MAYO + RainHash + VOLEitH   [{name}]")));
    s.push_str(&format!("├{rule}┤\n"));

    s.push_str(&format!("│ {:<56} │\n", "Phase                                  mean over 50 runs"));
    for (label, ms) in [
        ("keygen_signer", t.keygen_signer),
        ("keygen_recipient", t.keygen_recipient),
        ("issue", t.issue),
        ("obtain (prove)", t.obtain),
        ("verify", t.verify),
    ] {
        s.push_str(&format!("│   {:<32}{:>19.3} ms │\n", label, ms));
    }
    s.push_str(&format!(
        "│   {:<32}{:>19.3} ms │\n",
        "lowmc setup (one-time, shared)", setup_ms
    ));

    s.push_str(&format!("├{rule}┤\n"));
    s.push_str(&format!("│ {:<56} │\n", "Sizes"));
    for (label, bytes) in [
        ("presignature |sigma_pre|", t.presig_bytes),
        ("signature    |sigma|", t.sig_bytes),
    ] {
        s.push_str(&format!(
            "│   {:<28}{:>10.3} KB{:>10} B  │\n",
            label,
            bytes as f64 / 1024.0,
            bytes
        ));
    }
    for (label, bytes) in [
        ("receiver key K", SKR_BYTES),
        ("opening op", OPEN_BYTES),
        ("nonce r", NONCE_BYTES),
        ("receiver pk_R", PKR_BYTES),
        ("message m", MSG_BYTES),
    ] {
        s.push_str(&format!("│   {:<28}{:>23} B │\n", label, bytes));
    }

    s.push_str(&format!("├{rule}┤\n"));
    s.push_str(&format!("│ {:<56} │\n", "Instances"));
    s.push_str(&format!(
        "│   {:<54} │\n",
        format!(
            "GadM  LowMC(n={}, k={}, m={}, r={}, d=2^64)",
            LOWMC_BLOCK_BYTES * 8,
            LOWMC_KEY_BYTES * 8,
            (LOWMC_BLOCK_BYTES * 8) / 3,
            LOWMC_ROUNDS
        )
    ));
    s.push_str(&format!("│   {:<54} │\n", "GadA  Rain(512, 7r), 1 block:  c = H(op | K)"));
    s.push_str(&format!("│   {:<54} │\n", "Gad2  Rain(512, 7r), 2 blocks: t = H(c | r | salt)"));
    s.push_str(&format!("│   {:<54} │\n", "witness 15744 bits (1968 B), 1960 constraints"));
    s.push_str(&format!("└{rule}┘\n"));
    s
}

fn bench_all(c: &mut Criterion) {
    let start = Instant::now();
    lowmc_setup();
    let setup_ms = start.elapsed().as_secs_f64() * 1_000.0;

    let slow = Duration::from_secs(slow_secs());
    let fast = Duration::from_secs(FAST_SECS);

    for (name, zk) in PARAM_SETS {
        let mut f = build_fixture(*zk);

        let t = measure(&mut f, name);
        let summary = report(name, &t, setup_ms);
        println!("\n{summary}");

        let mut path = PathBuf::from("bench_results");
        if let Err(e) = fs::create_dir_all(&path) {
            eprintln!("[{name}] could not create bench_results/: {e}");
        } else {
            path.push(format!("nibs_lowmc_{name}.txt"));
            match fs::File::create(&path)
                .and_then(|mut file| file.write_all(summary.as_bytes()))
            {
                Ok(()) => println!("[{name}] summary written to {}", path.display()),
                Err(e) => eprintln!("[{name}] could not write {}: {e}", path.display()),
            }
        }

        let mut group = c.benchmark_group(format!("nibs_lowmc/{name}"));

        group.sample_size(100).warm_up_time(Duration::from_secs(1)).measurement_time(fast);

        group.bench_function("keygen_signer", |b| b.iter(|| black_box(f.bs.keygen_signer())));
        group.bench_function("keygen_recipient", |b| {
            b.iter(|| black_box(f.bs.keygen_recipient()))
        });
        group.bench_function("issue", |b| b.iter(|| black_box(f.bs.issue(&f.sk, &f.pk_r))));

        group.warm_up_time(Duration::from_secs(3)).measurement_time(slow);

        group.bench_function("obtain", |b| {
            b.iter_batched(
                || {
                    let (presig, nonce) = f.bs.issue(&f.sk, &f.pk_r);
                    let epk = f.bs.mayo.expand_pk(&f.pk);
                    (presig, nonce, epk, [0xffu8; 32])
                },
                |(presig, nonce, mut epk, mut add_r)| {
                    black_box(f.bs.obtain(&f.pk, &mut epk, &f.sk_r, &presig, &nonce, &mut add_r))
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.bench_function("verify", |b| {
            b.iter_batched(
                || {
                    let (presig, nonce) = f.bs.issue(&f.sk, &f.pk_r);
                    let mut epk = f.bs.mayo.expand_pk(&f.pk);
                    let mut add_r = [0xffu8; 32];
                    let (m, sig) =
                        f.bs.obtain(&f.pk, &mut epk, &f.sk_r, &presig, &nonce, &mut add_r);
                    (epk, m, sig, add_r)
                },
                |(mut epk, m, mut sig, mut add_r)| {
                    black_box(f.bs.verify(&mut epk, &m, &mut sig, &mut add_r))
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.finish();
    }
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
