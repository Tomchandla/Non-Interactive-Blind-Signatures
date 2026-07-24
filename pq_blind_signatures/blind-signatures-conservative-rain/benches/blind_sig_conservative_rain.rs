//! Criterion benchmarks for the LowMC+MAYO NIBS scheme.
//!
//! Methodology is deliberately IDENTICAL to the RainHash bench
//! (blind_sig_conservative_rain.rs): same five ops, same ITERS, same
//! param sets, same batching -- so the two result sets are directly
//! comparable columns. Results go to bench_results/nibs_lowmc_<name>.txt,
//! NOT overwriting the Rain-era nibs_<name>.txt files.
//!
//! One genuinely new line item vs Rain: `lowmc_setup()` instantiates the
//! two LowMC instances (35 rounds' worth of 256x256 invertible matrices
//! from the reference LFSR, with rejection sampling) -- a one-time,
//! multi-second cost with no Rain analogue (Rain's constants were
//! compile-time headers). It is timed ONCE at startup and reported as a
//! Setup cost (the `pp`-generation bucket in the BGY25 interface); it must
//! never run inside a timed closure, which is why it is called before any
//! fixture is built.
//!
//! Run:
//!     cargo bench --bench blind_sig_conservative_rain
//! (bench target name kept from the Rain edition; see Cargo.toml)
//!
//! Criterion writes HTML reports to target/criterion/. The one-shot summary
//! block (means in ms, sizes in KB) is printed once per parameter set.
//!
//! Cargo.toml declares:
//!     [[bench]]
//!     name = "blind_sig_conservative_rain"
//!     harness = false

use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use blind_signatures_conservative_rain::blind_sig_conservative_rain::NibsLowmc;
use blind_signatures_conservative_rain::derive::lowmc_setup;
use blind_signatures_conservative_rain::zk::ZKType;

/// Parameter sets to benchmark. All four level-1 variants (fast/slow x v1/v2)
/// over the same LowMC+MAYO circuit. Each writes its own summary file.
const PARAM_SETS: &[(&str, ZKType)] = &[
    ("FV1_128", ZKType::FV1_128),
    ("FV2_128", ZKType::FV2_128),
    ("SV1_128", ZKType::SV1_128),
    ("SV2_128", ZKType::SV2_128),
];

/// Everything an operation might need, generated once per parameter set so the
/// benchmarked closures don't pay setup/keygen cost inside the timing loop.
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
    // lowmc_setup() has already run (timed, in bench_all) and is idempotent,
    // so nothing here can trigger a lazy multi-second instantiation.
    let bs = NibsLowmc::setup(zk);
    let (pk, sk) = bs.keygen_signer();
    let (pk_r, sk_r) = bs.keygen_recipient(); // skR is 32 bytes now
    let epk = bs.mayo.expand_pk(&pk);
    Fixture {
        bs,
        pk,
        sk,
        pk_r,
        sk_r,
        epk,
        additional_r: [0xffu8; 32],
    }
}

/// A quick, non-criterion summary: mean per-op time and the two byte sizes.
/// Cheap to read at a glance and easy to paste next to Table 2.
/// `setup_ms` is the one-time LowMC instantiation cost, reported per file so
/// each summary is self-contained.
fn print_summary(name: &str, f: &mut Fixture, setup_ms: f64) {
    const ITERS: u32 = 20;

    // warm-up + correctness (also confirms the pipeline is sound before timing)
    for _ in 0..5 {
        let (presig, nonce) = f.bs.issue(&f.sk, &f.pk_r);
        let (m, mut sig) = f
            .bs
            .obtain(&f.pk, &mut f.epk, &f.sk_r, &presig, &nonce, &mut f.additional_r);
        assert!(
            f.bs.verify(&mut f.epk, &m, &mut sig, &mut f.additional_r),
            "[{name}] warm-up round-trip failed"
        );
    }

    let (mut t_ks, mut t_kr, mut t_issue, mut t_obtain, mut t_verify) =
        (0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64);
    let mut presig_len = 0usize;
    let mut sig_len = 0usize;

    for _ in 0..ITERS {
        let start = Instant::now();
        let (pk, sk) = f.bs.keygen_signer();
        t_ks += start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let (_pk_r, _sk_r) = f.bs.keygen_recipient();
        t_kr += start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        // issue = nonce sampling + derive_com (22-round LowMC-MMO)
        //         + Rain target hash + MAYO preimage sampling
        let (presig, nonce) = f.bs.issue(&sk, &f.pk_r);
        t_issue += start.elapsed().as_secs_f64() * 1_000.0;

        // expand_pk is not part of any timed phase; do it between timers
        let mut epk = f.bs.mayo.expand_pk(&pk);

        let start = Instant::now();
        // obtain = witness expansion (48 LowMC rounds of bit-matrix products
        // + one 7-round Rain gadget, in the clear) + the VOLEitH prove. The
        // prove dominates; the LowMC circuit's dense linear layers are the
        // interesting delta vs the all-Rain edition.
        let (m, mut sig) = f
            .bs
            .obtain(&pk, &mut epk, &f.sk_r, &presig, &nonce, &mut f.additional_r);
        t_obtain += start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        assert!(f.bs.verify(&mut epk, &m, &mut sig, &mut f.additional_r));
        t_verify += start.elapsed().as_secs_f64() * 1_000.0;

        presig_len = presig.len(); // now includes the 16-byte salt
        sig_len = sig.proof.len();
    }

    let n = ITERS as f64;

    // Build the summary once, then send it to BOTH stdout and a per-parameter
    // file: bench_results/nibs_lowmc_<name>.txt. Distinct from the Rain-era
    // nibs_<name>.txt so both columns survive for the comparison section.
    let summary = format!(
        "================ NIBS LowMC+MAYO [{name}] ================\n\
         lowmc setup (one-time, shared): {:.3} ms\n\
         keygen_signer      : {:.3} ms\n\
         keygen_recipient   : {:.3} ms\n\
         issue              : {:.3} ms\n\
         obtain (prove)     : {:.3} ms\n\
         verify             : {:.3} ms\n\
         presignature |Spre| : {:.3} KB\n\
         signature    |sigma|: {:.3} KB\n\
         iterations (mean over): {}\n\
         instances: PRF(256,256,85,13r,d=2^64)  HASH(256,256,85,22r,d=2^256)  Gad2=Rain(512,7r)\n\
         ==========================================================\n",
        setup_ms,
        t_ks / n,
        t_kr / n,
        t_issue / n,
        t_obtain / n,
        t_verify / n,
        presig_len as f64 / 1024.0,
        sig_len as f64 / 1024.0,
        ITERS,
    );

    // stdout (visible during the run)
    println!("\n{summary}");

    // per-parameter file
    let mut path = PathBuf::from("bench_results");
    if let Err(e) = fs::create_dir_all(&path) {
        eprintln!("[{name}] could not create bench_results/: {e}");
        return;
    }
    path.push(format!("nibs_lowmc_{name}.txt"));
    match fs::File::create(&path).and_then(|mut file| file.write_all(summary.as_bytes())) {
        Ok(()) => println!("[{name}] summary written to {}", path.display()),
        Err(e) => eprintln!("[{name}] could not write {}: {e}", path.display()),
    }
}

fn bench_all(c: &mut Criterion) {
    // One-time LowMC instantiation: timed here, reported in every summary,
    // and NEVER inside a timed closure. Idempotent thereafter.
    let start = Instant::now();
    lowmc_setup();
    let setup_ms = start.elapsed().as_secs_f64() * 1_000.0;
    println!("lowmc_setup (one-time instance generation): {setup_ms:.1} ms");

    for (name, zk) in PARAM_SETS {
        let mut f = build_fixture(*zk);

        // one-shot human-readable summary (means + sizes)
        print_summary(name, &mut f, setup_ms);

        let mut group = c.benchmark_group(format!("nibs_lowmc/{name}"));

        // keygen_signer (MAYO keygen -- unchanged from Rain version)
        group.bench_function("keygen_signer", |b| {
            b.iter(|| black_box(f.bs.keygen_signer()))
        });

        // keygen_recipient: skR <-$ {0,1}^256, pkR = E^PRF_skR(PT_PK)
        group.bench_function("keygen_recipient", |b| {
            b.iter(|| black_box(f.bs.keygen_recipient()))
        });

        // issue: signer samples the nonce, derives com (LowMC-MMO) and
        // MAYO-signs it (the non-interactive step: needs only pkR)
        group.bench_function("issue", |b| {
            b.iter(|| black_box(f.bs.issue(&f.sk, &f.pk_r)))
        });

        // obtain: the recipient's proving step (the expensive one -- VOLEitH)
        group.bench_function("obtain", |b| {
            // each iteration needs a fresh presignature + a fresh epk buffer,
            // generated OUTSIDE the timed closure via iter_batched.
            b.iter_batched(
                || {
                    let (presig, nonce) = f.bs.issue(&f.sk, &f.pk_r);
                    let epk = f.bs.mayo.expand_pk(&f.pk);
                    let add_r = [0xffu8; 32];
                    (presig, nonce, epk, add_r)
                },
                |(presig, nonce, mut epk, mut add_r)| {
                    black_box(f.bs.obtain(
                        &f.pk, &mut epk, &f.sk_r, &presig, &nonce, &mut add_r,
                    ))
                },
                criterion::BatchSize::SmallInput,
            )
        });

        // verify: public verification of the blind signature
        group.bench_function("verify", |b| {
            b.iter_batched(
                || {
                    let (presig, nonce) = f.bs.issue(&f.sk, &f.pk_r);
                    let mut epk = f.bs.mayo.expand_pk(&f.pk);
                    let mut add_r = [0xffu8; 32];
                    let (m, sig) = f
                        .bs
                        .obtain(&f.pk, &mut epk, &f.sk_r, &presig, &nonce, &mut add_r);
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
