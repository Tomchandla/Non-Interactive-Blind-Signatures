// Run:
//     RUST_MIN_STACK=8388608 cargo bench --bench blind_sig_conservative_rain

use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use blind_signatures_conservative_rain::blind_sig_conservative_rain::NibsLowmc;
use blind_signatures_conservative_rain::derive::lowmc_setup;
use blind_signatures_conservative_rain::zk::ZKType;

const PARAM_SETS: &[(&str, ZKType)] = &[
    ("FV1_128", ZKType::FV1_128),
    ("FV2_128", ZKType::FV2_128),
    ("SV1_128", ZKType::SV1_128),
    ("SV2_128", ZKType::SV2_128),
];

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

fn print_summary(name: &str, f: &mut Fixture, setup_ms: f64) {
    const ITERS: u32 = 20;
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
        // issue = nonce sampling + two-block Rain target hash on
        //         pkR || nonce || salt + MAYO preimage sampling
        let (presig, nonce) = f.bs.issue(&sk, &f.pk_r);
        t_issue += start.elapsed().as_secs_f64() * 1_000.0;

        // expand_pk is not part of any timed phase; do it between timers
        let mut epk = f.bs.mayo.expand_pk(&pk);

        let start = Instant::now();
        // obtain = witness expansion (26 LowMC rounds of bit-matrix products
        // + two 7-round Rain blocks, in the clear) + the VOLEitH prove.
        let (m, mut sig) = f
            .bs
            .obtain(&pk, &mut epk, &f.sk_r, &presig, &nonce, &mut f.additional_r);
        t_obtain += start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        assert!(f.bs.verify(&mut epk, &m, &mut sig, &mut f.additional_r));
        t_verify += start.elapsed().as_secs_f64() * 1_000.0;

        presig_len = presig.len(); // includes MAYO1's 24-byte salt
        sig_len = sig.proof.len();
    }

    let n = ITERS as f64;

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
         instances: PRF(256,256,85,13r,d=2^64)  Gad2=Rain2(512,7r x2 blocks)\n\
         [22r HASH instance generated for PRG-stream stability; unused by the scheme]\n\
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
    
    println!("\n{summary}");

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
    let start = Instant::now();
    lowmc_setup();
    let setup_ms = start.elapsed().as_secs_f64() * 1_000.0;
    println!("lowmc_setup (one-time instance generation): {setup_ms:.1} ms");

    for (name, zk) in PARAM_SETS {
        let mut f = build_fixture(*zk);
        
        print_summary(name, &mut f, setup_ms);

        let mut group = c.benchmark_group(format!("nibs_lowmc/{name}"));

        group.bench_function("keygen_signer", |b| {
            b.iter(|| black_box(f.bs.keygen_signer()))
        });

        group.bench_function("keygen_recipient", |b| {
            b.iter(|| black_box(f.bs.keygen_recipient()))
        });

        group.bench_function("issue", |b| {
            b.iter(|| black_box(f.bs.issue(&f.sk, &f.pk_r)))
        });

        group.bench_function("obtain", |b| {
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
