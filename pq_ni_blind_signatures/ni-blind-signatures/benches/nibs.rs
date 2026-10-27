// NIBS benchmarks across both frameworks and all NIST levels.
//
//   RUST_MIN_STACK=8388608 cargo bench --bench nibs
//
// Environment knobs (all optional):
//   NIBS_BENCH_ITERS=50              timed runs per phase (mean is reported)
//   NIBS_BENCH_ZK=SV1_128,FV1_192    VOLEitH sets (default: all 12)
//   NIBS_BENCH_VARIANTS=BCGY,sPRP    frameworks (default: both)
//   NIBS_BENCH_CRITERION=1           also run Criterion on obtain/verify
//
// Output: one box per instance on stdout, bench_results/<framework>_<zk>.txt,
// and bench_results/summary.md / summary.csv with one row per instance.

use criterion::{criterion_group, criterion_main, Criterion};
use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ni_blind_signatures::{Nibs, NibsParams, ZKType};

fn env_list(name: &str) -> Option<Vec<String>> {
    std::env::var(name)
        .ok()
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

fn selected() -> Vec<NibsParams> {
    let zks: Vec<ZKType> = match env_list("NIBS_BENCH_ZK") {
        Some(names) => names.iter().map(|n| ZKType::from_name(n).expect("unknown ZK set")).collect(),
        None => ZKType::ALL.to_vec(),
    };
    let variants = env_list("NIBS_BENCH_VARIANTS");
    let mut out = Vec::new();
    for zk in zks {
        for p in NibsParams::variants(zk) {
            if variants.as_ref().is_none_or(|v| v.iter().any(|x| x.eq_ignore_ascii_case(p.variant_label()))) {
                out.push(p);
            }
        }
    }
    out
}

fn iters() -> u32 {
    std::env::var("NIBS_BENCH_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(50)
}

#[derive(Default)]
struct Timings {
    keygen_signer: f64,
    keygen_recipient: f64,
    issue: f64,
    obtain: f64,
    verify: f64,
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

fn measure(bs: &Nibs, n: u32) -> Timings {
    let (pk, sk) = bs.keygen_signer();
    let epk = bs.expand_pk(&pk);
    let (pk_r, sk_r) = bs.keygen_recipient();
    for _ in 0..3 {
        let (ps, nonce) = bs.issue(&sk, &pk_r);
        let (m, sig) = bs.obtain(&pk, &epk, &sk_r, &ps, &nonce).unwrap();
        assert!(bs.verify(&pk, &epk, &m, &sig), "warm-up round trip failed");
    }
    let mut t = Timings::default();
    for _ in 0..n {
        let s = Instant::now();
        black_box(bs.keygen_signer());
        t.keygen_signer += ms(s);

        let s = Instant::now();
        black_box(bs.keygen_recipient());
        t.keygen_recipient += ms(s);

        let s = Instant::now();
        let (ps, nonce) = bs.issue(&sk, &pk_r);
        t.issue += ms(s);

        let s = Instant::now();
        let (m, sig) = bs.obtain(&pk, &epk, &sk_r, &ps, &nonce).unwrap();
        t.obtain += ms(s);

        let s = Instant::now();
        assert!(bs.verify(&pk, &epk, &m, &sig));
        t.verify += ms(s);
    }
    let k = n as f64;
    Timings {
        keygen_signer: t.keygen_signer / k,
        keygen_recipient: t.keygen_recipient / k,
        issue: t.issue / k,
        obtain: t.obtain / k,
        verify: t.verify / k,
    }
}

fn report(p: &NibsParams, bs: &Nibs, t: &Timings, n: u32) -> String {
    let i = &bs.info;
    let rule = "─".repeat(60);
    let mut s = String::new();
    let _ = writeln!(s, "┌{rule}┐");
    let _ = writeln!(s, "│ {:<58} │", format!("NIBS {}  (LowMC + MAYO + RainHash + VOLEitH)", p));
    let _ = writeln!(s, "├{rule}┤");
    let _ = writeln!(s, "│ {:<58} │", format!("Phase                               mean over {n} runs"));
    for (label, v) in [
        ("KeyGen_S", t.keygen_signer),
        ("KeyGen_R", t.keygen_recipient),
        ("Issue", t.issue),
        ("Obtain (prove)", t.obtain),
        ("Verify", t.verify),
    ] {
        let _ = writeln!(s, "│   {:<34}{:>17.3} ms │", label, v);
    }
    let _ = writeln!(s, "├{rule}┤");
    for (label, b) in [
        ("presignature |sigma_pre|", bs.presignature_bytes()),
        ("signature |sigma|", bs.signature_bytes()),
        ("receiver pk_R", i.pkr_bytes),
        ("message m", i.m_bytes),
        ("nonce r", i.r_bytes),
    ] {
        let _ = writeln!(s, "│   {:<30}{:>10.3} KB {:>9} B │", label, b as f64 / 1024.0, b);
    }
    let _ = writeln!(s, "├{rule}┤");
    let _ = writeln!(
        s,
        "│   {:<56} │",
        format!("witness {} bits = {} NIBS + {} MAYO s", i.witness_bits, i.nibs_witness_bits, i.mayo_s_bits)
    );
    let _ = writeln!(
        s,
        "│   {:<56} │",
        format!(
            "{} LowMC + {} Rain gadgets ({} for the target), {} constraints",
            i.lowmc_gadgets, i.rain_gadgets, i.target_blocks, i.constraints
        )
    );
    let _ = writeln!(s, "│   {:<56} │", format!("VOLEitH tau = {}", i.tau));
    let _ = writeln!(s, "└{rule}┘");
    s
}

fn bench_all(c: &mut Criterion) {
    let n = iters();
    let dir = PathBuf::from("bench_results");
    let _ = fs::create_dir_all(&dir);
    let mut md = String::from(
        "| Variant | ZK set | KeyGen_S | KeyGen_R | Issue | Obtain | Verify | presig (B) | sigma (B) | sigma (KB) | witness bits |\n|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    let mut csv = String::from(
        "variant,zk,level,keygen_s_ms,keygen_r_ms,issue_ms,obtain_ms,verify_ms,presig_bytes,sig_bytes,witness_bits,nibs_witness_bits,constraints\n",
    );

    for p in selected() {
        let bs = Nibs::setup(p);
        let t = measure(&bs, n);
        let box_ = report(&p, &bs, &t, n);
        println!("\n{box_}");
        let fname = format!("{}_{}.txt", p.variant_label().replace('+', "_"), p.zk.name());
        let _ = fs::write(dir.join(fname), &box_);
        let i = &bs.info;
        let _ = writeln!(
            md,
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} | {:.2} | {} |",
            p.variant_label(),
            p.zk.name(),
            t.keygen_signer,
            t.keygen_recipient,
            t.issue,
            t.obtain,
            t.verify,
            bs.presignature_bytes(),
            bs.signature_bytes(),
            bs.signature_bytes() as f64 / 1024.0,
            i.witness_bits
        );
        let _ = writeln!(
            csv,
            "{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{},{},{},{},{}",
            p.variant_label(),
            p.zk.name(),
            p.zk.level(),
            t.keygen_signer,
            t.keygen_recipient,
            t.issue,
            t.obtain,
            t.verify,
            bs.presignature_bytes(),
            bs.signature_bytes(),
            i.witness_bits,
            i.nibs_witness_bits,
            i.constraints
        );
        let _ = fs::write(dir.join("summary.md"), &md);
        let _ = fs::write(dir.join("summary.csv"), &csv);

        if std::env::var("NIBS_BENCH_CRITERION").is_ok() {
            let (pk, sk) = bs.keygen_signer();
            let epk = bs.expand_pk(&pk);
            let (pk_r, sk_r) = bs.keygen_recipient();
            let mut g = c.benchmark_group(format!("nibs/{}/{}", p.variant_label(), p.zk.name()));
            g.sample_size(20).measurement_time(Duration::from_secs(20));
            g.bench_function("obtain", |b| {
                b.iter_batched(
                    || bs.issue(&sk, &pk_r),
                    |(ps, nonce)| black_box(bs.obtain(&pk, &epk, &sk_r, &ps, &nonce)),
                    criterion::BatchSize::SmallInput,
                )
            });
            let (ps, nonce) = bs.issue(&sk, &pk_r);
            let (m, sig) = bs.obtain(&pk, &epk, &sk_r, &ps, &nonce).unwrap();
            g.bench_function("verify", |b| b.iter(|| black_box(bs.verify(&pk, &epk, &m, &sig))));
            g.finish();
        }
    }
    println!("\n{md}");
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
