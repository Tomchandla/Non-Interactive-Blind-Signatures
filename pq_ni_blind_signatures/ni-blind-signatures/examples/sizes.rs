// Print sizes and circuit statistics of every compiled NIBS instance.
//
//   cargo run --release --example sizes            # markdown table
//   cargo run --release --example sizes -- --csv

use ni_blind_signatures::zk::instance_info;
use ni_blind_signatures::NibsParams;

fn main() {
    let csv = std::env::args().any(|a| a == "--csv");
    if csv {
        println!("variant,zk,level,presig_bytes,sig_bytes,witness_bits,nibs_witness_bits,mayo_s_bits,lowmc_gadgets,rain_gadgets,target_blocks,constraints,tau");
    } else {
        println!("| Variant | ZK set | presig (B) | sigma (B) | sigma (KB) | witness bits (NIBS + s) | LowMC | Rain (T) | constraints |");
        println!("|---|---|---|---|---|---|---|---|---|");
    }
    for p in NibsParams::all() {
        let i = instance_info(&p);
        let presig = i.s_bytes + i.salt_bytes;
        if csv {
            println!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                p.variant_label(), p.zk.name(), p.zk.level(), presig, i.proof_bytes, i.witness_bits,
                i.nibs_witness_bits, i.mayo_s_bits, i.lowmc_gadgets, i.rain_gadgets, i.target_blocks,
                i.constraints, i.tau
            );
        } else {
            println!(
                "| {} | {} | {} | {} | {:.2} | {} ({} + {}) | {} | {} ({}) | {} |",
                p.variant_label(), p.zk.name(), presig, i.proof_bytes, i.proof_bytes as f64 / 1024.0,
                i.witness_bits, i.nibs_witness_bits, i.mayo_s_bits, i.lowmc_gadgets, i.rain_gadgets,
                i.target_blocks, i.constraints
            );
        }
    }
}
