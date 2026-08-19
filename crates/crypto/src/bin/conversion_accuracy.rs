//! RQ5 conversion-accuracy sweep: numerical simulation of the H2S/S2H truncation-and-wrap
//! error model in Section 3 (Eqs. h2s-wrap-bit / h2s-effective-error / s2h-wrap-error).
//!
//! For each (noise/Delta, rho/Delta) point we sample canonical x, r in [0,q) and the
//! normalized total noise e/Delta uniformly in [-noise, noise], then count the fraction of
//! conversions whose effective error `round(e +- omega*rho)` is nonzero (a "mismatch").

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

fn main() {
    let params = [
        (0.05_f64, 0.00_f64),
        (0.20, 0.10),
        (0.40, 0.15),
        (0.55, 0.20),
    ];
    let trials = 100_000_u64;
    let mut rng = StdRng::seed_from_u64(0);

    println!("Noise/Delta,Rho/Delta,Trials,H2S(%),S2H(%)");
    for (noise, rho) in params {
        let mut h2s = 0_u64;
        let mut s2h = 0_u64;
        for _ in 0..trials {
            // canonical x, r in [0,1) (scaled by q); delta = x - r, symmetric.
            let x = rng.gen::<f64>();
            let r = rng.gen::<f64>();
            let delta = x - r;
            // omega is the borrow bit: omega = 1[delta < 0] (e/Delta negligible at delta ~ 0).
            let omega = if delta < 0.0 { 1.0 } else { 0.0 };

            // H2S: eps = round(e_tot/Delta + omega * rho/Delta).
            let e = (rng.gen::<f64>() * 2.0 - 1.0) * noise;
            if (e + omega * rho).round() != 0.0 {
                h2s += 1;
            }

            // S2H: eps = round(e_r/Delta - omega * rho/Delta).
            let er = (rng.gen::<f64>() * 2.0 - 1.0) * noise;
            if (er - omega * rho).round() != 0.0 {
                s2h += 1;
            }
        }
        println!(
            "{:.2},{:.2},{},{:.3},{:.3}",
            noise,
            rho,
            trials,
            h2s as f64 / trials as f64 * 100.0,
            s2h as f64 / trials as f64 * 100.0
        );
    }
}
