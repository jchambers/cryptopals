use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;
use cryptopals::random::MersenneTwister;

fn main() {
    let (seed_time, sweep_time, random_value) = {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let seed_time = start_time +
            (rand::thread_rng().next_u64() % 3_600_000) +
            (rand::thread_rng().next_u64() % 30_000);

        let sweep_time = seed_time +
            (rand::thread_rng().next_u64() % 3_600_000) +
            (rand::thread_rng().next_u64() % 30_000);

        (seed_time, sweep_time, MersenneTwister::new(seed_time as u32).next_u32())
    };

    for t in sweep_time - 7_260_000..=sweep_time {
        if MersenneTwister::new(t as u32).next_u32() == random_value {
            println!("Seed: {}", t);
            assert_eq!(seed_time, t);
            break;
        }
    }
}
