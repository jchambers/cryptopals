fn main() {
    let mut mt = cryptopals::random::MersenneTwister::new(749308573);

    for _ in 0..10 {
        println!("{}", mt.next_u32());
    }
}
