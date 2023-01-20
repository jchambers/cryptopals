use rand::RngCore;
use cryptopals::random::MersenneTwister;

const L: u32 = 18;
const T: u32 = 15;
const C: u32 = 0xefc60000;
const S: u32 = 7;
const B: u32 = 0x9d2c5680;
const U: u32 = 11;

fn main() {
    let mut original = MersenneTwister::new(rand::thread_rng().next_u32());
    let mut cloned_state = [0; 624];

    for i in 0..cloned_state.len() {
        cloned_state[i] = untemper(original.next_u32());
    }

    let mut cloned = MersenneTwister::from(cloned_state);

    for _ in 0..1024 {
        assert_eq!(original.next_u32(), cloned.next_u32());
    }
}

fn untemper(y: u32) -> u32 {
    let mut x = untemper_right_shift(y, L);
    x = untemper_left_shift(x, T, C);
    x = untemper_left_shift(x, S, B);
    untemper_right_shift(x, U)
}

fn untemper_right_shift(y: u32, shift_magnitude: u32) -> u32 {
    // Right shifts take the form:
    //
    // y = x ^ (x >> shift_magnitude)
    //
    // One really important observation here is that, if we're shifting a thing right, we know that
    // the highest shift_magnitude bits in the result are all going to be zero, and if we're xor-ing
    // that result with the original value, then the first shift_magnitude bits of THAT result
    // are going to be the unchanged, original bits from the input value.
    let mut x = y & u32::MAX << (u32::BITS - shift_magnitude);

    // Then, for all of the lower bits, we know that:
    //
    //     y_N = x_(N - shift_magnitude) ^ x_N
    // ==> x_N = y_N ^ x_(N - shift_magnitude)

    let mut bit_mask = 1 << (u32::BITS - shift_magnitude);

    while bit_mask != 0 {
        x |= (y ^ (x >> shift_magnitude)) & bit_mask;
        bit_mask >>= 1;
    }

    x
}

fn untemper_left_shift(y: u32, shift_magnitude: u32, mask: u32) -> u32 {
    // Left shifts take the form:
    //
    // y = x ^ ((x << shift_magnitude) & mask)
    //
    // We can borrow a lot from the right shift untempering function; if we're shifting x to the
    // left, we know that the LOWER shift_magnitude bits will be unchanged and only the UPPER bits
    // of the mask come into play. We're still doing the one-bit-at-a-time xor thing, but now the
    // thing we're xor-ing also has that and operation with a mask.
    let mut x = y & ((1 << shift_magnitude) - 1);

    let mut bit_mask = 1 << shift_magnitude;

    while bit_mask != 0 {
        x |= (y ^ ((x << shift_magnitude) & mask)) & bit_mask;
        bit_mask <<= 1;
    }

    x
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use crate::*;

    #[test]
    fn test_untemper_right_shift() {
        for _ in 0..1024 {
            let x = rand::thread_rng().next_u32();

            for magnitude in 1..32 {
                let y = x ^ (x >> magnitude);
                assert_eq!(x, untemper_right_shift(y, magnitude));
            }
        }
    }

    #[test]
    fn test_untemper_left_shift() {
        for _ in 0..1024 {
            let x = rand::thread_rng().next_u32();
            let mask = rand::thread_rng().next_u32();

            for magnitude in 1..32 {
                let y = x ^ ((x << magnitude) & mask);
                assert_eq!(x, untemper_left_shift(y, magnitude, mask));
            }
        }
    }

    fn temper(x: u32) -> u32 {
        let mut y = x;

        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        y
    }

    #[test]
    fn test_untemper() {
        for _ in 0..1024 {
            let x = rand::thread_rng().next_u32();

            assert_eq!(x, untemper(temper(x)));
        }
    }
}
