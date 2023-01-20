const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908b0df;
const U: u8 = 11;
const D: u32 = 0xffffffff;
const S: u8 = 7;
const B: u32 = 0x9d2c5680;
const T: u8 = 15;
const C: u32 = 0xefc60000;
const L: u8 = 18;
const F: u32 = 1812433253;

const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MersenneTwister {
    state: [u32; N],
    index: usize,
}

impl MersenneTwister {
    pub fn new(seed: u32) -> Self {
        let mut state = [0; N];
        state[0] = seed;

        for i in 1..state.len() {
            state[i] = F.wrapping_mul(state[i - 1] ^ (state[i - 1] >> (u32::BITS - 2))).wrapping_add(i as u32);
        }

        Self {
            state,
            index: N,
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index == N {
            self.twist();
        }

        let mut y = self.state[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;

        y
    }

    fn twist(&mut self) {
        for i in 0..self.state.len() {
            let x = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;

            if x % 2 != 0 {
                x_a ^= A;
            }

            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }

        self.index = 0;
    }
}

impl From<[u32; N]> for MersenneTwister {
    fn from(state: [u32; N]) -> Self {
        Self {
            state,
            index: N,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::random::MersenneTwister;

    // Test vectors via https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
    const EXPECTED_VALUES: [u32; 10] = [
        3521569528,
        1101990581,
        1076301704,
        2948418163,
        3792022443,
        2697495705,
        2002445460,
        502890592,
        3431775349,
        1040222146,
    ];

    #[test]
    fn test_next() {
        let mut mt = MersenneTwister::new(1131464071);

        for i in 0..10 {
            assert_eq!(EXPECTED_VALUES[i], mt.next_u32());
        }
    }
}
