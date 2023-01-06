use std::cmp::Ordering;

#[derive(Debug)]
pub struct Fraction {
    numerator: u64,
    denominator: u64,
}

impl Fraction {
    pub fn new(numerator: u64, denominator: u64) -> Self {
        Fraction { numerator, denominator }
    }
}

impl Eq for Fraction {
}

impl PartialEq<Self> for Fraction {
    fn eq(&self, other: &Self) -> bool {
        self.numerator * other.denominator == other.numerator * self.denominator
    }
}

impl Ord for Fraction {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.numerator * other.denominator).cmp(&(other.numerator * self.denominator))
    }
}

impl PartialOrd<Self> for Fraction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod test {
    use crate::fraction::Fraction;

    #[test]
    fn test_eq() {
        assert_eq!(Fraction::new(1, 2), Fraction::new(84, 168));
        assert_ne!(Fraction::new(1, 2), Fraction::new(84, 169));
    }

    #[test]
    fn test_cmp() {
        assert!(Fraction::new(1, 2) < Fraction::new(2, 3));
        assert!(Fraction::new(1, 3) > Fraction::new(9, 30));
    }
}