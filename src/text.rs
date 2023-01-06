use std::collections::HashSet;
use crate::fraction::Fraction;

const MOST_FREQUENT_CHARACTERS: &str = "etaoin shrdlu";
const _WORDS_FILE: &str = "/usr/share/dict/words";

pub fn englishiness(string: &str) -> Fraction {
    let common_characters: HashSet<char> = MOST_FREQUENT_CHARACTERS
        .chars()
        .collect();

    let common_character_count = string
        .chars()
        .filter(|c| common_characters.contains(c))
        .count();

    Fraction::new(common_character_count as u64, string.len() as u64)
}

#[cfg(test)]
mod test {
    use crate::text::englishiness;

    #[test]
    fn test_englishiness() {
        assert!(englishiness("This is a relatively normal string of English text") >
            englishiness("jkdbfnjkvndkvlbmsidfnuvndfnvblskdnblkd")
        );
    }
}
