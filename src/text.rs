use std::collections::HashMap;

const MOST_FREQUENT_CHARACTERS: &str = " etaoinshrdlu";

pub fn deviation_from_expected_frequency(string: &str) -> usize {
    let character_counts: HashMap<char, u32> = string.to_lowercase().chars()
            .fold(HashMap::new(), |mut character_counts, c| {
                *character_counts.entry(c).or_insert(0) += 1;
                character_counts
            });

    let mut character_counts: Vec<(char, u32)> = character_counts
        .into_iter()
        .collect();

    character_counts.sort_by_key(|(_, count)| *count);
    character_counts.reverse();

    println!("Character counts: {:?}", character_counts);

    let sorted: String = character_counts
        .iter()
        .take(MOST_FREQUENT_CHARACTERS.len())
        .map(|(c, _)| c)
        .collect();

    println!("Sorted: {}", sorted);
    println!("Deviation: {}", levenshtein::levenshtein(MOST_FREQUENT_CHARACTERS, &sorted));

    levenshtein::levenshtein(MOST_FREQUENT_CHARACTERS, &sorted)
}

#[cfg(test)]
mod test {
    use crate::text::deviation_from_expected_frequency;

    #[test]
    fn test_deviation_from_expected_frequency() {
        assert!(deviation_from_expected_frequency("This is a relatively normal string of English text") <
            deviation_from_expected_frequency("jkdbfnjkvndkvlbmsidfnuvndfnvblskdnblkd")
        );
    }
}
