//! A fingerprint written as five words, for people to compare.
//!
//! The words are another way of writing the 48 bits of a [`Fingerprint`], not a
//! second value. Each of the 2^48 fingerprints has exactly one spelling and no
//! two share it, so no bits are lost and no modulo reduction can favour a word
//! sequence. The hex form stays what the API, the database and the audit log
//! carry, so stored fingerprints need no change and every warden version agrees
//! on them: see "The fingerprint" in `docs/agent-usage.md`.

use crate::Fingerprint;
use crate::wordlist::{COUNT, WORDS};

/// How many words a fingerprint is written in. Four hold under 42 bits; five
/// hold 51.7, so the 48 bits fit.
const LENGTH: usize = 5;

impl Fingerprint {
    /// This fingerprint as five hyphenated words: the 48 bits as one number,
    /// written in base 1296, least significant digit first.
    ///
    /// The first four words are spread over the whole list. The last holds what
    /// is left, under 7 bits, so it comes from the first 100 words. A person
    /// who compares only the start of a fingerprint still compares the most
    /// varied words.
    #[must_use]
    pub fn words(&self) -> String {
        let mut rest = self.bits();
        let mut words = Vec::with_capacity(LENGTH);
        for _ in 0..LENGTH {
            // A remainder of a division by the list's length: always an index
            // into it, so the default is never taken.
            let digit = usize::try_from(rest % COUNT).unwrap_or_default();
            words.push(WORDS[digit]);
            rest /= COUNT;
        }
        words.join("-")
    }

    /// The hex digits as a number. The type only holds `xxxx-xxxx-xxxx`, so
    /// the only character this skips is the hyphen.
    fn bits(&self) -> u64 {
        self.0
            .chars()
            .filter_map(|c| c.to_digit(16))
            .fold(0, |bits, digit| (bits << 4) | u64::from(digit))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};
    use std::fmt::Write as _;

    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};

    use super::{COUNT, Fingerprint, LENGTH, WORDS};
    use crate::{AgentName, CreateRequest, CreatedResponse, fingerprint};

    /// The SHA-256 of `eff_short_wordlist_2_0.txt` as EFF publishes it, at
    /// <https://www.eff.org/files/2016/09/08/eff_short_wordlist_2_0.txt>.
    const PUBLISHED_SHA256: &str =
        "22b45c52e0bd0bbf03aa522240b111eb4c7c0c1d86c4e518e1be2a7eb2a625e4";

    const LARGEST: u64 = (1 << 48) - 1;

    const VECTORS: &str = include_str!("../tests/fixtures/fingerprint-words-v1.json");

    #[derive(Deserialize)]
    struct Fixture {
        vectors: Vec<Vector>,
    }

    /// `agent` and `body` are absent where only the conversion is tested, for
    /// values no known request hashes to.
    #[derive(Deserialize)]
    struct Vector {
        name: String,
        agent: Option<String>,
        body: Option<String>,
        hex: String,
        words: String,
    }

    fn from_bits(bits: u64) -> Fingerprint {
        let hex = format!("{bits:012x}");
        Fingerprint::try_from(format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])).unwrap()
    }

    /// The number a spelling stands for, to check that nothing is lost.
    /// `yo-yo` is the one word with a hyphen.
    fn to_bits(words: &str) -> u64 {
        let protected = words.replace("yo-yo", "yo_yo");
        let digits: Vec<u64> = protected
            .split('-')
            .map(|word| {
                let word = word.replace('_', "-");
                let index = WORDS.iter().position(|known| *known == word).unwrap();
                u64::try_from(index).unwrap()
            })
            .collect();
        assert_eq!(digits.len(), LENGTH, "{words}");
        digits.iter().rev().fold(0, |bits, d| bits * COUNT + d)
    }

    #[test]
    fn list_is_the_published_file() {
        // The file is `<four dice>\t<word>\n` for each word, in order: rebuild
        // it, so the list can be compared with what EFF serves.
        let mut file = String::new();
        for (index, word) in WORDS.iter().enumerate() {
            let [a, b, c, d] = [216, 36, 6, 1].map(|place| index / place % 6 + 1);
            writeln!(file, "{a}{b}{c}{d}\t{word}").unwrap();
        }
        assert_eq!(hex::encode(Sha256::digest(&file)), PUBLISHED_SHA256);
    }

    #[test]
    fn list_has_the_properties_the_display_relies_on() {
        assert_eq!(u64::try_from(WORDS.len()).unwrap(), COUNT);
        assert_eq!(WORDS.iter().collect::<HashSet<_>>().len(), WORDS.len());
        for word in WORDS {
            // The approval page is sized for two of the longest on a line.
            assert!((3..=10).contains(&word.len()), "{word}");
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{word}"
            );
        }
        // The separator is inside one word, and neither half of it is a word,
        // so a spelling reads only one way.
        let hyphenated: Vec<_> = WORDS.iter().filter(|w| w.contains('-')).collect();
        assert_eq!(hyphenated, [&"yo-yo"]);
        assert!(!WORDS.contains(&"yo"));
    }

    fn edit_distance(a: &str, b: &str) -> usize {
        let mut row: Vec<usize> = (0..=b.len()).collect();
        for (i, x) in a.bytes().enumerate() {
            let mut diagonal = row[0];
            row[0] = i + 1;
            for (j, y) in b.bytes().enumerate() {
                let replace = diagonal + usize::from(x != y);
                diagonal = row[j + 1];
                row[j + 1] = replace.min(row[j] + 1).min(row[j + 1] + 1);
            }
        }
        row[b.len()]
    }

    /// Why this list: one misread or misheard letter never makes another of its
    /// words, as it would in EFF's list 1 (`bash`, `bath`). The measured minimum
    /// over all pairs is 3 edits.
    #[test]
    fn any_two_words_are_at_least_three_edits_apart() {
        let mut closest = usize::MAX;
        for (i, a) in WORDS.iter().enumerate() {
            for b in &WORDS[i + 1..] {
                closest = closest.min(edit_distance(a, b));
            }
        }
        assert_eq!(closest, 3);
    }

    #[test]
    fn no_two_words_start_with_the_same_three_letters() {
        let prefixes: HashSet<&str> = WORDS.iter().map(|word| &word[..3]).collect();
        assert_eq!(prefixes.len(), WORDS.len());
    }

    #[test]
    fn five_words_are_needed_and_hold_all_48_bits() {
        assert!(COUNT.pow(4) <= LARGEST, "four words would do");
        assert!(u128::from(COUNT).pow(5) > u128::from(LARGEST));
    }

    #[test]
    fn each_value_tried_has_its_own_spelling_and_comes_back() {
        // Multiples of an odd constant walk the whole range.
        let spread = (0..20_000u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4B) & LARGEST);
        let edges = [0, 1, 1295, 1296, LARGEST - 1, LARGEST];
        let values: BTreeSet<u64> = spread.chain(edges).collect();
        let mut spellings = HashSet::new();
        for bits in &values {
            let words = from_bits(*bits).words();
            assert_eq!(to_bits(&words), *bits, "{words}");
            spellings.insert(words);
        }
        assert_eq!(spellings.len(), values.len());
    }

    #[test]
    fn only_the_last_word_is_limited() {
        let largest = from_bits(LARGEST).words();
        let last = largest.rsplit('-').next().unwrap();
        assert_eq!(WORDS.iter().position(|word| *word == last), Some(99));
    }

    #[test]
    fn shared_vectors() {
        let fixture: Fixture = serde_json::from_str(VECTORS).unwrap();
        assert!(fixture.vectors.iter().any(|v| v.body.is_some()));
        for v in &fixture.vectors {
            let parsed = Fingerprint::try_from(v.hex.clone()).unwrap();
            assert_eq!(parsed.words(), v.words, "{}", v.name);
            if let (Some(agent), Some(body)) = (&v.agent, &v.body) {
                let agent = AgentName::try_from(agent.clone()).unwrap();
                let request: CreateRequest = serde_json::from_str(body).unwrap();
                assert_eq!(fingerprint(&agent, &request).as_str(), v.hex, "{}", v.name);
            }
        }
    }

    /// Older CLIs parse and compare this form, the audit log and the database
    /// hold it, and agents hash their way to it. The words are never on the wire.
    #[test]
    fn the_wire_form_stays_hex() {
        let created = CreatedResponse {
            id: "0".repeat(32).try_into().unwrap(),
            fingerprint: "42d5-403c-c2f0".to_owned().try_into().unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&created).unwrap(),
            format!(
                r#"{{"id":"{}","fingerprint":"42d5-403c-c2f0"}}"#,
                "0".repeat(32)
            )
        );
        let words = created.fingerprint.words();
        assert!(Fingerprint::try_from(words).is_err());
    }

    /// `docs/agent-protocol.md` shows the first vector in both forms.
    #[test]
    fn protocol_doc_shows_the_first_vector() {
        const DOC: &str = include_str!("../../../docs/agent-protocol.md");
        let fixture: Fixture = serde_json::from_str(VECTORS).unwrap();
        let first = &fixture.vectors[0];
        assert!(DOC.contains(&first.hex), "doc lacks {}", first.hex);
        assert!(DOC.contains(&first.words), "doc lacks {}", first.words);
    }
}
