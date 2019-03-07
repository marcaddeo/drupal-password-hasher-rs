extern crate rand;
extern crate sha2;

use rand::RngCore;
use rand::os::OsRng;
use sha2::{Sha512, Digest};

pub trait PasswordHasher {
    const MAX_PASSWORD_LENGTH: usize = 512;

    fn hash(&self, password: &str) -> Option<String>;
    fn check(&self, password: &str, hash: &str) -> bool;
}

pub struct DrupalPasswordHasher {
    count_log2: usize,
}

impl DrupalPasswordHasher {
    const MIN_HASH_COUNT: usize = 7;
    const MAX_HASH_COUNT: usize = 30;
    const HASH_LENGTH: usize = 55;
    const ALPHABET: &'static [char] = &[
        '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
        'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    ];

    pub fn new(count_log2: usize) -> Self {
        DrupalPasswordHasher {
           count_log2: Self::enforce_log2_boundaries(count_log2)
        }
    }

    fn enforce_log2_boundaries(count_log2: usize) -> usize {
        if count_log2 < Self::MIN_HASH_COUNT {
            Self::MIN_HASH_COUNT
        } else if count_log2 > Self::MAX_HASH_COUNT {
            Self::MAX_HASH_COUNT
        } else {
            count_log2
        }
    }

    fn base64_encode(input: &[u8], count: usize) -> String {
        let mut output: String = String::new();
        let mut i = 0;

        loop {
            let mut value: usize = input[i] as usize;
            i = i + 1;

            output.push(Self::ALPHABET[(value & 0x3F) as usize]);

            if i < count {
                value = value as usize | ((input[i] as usize) << 8);
            }

            output.push(Self::ALPHABET[((value as usize >> 6) as i32 & 0x3F) as usize]);

            if i >= count {
                break
            }
            i = i + 1;

            if i < count {
                value = value | ((input[i] as usize) << 16);
            }

            output.push(Self::ALPHABET[(((value as usize) >> 12) as i32 & 0x3F) as usize]);

            if i >= count {
                break
            }
            i = i + 1;

            output.push(Self::ALPHABET[(((value as usize) >> 18) as i32 & 0x3F) as usize]);

            if !(i < count) { break }
        }

        output
    }

    fn generate_salt(&self) -> String {
        let mut output = String::from("$S$");
        let mut rng = OsRng::new().unwrap();
        let mut random_bytes = vec![0u8; 6];
        rng.fill_bytes(&mut random_bytes);

        output.push(Self::ALPHABET[self.count_log2]);
        output.push_str(Self::base64_encode(&random_bytes, 6).as_str());

        output
    }

    fn crypt<D: Digest>(password: String, setting: &str) -> Option<String> {
        if password.chars().count() > Self::MAX_PASSWORD_LENGTH {
            return None;
        }

        let setting = &setting[..12];
        if &setting[..1] != "$" || &setting[2..3] != "$" {
            return None;
        }

        let count_log2 = Self::count_log2(setting);
        if count_log2 != Self::enforce_log2_boundaries(count_log2) {
            return None;
        }


        let salt = &setting[4..12];
        if salt.chars().count() != 8 {
            return None;
        }

        let mut count = 1 << count_log2;
        let mut hash;
        let mut hasher = D::new();
        hasher.input(salt);
        hasher.input(password.clone());
        hash = hasher.result_reset();

        loop {
            hasher.input(hash);
            hasher.input(password.clone());
            hash = hasher.result_reset();

            count = count - 1;

            if count <= 0 { break }
        }

        let mut output = String::from(setting);
        output.push_str(
            Self::base64_encode(hash.as_slice(), hash.len()).as_str()
        );

        let expected = 12 + (8.0 * hash.len() as f32 / 6.0).ceil() as i32;

        if output.chars().count() == expected as usize {
            return Some(String::from(&output[0..Self::HASH_LENGTH]));
        }

        None
    }

    fn count_log2(setting: &str) -> usize {
        let string: String = Self::ALPHABET.iter().cloned().collect::<String>();
        let setting: Vec<char> = setting.chars().collect();

        string.chars().position(|c| c == setting[3]).unwrap()
    }
}

impl PasswordHasher for DrupalPasswordHasher {
    fn hash(&self, password: &str) -> Option<String> {
        let password = String::from(password);
        let salt = self.generate_salt();

        return if let Some(hash) = Self::crypt::<Sha512>(password, &salt) {
            Some(String::from(hash))
        } else {
            None
        }
    }

    fn check(&self, password: &str, hash: &str) -> bool {
        let hash_type = &hash[0..3];

        let computed_hash = match hash_type {
            "$S$" => Self::crypt::<Sha512>(String::from(password), hash),
            _ => None,
        };

        // Check the hashes in constant time. This should not be optimized.
        if let Some(computed_hash) = computed_hash {
            let computed_hash_bytes = computed_hash.as_bytes();
            let hash_bytes = hash.as_bytes();

            let mut i = 0;
            let mut result = 0;
            while i < hash_bytes.len() {
                result = result | hash_bytes[i] ^ computed_hash_bytes[i];
                i += 1
            }

            return result == 0;
        } else {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        use super::*;

        let drupal_hasher = DrupalPasswordHasher::new(16);

        let stored_hash = "$S$ECw0enicwqDyCttylJNJ/iA6mZD.UGU8PwwHFFgGRK/iefY9HqSi";
        assert!(drupal_hasher.check("password", stored_hash));

        let stored_hash = "$S$E0yeIpFmXLNKlaCstd2PciVJuu48rW0fMgIEkW54sUsfVo7aREtW";
        assert!(drupal_hasher.check("admin", stored_hash));

        let hash = drupal_hasher.hash("password").unwrap();
        assert!(drupal_hasher.check("password", &hash));
    }
}
