#[cfg(any(feature = "std", test))]
use std::{string::String, vec::Vec};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::{string::String, vec::Vec};

use hmac::Hmac;
use lazy_static::lazy_static;
use parity_scale_codec::Encode;
use pbkdf2::pbkdf2;
use regex::Regex;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::Error;

pub const HASH_LEN: usize = 32;

pub fn blake2_256(bytes: &[u8]) -> [u8; HASH_LEN] {
    blake2b_simd::Params::new()
        .hash_length(HASH_LEN)
        .hash(bytes)
        .as_bytes()
        .try_into()
        .expect("static length, always fits")
}

/// Verbatim from `substrate-bip39`.
pub fn entropy_to_big_seed(entropy: &[u8], password: &str) -> Result<[u8; 64], Error> {
    if entropy.len() < 16 || entropy.len() > 32 || entropy.len() % 4 != 0 {
        return Err(Error::InvalidEntropy);
    }

    let mut salt = String::with_capacity(8 + password.len());
    salt.push_str("mnemonic");
    salt.push_str(password);

    let mut seed = [0u8; 64];

    let result = pbkdf2::<Hmac<Sha512>>(entropy, salt.as_bytes(), 2048, &mut seed);

    salt.zeroize();

    if result.is_ok() {
        Ok(seed)
    } else {
        Err(Error::Pbkdf2Internal)
    }
}

lazy_static! {
    static ref REG_PATH_PWD: Regex =
        Regex::new(r"^(?P<path>(//?[^/]+)*)(///(?P<password>.+))?$").expect("checked value");
    static ref REG_DERIVATION: Regex =
        Regex::new(r"/(?P<derivation>/?[^/]+)").expect("checked value");
}

#[derive(Debug)]
pub enum DeriveJunction {
    Hard([u8; HASH_LEN]),
    Soft([u8; HASH_LEN]),
}

fn derive_junction_inner<T: Encode>(input: T) -> [u8; HASH_LEN] {
    input.using_encoded(|encoded_input| {
        if encoded_input.len() > HASH_LEN {
            blake2_256(encoded_input)
        } else {
            let mut out = [0u8; HASH_LEN];
            out[0..encoded_input.len()].copy_from_slice(encoded_input);
            out
        }
    })
}

impl DeriveJunction {
    pub fn soft<T: Encode>(input: T) -> Self {
        DeriveJunction::Soft(derive_junction_inner(input))
    }
    pub fn hard<T: Encode>(input: T) -> Self {
        DeriveJunction::Hard(derive_junction_inner(input))
    }
    pub fn is_soft(&self) -> bool {
        matches!(self, DeriveJunction::Soft(_))
    }
    pub fn is_hard(&self) -> bool {
        matches!(self, DeriveJunction::Hard(_))
    }
    pub fn inner(&self) -> [u8; HASH_LEN] {
        match self {
            DeriveJunction::Hard(inner) | DeriveJunction::Soft(inner) => *inner,
        }
    }
}

#[derive(Debug)]
pub struct FullDerivation<'a> {
    pub junctions: Vec<DeriveJunction>,
    pub password: Option<&'a str>,
}

pub fn cut_path(path_and_pwd: &str) -> Option<FullDerivation<'_>> {
    match REG_PATH_PWD.captures(path_and_pwd) {
        Some(caps) => {
            let junctions = {
                if let Some(path) = caps.name("path") {
                    REG_DERIVATION
                        .captures_iter(path.as_str())
                        .map(|caps| {
                            let derivation = caps.name("derivation").expect("");
                            if derivation.as_str().starts_with('/') {
                                DeriveJunction::hard(&derivation.as_str()[1..])
                            } else {
                                DeriveJunction::soft(derivation.as_str())
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            };
            let password = caps.name("password").map(|a| a.as_str());
            Some(FullDerivation {
                junctions,
                password,
            })
        }
        None => None,
    }
}

pub const ALICE_WORDS: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

#[cfg(any(feature = "std", test))]
#[cfg(test)]
mod tests {

    use mnemonic_external::{regular::InternalWordList, WordSet};
    use sp_core::crypto::DeriveJunction;

    use crate::common::{cut_path, entropy_to_big_seed, ALICE_WORDS};

    #[test]
    fn cut_path_test() {
        let path_and_pwd =
        "//alice/soft//hard//some_extraordinarily_long_derivation_just_for_test///secret_password";
        let cut = cut_path(path_and_pwd).unwrap();
        assert_eq!(cut.junctions.len(), 4);
        assert!(cut.junctions[0].is_hard());
        assert_eq!(
            cut.junctions[0].inner(),
            DeriveJunction::hard("alice").unwrap_inner()
        );
        assert!(cut.junctions[1].is_soft());
        assert_eq!(
            cut.junctions[1].inner(),
            DeriveJunction::soft("soft").unwrap_inner()
        );
        assert!(cut.junctions[2].is_hard());
        assert_eq!(
            cut.junctions[2].inner(),
            DeriveJunction::hard("hard").unwrap_inner()
        );
        assert!(cut.junctions[3].is_hard());
        assert_eq!(
            cut.junctions[3].inner(),
            DeriveJunction::hard("some_extraordinarily_long_derivation_just_for_test")
                .unwrap_inner()
        );
        assert_eq!(cut.password.unwrap(), "secret_password");
    }

    #[test]
    fn big_seed_works() {
        // phrase-to-entropy, with `mnemonic-external`
        let internal_word_list = InternalWordList;
        let mut word_set = WordSet::new();
        for word in ALICE_WORDS.split(' ') {
            word_set.add_word(word, &internal_word_list).unwrap();
        }
        let entropy = word_set.to_entropy().unwrap();

        assert!(entropy_to_big_seed(&entropy, "").is_ok())
    }
}
