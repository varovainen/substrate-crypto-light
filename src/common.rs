#[cfg(any(feature = "std", test))]
use std::{string::String, vec, vec::Vec};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::{string::String, vec, vec::Vec};

use base58::{FromBase58, ToBase58};
use hmac::Hmac;
use lazy_static::lazy_static;
use parity_scale_codec::Encode;
use pbkdf2::pbkdf2;
use regex::Regex;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::Error;

#[cfg(feature = "ecdsa")]
use crate::ecdsa::{Public as EcdsaPublic, PUBLIC_LEN as ECDSA_PUBLIC_LEN};

#[cfg(feature = "ed25519")]
use crate::ed25519::{Public as Ed25519Public, PUBLIC_LEN as ED25519_PUBLIC_LEN};

#[cfg(feature = "sr25519")]
use crate::sr25519::{Public as Sr25519Public, PUBLIC_LEN as SR25519_PUBLIC_LEN};

pub const ALICE_WORDS: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

pub const BIG_SEED_LEN: usize = 64;

pub const HASH_256_LEN: usize = 32;
pub const HASH_512_LEN: usize = 64;

pub const BASE58_ID: &[u8] = b"SS58PRE";
pub const BASE58_CHECKSUM_LEN: usize = 2;

pub fn blake2_256(bytes: &[u8]) -> [u8; HASH_256_LEN] {
    blake2b_simd::Params::new()
        .hash_length(HASH_256_LEN)
        .hash(bytes)
        .as_bytes()
        .try_into()
        .expect("static length, always fits")
}

fn ss58hash(data: &[u8]) -> [u8; HASH_512_LEN] {
    let mut blake2b_state = blake2b_simd::Params::new()
        .hash_length(HASH_512_LEN)
        .to_state();
    blake2b_state.update(BASE58_ID);
    blake2b_state.update(data);
    blake2b_state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("static length, always fits")
}

/// Verbatim from `substrate-bip39`.
pub fn entropy_to_big_seed(entropy: &[u8], password: &str) -> Result<[u8; BIG_SEED_LEN], Error> {
    if entropy.len() < 16 || entropy.len() > 32 || entropy.len() % 4 != 0 {
        return Err(Error::InvalidEntropy);
    }

    let mut salt = String::with_capacity(8 + password.len());
    salt.push_str("mnemonic");
    salt.push_str(password);

    let mut seed = [0u8; BIG_SEED_LEN];

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
    Hard([u8; HASH_256_LEN]),
    Soft([u8; HASH_256_LEN]),
}

fn derive_junction_inner<T: Encode>(input: T) -> [u8; HASH_256_LEN] {
    input.using_encoded(|encoded_input| {
        if encoded_input.len() > HASH_256_LEN {
            blake2_256(encoded_input)
        } else {
            let mut out = [0u8; HASH_256_LEN];
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
    pub fn inner(&self) -> [u8; HASH_256_LEN] {
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

pub trait AsBase58<const LEN: usize>: Sized {
    fn inner(&self) -> [u8; LEN];
    fn from_inner(inner: [u8; LEN]) -> Self;

    /// Same as `to_ss58check_with_version()` method for `Ss58Codec` from `sp_core`, comments from `sp_core`.
    fn to_base58_string(&self, base58prefix: u16) -> String {
        // We mask out the upper two bits of the ident - SS58 Prefix currently only supports 14-bits
        let ident: u16 = base58prefix & 0b0011_1111_1111_1111;
        let mut v = match ident {
            0..=63 => vec![ident as u8],
            64..=16_383 => {
                // upper six bits of the lower byte(!)
                let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
                // lower two bits of the lower byte in the high pos,
                // lower bits of the upper byte in the low pos
                let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
                vec![first | 0b0100_0000, second]
            }
            _ => unreachable!("masked out the upper two bits; qed"),
        };
        v.extend(self.inner());
        let r = ss58hash(&v);
        v.extend(&r[0..2]);
        v.to_base58()
    }

    /// Same as `from_ss58check_with_version()` method for `Ss58Codec` from `sp_core`, comments from `sp_core`.
    fn from_base58_string(base58_string: &str) -> Result<(Self, u16), Error> {
        let data = base58_string.from_base58().map_err(Error::Base58Decoding)?;
        if data.len() < 2 {
            return Err(Error::Base58Length);
        }
        let (prefix_len, prefix) = match data[0] {
            0..=63 => (1, data[0] as u16),
            64..=127 => {
                // weird bit manipulation owing to the combination of LE encoding and missing two
                // bits from the left.
                // d[0] d[1] are: 01aaaaaa bbcccccc
                // they make the LE-encoded 16-bit value: aaaaaabb 00cccccc
                // so the lower byte is formed of aaaaaabb and the higher byte is 00cccccc
                let lower = (data[0] << 2) | (data[1] >> 6);
                let upper = data[1] & 0b0011_1111;
                (2, (lower as u16) | ((upper as u16) << 8))
            }
            _ => return Err(Error::Base58Prefix),
        };
        if data.len() != prefix_len + LEN + BASE58_CHECKSUM_LEN {
            return Err(Error::Base58Length);
        }
        let hash = ss58hash(&data[..prefix_len + LEN]);
        if data[prefix_len + LEN..prefix_len + LEN + BASE58_CHECKSUM_LEN]
            != hash[..BASE58_CHECKSUM_LEN]
        {
            return Err(Error::Base58Checksum);
        }
        let inner = data[prefix_len..prefix_len + LEN]
            .try_into()
            .expect("static length, always fit");
        Ok((Self::from_inner(inner), prefix))
    }
}

pub const ACCOUNT_ID_32_LEN: usize = 32;

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AccountId32(pub [u8; ACCOUNT_ID_32_LEN]);

macro_rules! impl_as_base58 {
    ($($ty: ty, $len: expr), *) => {
        $(
            impl AsBase58<$len> for $ty {
                fn inner(&self) -> [u8; $len] {
                    self.0
                }
                fn from_inner(inner: [u8; $len]) -> Self {
                    Self(inner)
                }
            }
        )*
    }
}

impl_as_base58!(AccountId32, ACCOUNT_ID_32_LEN);

#[cfg(feature = "ecdsa")]
impl_as_base58!(EcdsaPublic, ECDSA_PUBLIC_LEN);

#[cfg(feature = "ed25519")]
impl_as_base58!(Ed25519Public, ED25519_PUBLIC_LEN);

#[cfg(feature = "sr25519")]
impl_as_base58!(Sr25519Public, SR25519_PUBLIC_LEN);

#[cfg(any(feature = "std", test))]
#[cfg(test)]
mod tests {

    use mnemonic_external::{regular::InternalWordList, WordSet};
    use sp_core::crypto::DeriveJunction;

    use crate::common::{cut_path, entropy_to_big_seed, AccountId32, AsBase58, ALICE_WORDS};

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

        assert!(entropy_to_big_seed(&entropy, "").is_ok());
    }

    #[test]
    fn from_base58() {
        let base58 = "5GCCgshTQCfGkXy6kAkFDW1TZXAdsbCNZJ9Uz2c7ViBnwcVg";
        let (account_id32, prefix) = AccountId32::from_base58_string(base58).unwrap();
        assert_eq!(
            hex::encode(account_id32.inner()),
            "b6a8b4b6bf796991065035093d3265e314c3fe89e75ccb623985e57b0c2e0c30"
        );
        assert_eq!(prefix, 42u16);
    }

    #[test]
    fn to_base58() {
        let account_id32 = AccountId32(
            hex::decode("b6a8b4b6bf796991065035093d3265e314c3fe89e75ccb623985e57b0c2e0c30")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let prefix = 42u16;
        let base58 = account_id32.to_base58_string(prefix);
        assert_eq!(base58, "5GCCgshTQCfGkXy6kAkFDW1TZXAdsbCNZJ9Uz2c7ViBnwcVg");
    }
}
