#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use hmac::Hmac;
use lazy_static::lazy_static;
use parity_scale_codec::Encode;
use pbkdf2::pbkdf2;
use regex::Regex;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::Error;

/// Verbatim from `substrate-bip39`.
pub fn entropy_to_big_seed(entropy: &[u8], password: &str) -> Result<[u8; 64], Error> {
    if entropy.len() < 16 || entropy.len() > 32 || entropy.len() % 4 != 0 {
        return Err(Error::InvalidEntropy);
    }

    let mut salt = String::with_capacity(8 + password.len());
    salt.push_str("mnemonic");
    salt.push_str(password);

    let mut seed = [0u8; 64];

    pbkdf2::<Hmac<Sha512>>(entropy, salt.as_bytes(), 2048, &mut seed);

    salt.zeroize();

    Ok(seed)
}

pub const SIGNING_CTX: &[u8] = b"substrate";

lazy_static! {
    static ref REG_PATH_PWD: Regex =
        Regex::new(r"^(?P<path>(//?[^/]+)*)(///(?P<password>.+))?$").expect("checked value");
    static ref REG_DERIVATION: Regex =
        Regex::new(r"/(?P<derivation>/?[^/]+)").expect("checked value");
}

pub const JUNCTION_ID_LEN: usize = 32;

#[derive(Debug)]
pub enum DeriveJunction {
    Hard([u8; JUNCTION_ID_LEN]),
    Soft([u8; JUNCTION_ID_LEN]),
}

fn derive_junction_inner<T: Encode>(input: T) -> [u8; JUNCTION_ID_LEN] {
    input.using_encoded(|encoded_input| {
        if encoded_input.len() > JUNCTION_ID_LEN {
            blake2b_simd::Params::new()
                .hash_length(JUNCTION_ID_LEN)
                .hash(encoded_input)
                .as_bytes()
                .try_into()
                .expect("static length, always fits")
        } else {
            let mut out = [0u8; JUNCTION_ID_LEN];
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
    pub fn inner(&self) -> [u8; JUNCTION_ID_LEN] {
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
