//! Sr25519, mostly follows `sp_core::sr25519`.
//! Also supports external Rng.

use rand_core::{CryptoRng, RngCore};
use schnorrkel::{
    context::attach_rng,
    derive::{ChainCode, Derivation},
    signing_context, ExpansionMode, Keypair, MiniSecretKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    common::{entropy_to_big_seed, DeriveJunction, FullDerivation, SIGNING_CTX},
    error::Error,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Public(pub [u8; 32]);

impl Public {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let Ok(signature) = schnorrkel::Signature::from_bytes(signature.0.as_ref()) else {
            return false;
        };
        let Ok(public) = schnorrkel::PublicKey::from_bytes(self.0.as_ref()) else {
            return false;
        };
        public.verify_simple(SIGNING_CTX, msg, &signature).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Signature(pub [u8; 64]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pair(Keypair);

impl Pair {
    pub fn from_entropy_and_pwd(entropy: &[u8], pwd: &str) -> Result<Self, Error> {
        let big_seed = entropy_to_big_seed(entropy, pwd)?;
        let mini_secret_bytes = &big_seed[..32];
        Ok(Pair(
            MiniSecretKey::from_bytes(mini_secret_bytes)
                .expect("static length, always fits")
                .expand_to_keypair(ExpansionMode::Ed25519),
        ))
    }

    pub fn from_entropy_and_full_derivation(
        entropy: &[u8],
        full_derivation: FullDerivation,
    ) -> Result<Self, Error> {
        let mut pair = Self::from_entropy_and_pwd(entropy, full_derivation.password.unwrap_or(""))?;
        for junction in full_derivation.junctions.iter() {
            match junction {
                DeriveJunction::Hard(inner) => {
                    pair = Pair(
                        pair.0
                            .hard_derive_mini_secret_key(Some(ChainCode(*inner)), b"")
                            .0
                            .expand_to_keypair(ExpansionMode::Ed25519),
                    );
                }
                DeriveJunction::Soft(inner) => {
                    pair = Pair(pair.0.derived_key_simple(ChainCode(*inner), []).0);
                }
            }
        }
        Ok(pair)
    }

    pub fn from_entropy_and_full_derivation_external_rng<R>(
        entropy: &[u8],
        full_derivation: FullDerivation,
        external_rng: &mut R,
    ) -> Result<Self, Error>
    where
        R: CryptoRng + RngCore,
    {
        let mut pair = Self::from_entropy_and_pwd(entropy, full_derivation.password.unwrap_or(""))?;
        for junction in full_derivation.junctions.iter() {
            match junction {
                DeriveJunction::Hard(inner) => {
                    pair = Pair(
                        pair.0
                            .hard_derive_mini_secret_key(Some(ChainCode(*inner)), b"")
                            .0
                            .expand_to_keypair(ExpansionMode::Ed25519),
                    );
                }
                DeriveJunction::Soft(inner) => {
                    pair = Pair(
                        pair.0
                            .derived_key_simple_rng(ChainCode(*inner), [], &mut *external_rng)
                            .0,
                    );
                }
            }
        }
        Ok(pair)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let context = signing_context(SIGNING_CTX);
        Signature(self.0.sign(context.bytes(msg)).to_bytes())
    }

    pub fn sign_external_rng<R>(&self, msg: &[u8], external_rng: &mut R) -> Signature
    where
        R: CryptoRng + RngCore,
    {
        let context = signing_context(SIGNING_CTX);
        Signature(
            self.0
                .sign(attach_rng(context.bytes(msg), external_rng))
                .to_bytes(),
        )
    }

    pub fn public(&self) -> Public {
        Public(self.0.public.to_bytes())
    }
}
