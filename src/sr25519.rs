//! Sr25519, mostly follows `sp_core::sr25519`.
//! Also supports external Rng.

use parity_scale_codec::{Decode, Encode};
use rand_core::{CryptoRng, RngCore};
use schnorrkel::{
    context::attach_rng,
    derive::{ChainCode, Derivation},
    signing_context, ExpansionMode, Keypair, MiniSecretKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    common::{entropy_to_big_seed, DeriveJunction, FullDerivation, HASH_256_LEN},
    error::Error,
};

pub const SIGNING_CTX: &[u8] = b"substrate";
pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Decode, Debug, Encode, Eq, Ord, PartialEq, PartialOrd)]
pub struct Public(pub [u8; PUBLIC_LEN]);

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

#[derive(Clone, Copy, Decode, Debug, Encode, Eq, Ord, PartialEq, PartialOrd)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pair(Keypair);

impl Pair {
    pub fn from_entropy_and_pwd(entropy: &[u8], pwd: &str) -> Result<Self, Error> {
        let mut big_seed = entropy_to_big_seed(entropy, pwd)?;
        let mini_secret_bytes = &big_seed[..HASH_256_LEN];
        let pair = Pair(
            MiniSecretKey::from_bytes(mini_secret_bytes)
                .expect("static length, always fits")
                .expand_to_keypair(ExpansionMode::Ed25519),
        );
        big_seed.zeroize();
        Ok(pair)
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

#[cfg(any(feature = "std", test))]
#[cfg(test)]
mod tests {

    use mnemonic_external::{regular::InternalWordList, WordSet};
    use rand_core::{CryptoRng, RngCore};
    use sp_core::{crypto::Pair, sr25519};
    use std::format;

    use crate::common::{cut_path, ALICE_WORDS};
    use crate::sr25519::{
        Pair as Sr25529Pair, Public as Sr25519Public, Signature as Sr25519Signature,
    };

    #[test]
    fn identical_sr25519() {
        let derivation = "//hard/soft//alicealicealicealicealicealicealicealice";
        let password = "trickytrick";

        // phrase and full derivation, for `sp-core` procedure
        let phrase_with_derivations = format!("{ALICE_WORDS}{derivation}");

        // path and password combined, for `substrate-crypto-light` procedure
        let path_and_pwd = format!("{derivation}///{password}");

        // bytes to sign
        let msg = b"super important thing to sign";

        // `sr25519` pair, public, and signature with `sp_core`
        let pair_from_core =
            sr25519::Pair::from_string(&phrase_with_derivations, Some(password)).unwrap();
        let public_from_core = pair_from_core.public().0;
        let signature_from_core = pair_from_core.sign(msg).0;

        // phrase-to-entropy, with `mnemonic-external`
        let internal_word_list = InternalWordList;
        let mut word_set = WordSet::new();
        for word in ALICE_WORDS.split(' ') {
            word_set.add_word(word, &internal_word_list).unwrap();
        }
        let entropy = word_set.to_entropy().unwrap();

        // full derivation, `substrate-crypto-light`
        let full_derivation = cut_path(&path_and_pwd).unwrap();

        // `sr25519` pair, public, and signature with `substrate-crypto-light`
        let pair =
            Sr25529Pair::from_entropy_and_full_derivation(&entropy, full_derivation).unwrap();
        let public = pair.public().0;
        let signature = pair.sign(msg).0;

        assert_eq!(public_from_core, public);

        // verify signature made with `substrate-crypto-light` using tools of
        // `sp-core`
        let signature_import_into_core = sr25519::Signature::from_raw(signature);
        let public_import_into_core = sr25519::Public::from_raw(public);
        assert!(sr25519::Pair::verify(
            &signature_import_into_core,
            msg,
            &public_import_into_core
        ));

        // verify signature made with tools of `sp-core` using tools of
        // `substrate-crypto-light`
        let signature_import = Sr25519Signature(signature_from_core);
        let public_import = Sr25519Public(public_from_core);
        assert!(public_import.verify(msg, &signature_import));
    }

    struct DummyRng;

    impl RngCore for DummyRng {
        fn next_u32(&mut self) -> u32 {
            0u32
        }
        fn next_u64(&mut self) -> u64 {
            0u64
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            zeroize::Zeroize::zeroize(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for DummyRng {}

    #[test]
    fn identical_sr25519_external_rng() {
        let derivation = "//hard/soft//alicealicealicealicealicealicealicealice";
        let password = "trickytrick";

        // phrase and full derivation, for `sp-core` procedure
        let phrase_with_derivations = format!("{ALICE_WORDS}{derivation}");

        // path and password combined, for `substrate-crypto-light` procedure
        let path_and_pwd = format!("{derivation}///{password}");

        // bytes to sign
        let msg = b"super important thing to sign";

        // `sr25519` pair, public, and signature with `sp_core`
        let pair_from_core =
            sr25519::Pair::from_string(&phrase_with_derivations, Some(password)).unwrap();
        let public_from_core = pair_from_core.public().0;

        // phrase-to-entropy, with `mnemonic-external`
        let internal_word_list = InternalWordList;
        let mut word_set = WordSet::new();
        for word in ALICE_WORDS.split(' ') {
            word_set.add_word(word, &internal_word_list).unwrap();
        }
        let entropy = word_set.to_entropy().unwrap();

        // full derivation, `substrate-crypto-light`
        let full_derivation = cut_path(&path_and_pwd).unwrap();

        // `sr25519` pair, public, and signature with `substrate-crypto-light`
        let mut rng = DummyRng;
        let pair = Sr25529Pair::from_entropy_and_full_derivation_external_rng(
            &entropy,
            full_derivation,
            &mut rng,
        )
        .unwrap();
        let public = pair.public().0;
        let signature = pair.sign_external_rng(msg, &mut rng).0;

        assert_eq!(public_from_core, public);

        // verify signature made with `substrate-crypto-light` using tools of
        // `sp-core`
        let signature_import_into_core = sr25519::Signature::from_raw(signature);
        let public_import_into_core = sr25519::Public::from_raw(public);
        assert!(sr25519::Pair::verify(
            &signature_import_into_core,
            msg,
            &public_import_into_core
        ));
    }
}
