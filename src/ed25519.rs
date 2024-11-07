use ed25519_zebra::{SigningKey, VerificationKey};
use parity_scale_codec::{Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    common::{entropy_to_big_seed, DeriveJunction, FullDerivation, HASH_256_LEN},
    error::Error,
};

pub const ID: &str = "Ed25519HDKD";
pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Decode, Debug, Encode, Eq, Ord, PartialEq, PartialOrd)]
pub struct Public(pub [u8; PUBLIC_LEN]);

impl Public {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let signature = ed25519_zebra::Signature::from_bytes(&signature.0);
        let Ok(verification_key) = VerificationKey::try_from(self.0) else {
            return false;
        };
        verification_key.verify(&signature, msg).is_ok()
    }
}

#[derive(Clone, Copy, Decode, Debug, Encode, Eq, Ord, PartialEq, PartialOrd)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pair(SigningKey);

impl Pair {
    pub fn from_entropy_and_pwd(entropy: &[u8], pwd: &str) -> Result<Self, Error> {
        let mut big_seed = entropy_to_big_seed(entropy, pwd)?;
        let seed = &big_seed[..HASH_256_LEN];
        let pair = Pair(SigningKey::try_from(seed).expect("static length, always fits"));
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
                    // derivation mixing is done with hash updates, as opposed
                    // to `using_encoded`, to avoid multiple secret copying
                    let mut blake2b_state = blake2b_simd::Params::new()
                        .hash_length(HASH_256_LEN)
                        .to_state();
                    blake2b_state.update(&ID.encode());
                    blake2b_state.update(pair.0.as_ref());
                    blake2b_state.update(inner);
                    let bytes = blake2b_state.finalize();
                    pair = Pair(
                        SigningKey::try_from(bytes.as_ref()).expect("static length, always fits"),
                    );
                }
                DeriveJunction::Soft(_) => return Err(Error::NoSoftDerivationEd25519),
            }
        }
        Ok(pair)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }

    pub fn public(&self) -> Public {
        Public(VerificationKey::from(&self.0).into())
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use mnemonic_external::{regular::InternalWordList, WordSet};
    use sp_core::{crypto::Pair, ed25519};

    #[cfg(feature="std")]
    use std::format;

    #[cfg(not(feature="std"))]
    use alloc::format;

    use crate::common::{cut_path, ALICE_WORDS};
    use crate::ed25519::{
        Pair as Ed25519Pair, Public as Ed25519Public, Signature as Ed25519Signature,
    };

    #[test]
    fn identical_ed25519() {
        let derivation = "//hard//alicealicealicealicealicealicealicealice";
        let password = "trickytrick";

        // phrase and full derivation, for `sp-core` procedure
        let phrase_with_derivations = format!("{ALICE_WORDS}{derivation}");

        // path and password combined, for `substrate-crypto-light` procedure
        let path_and_pwd = format!("{derivation}///{password}");

        // bytes to sign
        let msg = b"super important thing to sign";

        // `ed25519` pair, public, and signature with `sp_core`
        let pair_from_core =
            ed25519::Pair::from_string(&phrase_with_derivations, Some(password)).unwrap();
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

        // `ed25519` pair, public, and signature with `substrate-crypto-light`
        let pair =
            Ed25519Pair::from_entropy_and_full_derivation(&entropy, full_derivation).unwrap();
        let public = pair.public().0;
        let signature = pair.sign(msg).0;

        assert_eq!(public_from_core, public);

        // verify signature made with `substrate-crypto-light` using tools of
        // `sp-core`
        let signature_import_into_core = ed25519::Signature::from_raw(signature);
        let public_import_into_core = ed25519::Public::from_raw(public);
        assert!(ed25519::Pair::verify(
            &signature_import_into_core,
            msg,
            &public_import_into_core
        ));

        // verify signature made with tools of `sp-core` using tools of
        // `substrate-crypto-light`
        let signature_import = Ed25519Signature(signature_from_core);
        let public_import = Ed25519Public(public_from_core);
        assert!(public_import.verify(msg, &signature_import));
    }
}
