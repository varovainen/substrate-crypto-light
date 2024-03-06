#[cfg(any(feature = "std", test))]
use std::vec;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, SigningKey, VerifyingKey};
use parity_scale_codec::{Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    common::{blake2_256, entropy_to_big_seed, DeriveJunction, FullDerivation, HASH_256_LEN},
    error::Error,
};

pub const ID: &str = "Secp256k1HDKD";
pub const PUBLIC_LEN: usize = 33;
pub const SIGNATURE_LEN: usize = 65;

#[derive(Clone, Copy, Decode, Debug, Encode, Eq, Ord, PartialEq, PartialOrd)]
pub struct Public(pub [u8; PUBLIC_LEN]);

impl Public {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let Ok(signature) = k256::ecdsa::Signature::from_slice(signature.0[..64].as_ref()) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(self.0.as_ref()) else {
            return false;
        };
        verifying_key
            .verify_prehash(&blake2_256(msg), &signature)
            .is_ok()
    }
}

#[derive(Clone, Copy, Decode, Debug, Encode, Eq, Ord, PartialEq, PartialOrd)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

#[derive(ZeroizeOnDrop)]
pub struct Pair(SigningKey);

impl Pair {
    pub fn from_entropy_and_pwd(entropy: &[u8], pwd: &str) -> Result<Self, Error> {
        let mut big_seed = entropy_to_big_seed(entropy, pwd)?;
        let seed = &big_seed[..HASH_256_LEN];
        let signing_key_result = SigningKey::from_bytes(seed.as_ref().into());
        big_seed.zeroize();
        match signing_key_result {
            Ok(signing_key) => Ok(Pair(signing_key)),
            Err(_) => Err(Error::EcdsaPairGen),
        }
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
                    blake2b_state.update(pair.0.to_bytes().as_slice());
                    blake2b_state.update(inner);
                    let bytes = blake2b_state.finalize();
                    pair = Pair(
                        SigningKey::from_bytes(bytes.as_ref().into())
                            .map_err(|_| Error::EcdsaPairGen)?,
                    );
                }
                DeriveJunction::Soft(_) => return Err(Error::NoSoftDerivationEcdsa),
            }
        }
        Ok(pair)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let (signature_ecdsa, recid) = self
            .0
            .sign_prehash_recoverable(&blake2_256(msg))
            .map_err(|_| Error::EcdsaSignatureGen)?;
        Ok(Signature(
            [
                signature_ecdsa.to_bytes().as_slice().to_vec(),
                vec![recid.to_byte()],
            ]
            .concat()
            .try_into()
            .map_err(|_| Error::EcdsaSignatureLength)?,
        ))
    }

    pub fn public(&self) -> Result<Public, Error> {
        Ok(Public(
            self.0
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .map_err(|_| Error::EcdsaPublicKeyLength)?,
        ))
    }
}

#[cfg(any(feature = "std", test))]
#[cfg(test)]
mod tests {

    use mnemonic_external::{regular::InternalWordList, WordSet};
    use sp_core::{crypto::Pair, ecdsa};
    use std::format;

    use crate::common::{cut_path, ALICE_WORDS};
    use crate::ecdsa::{Pair as EcdsaPair, Public as EcdsaPublic, Signature as EcdsaSignature};

    #[test]
    fn identical_ecdsa() {
        let derivation = "//hard//alicealicealicealicealicealicealicealice";
        let password = "trickytrick";

        // phrase and full derivation, for `sp-core` procedure
        let phrase_with_derivations = format!("{ALICE_WORDS}{derivation}");

        // path and password combined, for `substrate-crypto-light` procedure
        let path_and_pwd = format!("{derivation}///{password}");

        // bytes to sign
        let msg = b"super important thing to sign";

        // `ecdsa` pair, public, and signature with `sp_core`
        let pair_from_core =
            ecdsa::Pair::from_string(&phrase_with_derivations, Some(password)).unwrap();
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

        // `ecdsa` pair, public, and signature with `substrate-crypto-light`
        let pair = EcdsaPair::from_entropy_and_full_derivation(&entropy, full_derivation).unwrap();
        let public = pair.public().unwrap().0;
        let signature = pair.sign(msg).unwrap().0;

        assert_eq!(public_from_core, public);

        // verify signature made with `substrate-crypto-light` using tools of
        // `sp-core`
        let signature_import_into_core = ecdsa::Signature::from_raw(signature);
        let public_import_into_core = ecdsa::Public::from_raw(public);
        assert!(ecdsa::Pair::verify(
            &signature_import_into_core,
            msg,
            &public_import_into_core
        ));

        // verify signature made with tools of `sp-core` using tools of
        // `substrate-crypto-light`
        let signature_import = EcdsaSignature(signature_from_core);
        let public_import = EcdsaPublic(public_from_core);
        assert!(public_import.verify(msg, &signature_import));
    }
}
