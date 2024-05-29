#[cfg(feature = "std")]
use std::fmt::{Debug, Display, Formatter, Result};

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    Base58Checksum,
    Base58Decoding(base58::FromBase58Error),
    Base58Length,
    Base58Prefix,
    #[cfg(feature = "ecdsa")]
    EcdsaPairGen,
    #[cfg(feature = "ecdsa")]
    EcdsaPublicKeyLength,
    #[cfg(feature = "ecdsa")]
    EcdsaSignatureGen,
    #[cfg(feature = "ecdsa")]
    EcdsaSignatureLength,
    InvalidEntropy,
    #[cfg(feature = "ecdsa")]
    NoSoftDerivationEcdsa,
    #[cfg(feature = "ed25519")]
    NoSoftDerivationEd25519,
    Pbkdf2Internal,
}

// TODO: provide actual error descriptions.
#[cfg(feature = "std")]
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        <Self as Debug>::fmt(self, f)
    }
}
