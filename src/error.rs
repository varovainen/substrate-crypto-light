#[cfg(feature = "std")]
use std::{fmt::{Debug, Display, Formatter, Result as FmtResult}, string::String};

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
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

impl Error {
    fn error_text(&self) -> String {
        match self {
            Error::Base58Checksum => String::from("Base58 checksum mismatch"),
            Error::Base58Decoding(from_base58_error) => format!("Base58 decoding error: {:?}", from_base58_error),
            Error::Base58Length => String::from("Invalid base58 address length"),
            Error::Base58Prefix => String::from("Invalid base58 prefix value"),
            #[cfg(feature = "ecdsa")]
            Error::EcdsaPairGen => String::from("Could not construct ecdsa keypair"),
            #[cfg(feature = "ecdsa")]
            Error::EcdsaPublicKeyLength => String::from("Invalid ecdsa public key length"),
            #[cfg(feature = "ecdsa")]
            Error::EcdsaSignatureGen => String::from("Signing failed"),
            #[cfg(feature = "ecdsa")]
            Error::EcdsaSignatureLength => String::from("Invalid ecdsa signature size"),
            Error::InvalidEntropy => String::from("Invalid entropy size, only 16, 20, 24, 28, and 32 bytes are supported"),
            #[cfg(feature = "ecdsa")]
            Error::NoSoftDerivationEcdsa => String::from("Soft derivation is impossible for ecdsa"),
            #[cfg(feature = "ed25519")]
            Error::NoSoftDerivationEd25519 => String::from("Soft derivation is impossible for ed25519"),
            Error::Pbkdf2Internal => String::from("Pbkdf2 hashing internal error, please report this"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.error_text())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

