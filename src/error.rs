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
