#[derive(Debug)]
pub enum Error {
    EcdsaPairGen,
    EcdsaPublicKeyLength,
    EcdsaSignatureGen,
    EcdsaSignatureLength,
    InvalidEntropy,
    NoSoftDerivationEcdsa,
    Pbkdf2Internal,
}
