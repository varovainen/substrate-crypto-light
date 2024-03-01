#[derive(Debug)]
pub enum Error {
    EcdsaPairGen,
    InvalidEntropy,
    NoSoftDerivationEcdsa,
    Pbkdf2Internal,
}
