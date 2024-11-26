//! Errors.
use std::path::PathBuf;

use thiserror::Error;

/// Error type containing possible failure cases of this crate.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error {0}")]
    General(String),

    #[error(transparent)]
    Base58Encode(#[from] bs58::encode::Error),

    #[error(transparent)]
    Base58Decode(#[from] bs58::decode::Error),

    #[error("AesGCM error {0}")]
    AesGcm(aes_gcm::Error),

    #[error(transparent)]
    ParseInt(#[from] core::num::ParseIntError),

    #[error(transparent)]
    FromHex(#[from] rustc_hex::FromHexError),

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),

    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Bls12318 error{0}")]
    Bls12318(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    ArrayTryFrom(#[from] core::array::TryFromSliceError),

    #[error("Invalid path {0}")]
    InvalidPath(PathBuf),

    #[error("Invalid address or pubkey")]
    InvalidAddress,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature key")]
    InvalidSignature,

    #[error("Option value is none")]
    IsNone,
}

/// `Result` with error case set to `::error::Error`.
pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Self::General(e.to_string())
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(e: aes_gcm::Error) -> Self {
        Self::AesGcm(e)
    }
}

impl From<blst::BLST_ERROR> for Error {
    fn from(e: blst::BLST_ERROR) -> Self {
        Self::Bls12318(format!("{:?}", e))
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::General(s.to_string())
    }
}
