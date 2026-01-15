use crate::{
    error::{self, Result},
    Error,
};
use rustc_hex::{FromHex, ToHex};
use sha2::Sha256;
use sha3::{Digest, Keccak256, Sha3_256};
use std::u8;

const SIGNATURE_SECP256K1_SIZE: usize = 65;
const SIGNATURE_ED25519_SIZE: usize = 64;
const SIGNATURE_BLS12381_SIZE: usize = 96;

#[derive(Clone, Debug)]
pub enum Signature {
    SECP256K1([u8; SIGNATURE_SECP256K1_SIZE]),
    ED25519([u8; SIGNATURE_ED25519_SIZE]),
    BLS12381([u8; SIGNATURE_BLS12381_SIZE]),
}

impl Signature {
    /// As raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::SECP256K1(raw) => &raw[..],
            Self::ED25519(raw) => &raw[..],
            Self::BLS12381(raw) => &raw[..],
        }
    }

    /// signature key from bytes
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        match raw.len() {
            SIGNATURE_ED25519_SIZE => Ok(Self::ED25519(<[u8; SIGNATURE_ED25519_SIZE]>::try_from(
                raw,
            )?)),
            SIGNATURE_BLS12381_SIZE => Ok(Self::BLS12381(
                <[u8; SIGNATURE_BLS12381_SIZE]>::try_from(raw)?,
            )),
            _ => Ok(Self::SECP256K1(<[u8; SIGNATURE_SECP256K1_SIZE]>::try_from(
                raw,
            )?)), // 65
        }
    }

    /// signature to secp256k1::ecdsa::RecoverableSignature
    pub fn to_secp256k1(&self) -> Result<secp256k1::ecdsa::RecoverableSignature> {
        match self {
            Self::SECP256K1(raw) => {
                let recid =
                    secp256k1::ecdsa::RecoveryId::from_i32((raw[64] as i32 + 1) % 2).unwrap();
                Ok(
                    secp256k1::ecdsa::RecoverableSignature::from_compact(&raw[..64], recid)
                        .unwrap(),
                )
            }
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// signature to ed25519_dalek::Signature
    pub fn to_ed25519(&self) -> Result<ed25519_dalek::Signature> {
        match self {
            Self::ED25519(raw) => Ok(ed25519_dalek::Signature::from_bytes(raw)),
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// signature to blst::min_pk::Signature
    pub fn to_bls12381(&self) -> Result<blst::min_pk::Signature> {
        match self {
            Self::BLS12381(raw) => Ok(blst::min_pk::Signature::from_bytes(raw).unwrap()),
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// to string
    pub fn to_str(&self) -> String {
        match self {
            Self::SECP256K1(raw) => raw.to_hex(),
            Self::ED25519(raw) => bs58::encode(raw).into_string(),
            Self::BLS12381(raw) => bs58::encode(raw).into_string(),
        }
    }

    /// from hex or bs58 string
    pub fn from_str(str: &str) -> Result<Self> {
        if str.starts_with("0x") {
            // eth
            let raw: Vec<u8> = str.trim_start_matches("0x").from_hex()?;
            return Self::from_bytes(&raw);
        } else {
            // eth | sol
            let raw: Vec<u8> = match str.from_hex() {
                Ok(raw) => raw,
                _ => bs58::decode(str)
                    .into_vec()
                    .map_err(|_| Error::InvalidSignature)?,
            };
            Self::from_bytes(&raw)
        }
    }
}

impl serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_str())
        } else {
            s.serialize_bytes(&self.as_bytes())
        }
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if d.is_human_readable() {
            let hex = <String>::deserialize(d)?;
            Self::from_str(&hex).map_err(serde::de::Error::custom)
        } else {
            let raw = <Vec<u8>>::deserialize(d)?;
            Self::from_bytes(&raw).map_err(serde::de::Error::custom)
        }
    }
}

impl<'a> TryFrom<&'a Signature> for secp256k1::ecdsa::RecoverableSignature {
    type Error = error::Error;
    fn try_from(pk: &'a Signature) -> Result<Self> {
        pk.to_secp256k1()
    }
}

impl<'a> TryFrom<&'a Signature> for ed25519_dalek::Signature {
    type Error = error::Error;
    fn try_from(pk: &'a Signature) -> Result<Self> {
        pk.to_ed25519()
    }
}

impl<'a> TryFrom<&'a Signature> for blst::min_pk::Signature {
    type Error = error::Error;
    fn try_from(pk: &'a Signature) -> Result<Self> {
        pk.to_bls12381()
    }
}

impl<'a> From<&'a secp256k1::ecdsa::RecoverableSignature> for Signature {
    fn from(sig: &'a secp256k1::ecdsa::RecoverableSignature) -> Self {
        let (recid, sig) = sig.serialize_compact();
        let mut raw = [0x0; 65];
        raw[0..64].copy_from_slice(&sig);
        raw[64] = recid.to_i32() as u8 + 27;
        Self::SECP256K1(raw)
    }
}

impl<'a> From<&'a ed25519_dalek::Signature> for Signature {
    fn from(sig: &'a ed25519_dalek::Signature) -> Self {
        Self::ED25519(sig.to_bytes())
    }
}

impl<'a> From<&'a blst::min_pk::Signature> for Signature {
    fn from(sig: &'a blst::min_pk::Signature) -> Self {
        Self::BLS12381(sig.to_bytes())
    }
}

/// Compute the Keccak-256 hash of input bytes.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    <[u8; 32]>::try_from(digest).unwrap()
}

/// Compute the Keccak-256 hash of input bytes.
pub fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    <[u8; 32]>::try_from(digest).unwrap()
}

pub trait SignatureSecp256k1 {
    fn sig_raw(&self, msg: &[u8]) -> Result<Vec<u8>>;
    fn sig_msg(&self, msg: &[u8]) -> Result<Vec<u8>>;
    fn sig_eth(&self, msg: &[u8]) -> Result<Vec<u8>>;
    fn sig_tron(&self, msg: &[u8]) -> Result<Vec<u8>>;
    fn eth_msg(msg: &[u8]) -> [u8; 32];
}

impl SignatureSecp256k1 for secp256k1::SecretKey {
    /// signing raw bytes
    fn sig_raw(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let message = secp256k1::Message::from_digest_slice(msg)?;
        let secp256k1 = secp256k1::Secp256k1::new();
        let sig = secp256k1.sign_ecdsa_recoverable(&message, self);
        let raw = Signature::try_from(&sig).unwrap().as_bytes().to_vec();
        Ok(raw)
    }

    /// signing raw message
    fn sig_msg(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.sig_raw(&keccak256(msg))
    }

    /// signing for eth
    fn sig_eth(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.sig_raw(&Self::eth_msg(msg))
    }

    /// signing for tron
    fn sig_tron(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        self.sig_raw(&digest)
    }

    /// message to eth signing raw bytes
    fn eth_msg(msg: &[u8]) -> [u8; 32] {
        keccak256(
            &[
                "\x19Ethereum Signed Message:\n".as_bytes(),
                &msg.len().to_string().as_bytes(),
                &msg,
            ]
            .concat(),
        )
    }
}

#[cfg(test)]
pub mod tests {
    use ed25519_dalek::ed25519::signature::SignerMut;

    use crate::SecretKey;

    use super::*;

    #[test]
    pub fn ed25519_sign() {
        let body = "Your identity needs to be verified in order to authorize subsequent actions 4";
        let seckey =
            SecretKey::from_str("eeb6feb296871a7e123dc82515dbfd599df380ea29614a4ff1976ab7ca075d37")
                .unwrap();
        let mut secret = seckey.to_ed25519();
        let sig = secret.sign(body.as_ref()).to_vec();
        let sig_str: String = sig.to_hex();
        println!("{}", sig_str);
        assert!(sig_str == "a4a7304a54ec72a393c87ee51a4bae89b9d0c8de715e331c0d5c8341a21da1f01ea6c71e27436ffb77629d3e3e5dcdae1c69b9c298d173a01695b9c14bb66d01");
    }
}
