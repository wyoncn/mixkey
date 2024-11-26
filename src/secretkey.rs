use crate::error::{Error, Result};
use rand::RngCore;
use rustc_hex::{FromHex, ToHex};
use std::u8;

pub const SECRET_KEY_SIZE: usize = 32;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl SecretKey {
    /// ethereum secret, support ed25519 and secp256k1
    pub fn new() -> Self {
        let mut rng = rand::rngs::OsRng {};
        loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            rng.fill_bytes(&mut ret);
            if secp256k1::SecretKey::from_slice(&ret).is_ok() {
                return Self(ret);
            }
        }
    }
    /// not support secp256k1
    pub fn new_pure() -> Self {
        let mut rng = rand::rngs::OsRng {};
        let mut ret = [0u8; SECRET_KEY_SIZE];
        rng.fill_bytes(&mut ret);
        return Self(ret);
    }
    /// to secp256k1
    pub fn to_secp256k1(&self) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&self.0).unwrap()
    }
    /// to ED25519
    pub fn to_ed25519(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
    /// to bls12381
    pub fn to_bls12381(&self) -> blst::min_pk::SecretKey {
        blst::min_pk::SecretKey::key_gen(&self.0, &[]).expect("secret length should be higher")
    }
    /// build from raw bytes
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if let Ok(ret) = <[u8; SECRET_KEY_SIZE]>::try_from(&raw[..32]) {
            if secp256k1::SecretKey::from_slice(&ret).is_ok() {
                return Ok(Self(ret));
            }
        }
        Err(Error::InvalidSecretKey)
    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// get [u8; 32]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.clone()
    }
    /// build from string
    pub fn from_str(str: &str) -> Result<Self> {
        let raw: Vec<u8> = match str.starts_with("[") {
            true => {
                let matchs: &[_] = &['[', ']'];
                str.trim_matches(matchs)
                    .split(",")
                    .map(|s| s.parse().unwrap())
                    .collect()
            }
            false => match str.from_hex() {
                Ok(raw) => raw,
                _ => bs58::decode(str).into_vec().unwrap(),
            },
        };
        Self::from_bytes(&raw)
    }
    /// to base58 string
    pub fn to_bs58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
    /// to hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
    /// to sol raw bytes
    pub fn to_sol_bytes(&self) -> [u8; 64] {
        let mut raw: [u8; 64] = [0u8; 64];
        raw[..32].copy_from_slice(&self.0);
        let pubkey = ed25519_dalek::VerifyingKey::from(&self.to_ed25519());
        raw[32..].copy_from_slice(pubkey.as_bytes());
        raw
    }
    /// to sol string, base58
    pub fn to_sol(&self) -> String {
        bs58::encode(self.to_sol_bytes()).into_string()
    }
}

impl<'a> From<&'a SecretKey> for secp256k1::SecretKey {
    fn from(secret: &'a SecretKey) -> Self {
        secret.to_secp256k1()
    }
}

impl<'a> From<&'a SecretKey> for ed25519_dalek::SigningKey {
    fn from(secret: &'a SecretKey) -> Self {
        secret.to_ed25519()
    }
}

impl<'a> From<&'a SecretKey> for blst::min_pk::SecretKey {
    fn from(secret: &'a SecretKey) -> Self {
        secret.to_bls12381()
    }
}

impl<'a> From<&'a secp256k1::SecretKey> for SecretKey {
    fn from(secret: &'a secp256k1::SecretKey) -> Self {
        Self(secret.secret_bytes())
    }
}

impl<'a> From<&'a ed25519_dalek::SigningKey> for SecretKey {
    fn from(secret: &'a ed25519_dalek::SigningKey) -> Self {
        Self(secret.to_bytes())
    }
}

impl<'a> From<&'a blst::min_pk::SecretKey> for SecretKey {
    fn from(secret: &'a blst::min_pk::SecretKey) -> Self {
        Self(secret.to_bytes())
    }
}
