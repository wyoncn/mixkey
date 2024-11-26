use crate::{
    error::{self, Error, Result},
    keccak256,
    secretkey::SecretKey,
};
use rustc_hex::{FromHex, ToHex};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message,
};
use std::{fmt, u8};

const PUBLICKEY_SECP256K1_SIZE: usize = 33;
const PUBLICKEY_ED25519_SIZE: usize = 32;
const PUBLICKEY_BLS12381_SIZE: usize = 48;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum PublicKey {
    SECP256K1([u8; PUBLICKEY_SECP256K1_SIZE]),
    ED25519([u8; PUBLICKEY_ED25519_SIZE]),
    BLS12381([u8; PUBLICKEY_BLS12381_SIZE]),
}

impl PublicKey {
    // secp256k1 public key form secret
    pub fn secp256k1_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let secp = secp256k1::Secp256k1::new();
        let secret = secret.to_secp256k1();
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        Self::SECP256K1(public.serialize())
    }

    // ed25519 public key from secret
    pub fn ed25519_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let secret = secret.to_ed25519();
        let public = ed25519_dalek::VerifyingKey::from(&secret);
        Self::ED25519(public.to_bytes())
    }

    // BLS12381 public key from secret
    pub fn bls12381_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let secret = secret.to_bls12381();
        let public = secret.sk_to_pk();
        Self::BLS12381(public.to_bytes())
    }

    /// As raw public key bytes. Full format without a type prefix.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::SECP256K1(raw) => &raw[..],
            Self::ED25519(raw) => &raw[..],
            Self::BLS12381(raw) => &raw[..],
        }
    }

    /// As raw public key bytes. Full format without a type prefix.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// public key from bytes
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        match raw.len() {
            PUBLICKEY_ED25519_SIZE => Ok(Self::ED25519(
                ed25519_dalek::VerifyingKey::from_bytes(
                    &<[u8; PUBLICKEY_ED25519_SIZE]>::try_from(raw)?,
                )?
                .to_bytes(),
            )),
            PUBLICKEY_BLS12381_SIZE => Ok(Self::BLS12381(
                blst::min_pk::PublicKey::from_bytes(raw)?.to_bytes(),
            )),
            _ => Ok(Self::SECP256K1(
                secp256k1::PublicKey::from_slice(raw)?.serialize(),
            )), // 33
        }
    }

    /// eth sign to publickey
    pub fn from_secp256k1_sign(sig: &str, msg: &str) -> Result<Self> {
        let msg =
            keccak256(format!("\x19Ethereum Signed Message:\n{}{}", msg.len(), msg).as_bytes());
        let sig: Vec<u8> = sig.trim_start_matches("0x").from_hex()?;

        Self::from_secp256k1_sign_raw(&sig, &msg)
    }

    /// eth sign to publickey by bytes
    pub fn from_secp256k1_sign_raw(sig: &[u8], msg: &[u8]) -> Result<Self> {
        let msg = Message::from_digest_slice(msg)?;
        let sig = sig.to_vec();
        let recid = RecoveryId::from_i32((sig[64] as i32 + 1) % 2).unwrap();
        let sig = RecoverableSignature::from_compact(&sig[..64], recid)?;
        let secp256k1 = secp256k1::Secp256k1::new();
        let pubkey = secp256k1.recover_ecdsa(&msg, &sig)?;

        PublicKey::from_bytes(&pubkey.serialize())
    }

    /// to hex string
    pub fn to_hex(&self) -> String {
        self.as_bytes().to_hex()
    }

    /// to base58 string
    pub fn to_bs58(&self) -> String {
        bs58::encode(self.as_bytes()).into_string()
    }

    /// to string
    pub fn to_str(&self) -> String {
        match self {
            Self::SECP256K1(raw) => raw.to_hex(),
            Self::ED25519(raw) => bs58::encode(raw).into_string(),
            Self::BLS12381(raw) => bs58::encode(raw).into_string(),
        }
    }

    /// publickey to secp256k1::PublicKey
    pub fn to_secp256k1(&self) -> Result<secp256k1::PublicKey> {
        match self {
            Self::SECP256K1(raw) => Ok(secp256k1::PublicKey::from_slice(raw).unwrap()),
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// publickey to ed25519_dalek::VerifyingKey
    pub fn to_ed25519(&self) -> Result<ed25519_dalek::VerifyingKey> {
        match self {
            Self::ED25519(raw) => Ok(ed25519_dalek::VerifyingKey::from_bytes(raw).unwrap()),
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// publickey to blst::min_pk::PublicKey
    pub fn to_bls12381(&self) -> Result<blst::min_pk::PublicKey> {
        match self {
            Self::BLS12381(raw) => Ok(blst::min_pk::PublicKey::from_bytes(raw).unwrap()),
            _ => Err(Error::InvalidPublicKey),
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
                    .map_err(|_| Error::InvalidPublicKey)?,
            };
            Self::from_bytes(&raw)
        }
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_str())
        } else {
            s.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
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

impl<'a> TryFrom<&'a PublicKey> for secp256k1::PublicKey {
    type Error = error::Error;
    fn try_from(pk: &'a PublicKey) -> Result<Self> {
        pk.to_secp256k1()
    }
}

impl<'a> TryFrom<&'a PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = error::Error;
    fn try_from(pk: &'a PublicKey) -> Result<Self> {
        pk.to_ed25519()
    }
}

impl<'a> TryFrom<&'a PublicKey> for blst::min_pk::PublicKey {
    type Error = error::Error;
    fn try_from(pk: &'a PublicKey) -> Result<Self> {
        pk.to_bls12381()
    }
}

impl<'a> From<&'a secp256k1::PublicKey> for PublicKey {
    fn from(pk: &'a secp256k1::PublicKey) -> Self {
        Self::SECP256K1(pk.serialize())
    }
}

impl<'a> From<&'a ed25519_dalek::VerifyingKey> for PublicKey {
    fn from(pk: &'a ed25519_dalek::VerifyingKey) -> Self {
        Self::ED25519(pk.to_bytes())
    }
}

impl<'a> From<&'a blst::min_pk::PublicKey> for PublicKey {
    fn from(pk: &'a blst::min_pk::PublicKey) -> Self {
        Self::BLS12381(pk.to_bytes())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
