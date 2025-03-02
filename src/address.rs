use crate::{
    error::{Error, Result},
    publickey::PublicKey,
    secretkey::SecretKey,
    signature::{keccak256, sha3_256},
};
use rustc_hex::{FromHex, ToHex};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::{fmt, u8};

const ADDRESS_ETH_SIZE: usize = 20;
const ADDRESS_B32_SIZE: usize = 32;
const ADDRESS_TRX_SIZE: usize = 21;

#[derive(Clone, Hash, PartialEq, Eq)]
pub enum Address {
    ETH([u8; ADDRESS_ETH_SIZE]),
    B32([u8; ADDRESS_B32_SIZE]),
    TRX([u8; ADDRESS_TRX_SIZE]),
}

/// 默认地址
impl Default for Address {
    fn default() -> Self {
        Self::ETH([0x0; ADDRESS_ETH_SIZE])
    }
}

impl Address {
    // eth address from secretkey
    pub fn eth_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let raw = PublicKey::secp256k1_from_secret(secret)
            .to_secp256k1()
            .unwrap()
            .serialize_uncompressed();
        let digest = keccak256(&raw[1..]);
        Self::ETH(
            <[u8; ADDRESS_ETH_SIZE]>::try_from(&digest[digest.len() - ADDRESS_ETH_SIZE..]).unwrap(),
        )
    }

    // sol address  address from secretkey
    pub fn sol_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let raw = PublicKey::ed25519_from_secret(secret)
            .to_ed25519()
            .unwrap()
            .to_bytes();

        Self::B32(raw)
    }

    // tron address from secretkey
    pub fn trx_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let raw = PublicKey::secp256k1_from_secret(secret)
            .to_secp256k1()
            .unwrap()
            .serialize_uncompressed();
        let digest = keccak256(&raw[1..]);
        let mut raw = [0x41; ADDRESS_TRX_SIZE];
        raw[1..ADDRESS_TRX_SIZE].copy_from_slice(&digest[digest.len() - ADDRESS_ETH_SIZE..]);
        Self::TRX(raw)
    }

    // endless address  address from secretkey
    pub fn eds_from_secret(secret: &SecretKey) -> Self
    where
        Self: Sized,
    {
        let mut raw = PublicKey::ed25519_from_secret(secret)
            .to_ed25519()
            .unwrap()
            .to_bytes()
            .to_vec();

        raw.push(0);

        Self::B32(sha3_256(&raw))
    }

    /// is zero address
    pub fn is_zero(&self) -> bool {
        use Address::*;
        match self {
            ETH(raw) => raw == &[0x0; ADDRESS_ETH_SIZE],
            B32(raw) => raw == &[0x0; ADDRESS_B32_SIZE],
            TRX(raw) => raw == &[0x0; ADDRESS_TRX_SIZE],
        }
    }

    /// As raw public key bytes. Full format without a type prefix.
    pub fn as_bytes(&self) -> &[u8] {
        use Address::*;
        match self {
            ETH(raw) => &raw[..],
            B32(raw) => &raw[..],
            TRX(raw) => &raw[..],
        }
    }

    /// from raw bytes
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        match raw.len() {
            ADDRESS_ETH_SIZE => Ok(Self::ETH(<[u8; ADDRESS_ETH_SIZE]>::try_from(raw)?)),
            ADDRESS_B32_SIZE => Ok(Self::B32(<[u8; ADDRESS_B32_SIZE]>::try_from(raw)?)),
            ADDRESS_TRX_SIZE => Ok(Self::TRX(<[u8; ADDRESS_TRX_SIZE]>::try_from(raw)?)),
            _ => Err(Error::InvalidAddress)?,
        }
    }

    /// from sol bytes
    pub fn sol_from_bytes(raw: &[u8]) -> Result<Self> {
        Ok(Self::B32(<[u8; ADDRESS_B32_SIZE]>::try_from(raw)?))
    }

    /// from eds bytes
    pub fn eds_from_bytes(raw: &[u8]) -> Result<Self> {
        Ok(Self::B32(<[u8; ADDRESS_B32_SIZE]>::try_from(raw)?))
    }

    /// from eds bytes
    pub fn trx_from_bytes(raw: &[u8]) -> Result<Self> {
        // println!("{:?}", raw);
        let mut byte = [0x41; ADDRESS_TRX_SIZE];
        match raw.len() {
            ADDRESS_ETH_SIZE => byte[1..].copy_from_slice(raw),
            ADDRESS_TRX_SIZE => byte[1..].copy_from_slice(&raw[1..]),
            32 => {
                if (raw[..11] == [0x0; 11]) && (raw[11] == 0x0 || raw[11] == 0x41) {
                    byte[1..].copy_from_slice(&raw[12..])
                } else {
                    Err(Error::InvalidAddress)?
                }
            }
            _ => Err(Error::InvalidAddress)?,
        }
        Ok(Self::TRX(byte))
    }

    /// from eds bytes
    pub fn eth_from_bytes(raw: &[u8]) -> Result<Self> {
        let mut byte = [0x41; ADDRESS_ETH_SIZE];
        match raw.len() {
            ADDRESS_ETH_SIZE => byte.copy_from_slice(raw),
            ADDRESS_TRX_SIZE => byte.copy_from_slice(&raw[1..]),
            32 => {
                if raw[..12] == [0x0; 12] {
                    byte.copy_from_slice(&raw[12..])
                } else {
                    Err(Error::InvalidAddress)?
                }
            }
            _ => Err(Error::InvalidAddress)?,
        }
        Ok(Self::ETH(byte))
    }

    /// to hex string
    pub fn to_hex(&self) -> String {
        let val: String = self.as_bytes().to_hex();
        val
    }

    /// to tron string, base58
    pub fn to_trx(&self) -> Result<String> {
        use Address::*;
        let mut raw = match self {
            ETH(raw) => {
                let mut raw = raw.to_vec();
                raw.insert(0, 0x41);
                raw
            }
            TRX(raw) => raw.to_vec(),
            _ => Err(Error::InvalidAddress)?,
        };
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let digest1 = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(&digest1);
        let digest = hasher.finalize();

        raw.extend(&digest[..4]);
        Ok(bs58::encode(raw).into_string())
    }

    /// to eth string, hex case sensitive
    pub fn to_eth(&self) -> Result<String> {
        use Address::*;
        let addr: String = match self {
            ETH(raw) => raw.to_hex(),
            TRX(raw) => raw[1..].to_hex(),
            _ => Err(Error::InvalidAddress)?,
        };
        let hash: Vec<_> = {
            let mut hasher = Keccak256::new();
            hasher.update(addr.as_bytes());
            let hash: String = hasher.finalize().as_slice().to_hex();
            hash.chars().collect()
        };

        let addr =
            addr.char_indices()
                .fold(String::from("0x"), |mut acc, (index, address_char)| {
                    let n = u16::from_str_radix(&hash[index].to_string(), 16).unwrap();
                    if n > 7 {
                        // make char uppercase if ith character is 9..f
                        acc.push_str(&address_char.to_uppercase().to_string())
                    } else {
                        // already lowercased
                        acc.push(address_char)
                    }
                    acc
                });
        Ok(addr)
    }

    /// to sol string, base58
    pub fn to_sol(&self) -> Result<String> {
        let raw = match self {
            Self::B32(raw) => raw,
            _ => Err(Error::InvalidAddress)?,
        };
        Ok(bs58::encode(raw).into_string())
    }

    /// to eds string, base58
    pub fn to_eds(&self) -> Result<String> {
        let raw = match self {
            Self::B32(raw) => raw,
            _ => Err(Error::InvalidAddress)?,
        };
        Ok(bs58::encode(raw).into_string())
    }

    /// to sol string, base58
    pub fn to_bs58(&self) -> Result<String> {
        let raw = self.as_bytes();
        Ok(bs58::encode(raw).into_string())
    }

    /// to eth or sol or trx string
    pub fn to_str(&self) -> String {
        use Address::*;
        match self {
            ETH(_) => self.to_eth().unwrap(),
            B32(_) => self.to_sol().unwrap(),
            TRX(_) => self.to_trx().unwrap(),
        }
    }

    /// public to address
    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        match pubkey {
            PublicKey::SECP256K1(_) => {
                let digest =
                    keccak256(&pubkey.to_secp256k1().unwrap().serialize_uncompressed()[1..]);
                Self::ETH(
                    <[u8; ADDRESS_ETH_SIZE]>::try_from(&digest[digest.len() - ADDRESS_ETH_SIZE..])
                        .unwrap(),
                )
            }
            PublicKey::ED25519(pubkey) => Self::B32(pubkey.clone()),
            PublicKey::BLS12381(_) => panic!("BLS12381 not address"),
        }
    }

    // endless address  address from secretkey
    pub fn eds_from_pubkey(pubkey: &PublicKey) -> Result<Self>
    where
        Self: Sized,
    {
        match pubkey {
            PublicKey::ED25519(raw) => {
                let mut raw = raw.to_vec();
                raw.push(0);
                Ok(Self::B32(sha3_256(&raw)))
            }
            _ => Err(Error::InvalidPublicKey)?,
        }
    }

    /// eth sign to address
    pub fn from_secp256k1_sign(sig: &str, msg: &str) -> Result<Self> {
        let pk = PublicKey::from_secp256k1_sign(sig, msg)?;
        Ok(Self::from_pubkey(&pk))
    }

    /// eth sign to address by bytes
    pub fn from_secp256k1_sign_raw(sig: &[u8], msg: &[u8]) -> Result<Self> {
        let pk = PublicKey::from_secp256k1_sign_raw(sig, msg)?;
        Ok(Self::from_pubkey(&pk))
    }

    /// string to address
    pub fn from_str(str: &str) -> Result<Self> {
        let str = str.trim();
        let raw = if str.len() == 34 && str.starts_with("T") {
            // tron
            let mut raw = bs58::decode(str).into_vec()?;
            let check = raw.split_off(raw.len() - 4);
            let mut hasher = Sha256::new();
            hasher.update(&raw);
            let digest1 = hasher.finalize();

            let mut hasher = Sha256::new();
            hasher.update(&digest1);
            let digest = hasher.finalize();

            if check != &digest[..4] {
                Err(Error::InvalidAddress)?
            } else {
                raw
            }
        } else if str.starts_with("0x") {
            // eth
            let raw: Vec<u8> = str.trim_start_matches("0x").from_hex()?;
            raw
        } else {
            // eth | sol
            let raw: Vec<u8> = match str.from_hex() {
                Ok(raw) => raw,
                _ => bs58::decode(str)
                    .into_vec()
                    .map_err(|_| Error::InvalidAddress)?,
            };
            raw
        };

        Self::from_bytes(&raw)
    }

    /// endless address from string
    pub fn eds_from_str(str: &str) -> Result<Self> {
        let str = str.trim();
        if str.starts_with("0x") {
            let raw: Vec<u8> = str.trim_start_matches("0x").from_hex()?;
            let len = raw.len();
            if len != ADDRESS_B32_SIZE {
                let mut byte = [0u8; ADDRESS_B32_SIZE];
                byte[raw.len() - 1..].copy_from_slice(&raw);
                Ok(Self::B32(byte))
            } else {
                Self::eds_from_bytes(&raw)
            }
        } else {
            let raw: Vec<u8> = bs58::decode(str)
                .into_vec()
                .map_err(|_| Error::InvalidAddress)?;
            Self::eds_from_bytes(&raw)
        }
    }
}

impl From<&str> for Address {
    fn from(addr: &str) -> Address {
        Address::from_str(addr).unwrap()
    }
}

impl serde::Serialize for Address {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_str())
        } else {
            s.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> serde::Deserialize<'de> for Address {
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

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
