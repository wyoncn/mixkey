use crate::{
    address::Address,
    crypto,
    error::{Error, Result},
    secretkey::SecretKey,
};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::{fs, u8};

// key cache memory
static SECRETS: Lazy<RwLock<HashMap<String, SecretKey>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Keystore {
    secret: SecretKey,
    path: PathBuf,
    pwd: Vec<u8>,
}

impl Keystore {
    /// Returns secret part of the keypair
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// build from secretkey
    pub fn from_secret(secret: &SecretKey, path: &PathBuf, pwd: &[u8]) -> Self {
        Self {
            secret: secret.clone(),
            path: path.clone(),
            pwd: pwd.to_vec(),
        }
    }

    /// build from file with address
    pub fn from_address(addr: &Address, path: &PathBuf, pwd: &[u8]) -> Result<Self> {
        let addr = addr.to_hex();
        let secret = SECRETS.read()?.get(&addr).map(|s| s.clone());
        let secret = match secret {
            Some(secret) => secret,
            None => {
                let path = path.join(&addr);
                let code = fs::read(&path).map_err(|err| match err.kind() {
                    std::io::ErrorKind::NotFound => Error::InvalidPath(path),
                    _ => Error::Io(err),
                })?;
                let raw = crypto::decrypt(pwd, &code)?;
                let secret = SecretKey::from_bytes(&raw)?;
                SECRETS.write()?.insert(addr, secret.clone());
                secret
            }
        };
        Ok(Self::from_secret(&secret, path, pwd))
    }

    /// save secret to file with address as filename
    pub fn save(&self, addr: &Address) -> Result<bool> {
        let addr = addr.to_hex();
        let raw = crypto::encrypt(&self.pwd, self.secret.as_bytes())?;
        let path = self.path.join(&addr);
        fs::write(&path, raw).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => Error::InvalidPath(path),
            _ => Error::Io(err),
        })?;
        Ok(true)
    }

    /// delete secret file with address
    pub fn remove(&self, addr: &Address) -> Result<bool> {
        let addr = addr.to_hex();
        fs::remove_file(self.path.join(&addr))?;
        Ok(true)
    }

    /// the file exist with address as filename
    pub fn exist(&self, addr: &Address) -> bool {
        let addr = addr.to_hex();
        self.path.join(&addr).is_file()
    }
}
