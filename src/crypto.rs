use crate::error::Result;
use aes_gcm::{
    aead::{Aead, Key, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

// const SECRET_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// encryption text with key
pub fn encrypt(key: &[u8], text: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    // let mut key_ret = [0x30; SECRET_KEY_SIZE];
    // key_ret[..key.len()].copy_from_slice(key);

    let mut nonce_ret = [0x0; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_ret);
    let nonce = Nonce::from_slice(&nonce_ret);

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut crypt_text = cipher.encrypt(&nonce, text.as_ref())?;
    let mut dst_out = nonce.to_vec();
    dst_out.append(&mut crypt_text);
    Ok(dst_out)
}

/// decryption code with key
pub fn decrypt(key: &[u8], code: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    // let mut key_ret = [0x30; SECRET_KEY_SIZE];
    // key_ret[..key.len()].copy_from_slice(key);

    let code = code.as_ref();
    assert!(code.len() > 12, "Encrypt code error");
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&code[..NONCE_SIZE]);
    let crypt_text = &code[NONCE_SIZE..];
    let dst_out = cipher.decrypt(nonce, crypt_text)?;
    Ok(dst_out)
}
