use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, thread_rng};
use hmac::{Hmac, Mac};       
use sha2::Sha256;

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key_bytes = [0u8; 32]; // 256-bit key
    let iterations = 100_000;

    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        iterations,
        &mut key_bytes,
    );
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

type HmacSha256 = Hmac<Sha256>;

fn calculate_hmac(data: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
    .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&result);
    tag
}

fn verify_hmac(data: &[u8], expected_tag: &[u8], key: &[u8]) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
    .expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(expected_tag).is_ok()
}


pub fn encrypt_with_password(data: &[u8], password: &str) -> Vec<u8> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut salt);
    thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key_from_password(password, &salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .expect("Encryption failed");

    let mut output = [salt.to_vec(), nonce_bytes.to_vec(), ciphertext].concat();

    let hmac_key = &key[..];
    let tag = calculate_hmac(&output, hmac_key);
    output.extend_from_slice(&tag);
    output
}

pub fn decrypt_with_password(data: &[u8], password: &str) -> Vec<u8> {
    if data.len() < 16 + 12 + 32 {
        panic!("Data too short");
    }

    let data_len = data.len();
    let (without_tag, tag) = data.split_at(data_len - 32);

    let (salt, rest) = without_tag.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let key = derive_key_from_password(password, salt);
    let hmac_key = &key[..];

    if !verify_hmac(without_tag, tag, hmac_key) {
        panic!("HMAC verification failed — data corrupted or password incorrect");
    }

    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).expect("Decryption failed")
}