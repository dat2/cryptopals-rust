use std::cmp;
use std::u64;

use rand;
use rand::distributions::{IndependentSample, Range};

use errors::*;
use prelude::*;

lazy_static! {
  static ref CTR_RANDOM_ACCESS_KEY: Vec<u8> = random_bytes(16).unwrap();
  static ref CTR_RANDOM_ACCESS_NONCE: u64 = {
    let mut thread_rng = rand::thread_rng();
    Range::new(0, u64::MAX).ind_sample(&mut thread_rng)
  };
}

pub fn encrypt_random_access_ctr(plaintext: &[u8]) -> Result<Vec<u8>> {
  aes_128_ctr(&CTR_RANDOM_ACCESS_KEY, *CTR_RANDOM_ACCESS_NONCE, plaintext)
}

pub fn edit(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Result<Vec<u8>> {
  let plaintext = aes_128_ctr(&CTR_RANDOM_ACCESS_KEY, *CTR_RANDOM_ACCESS_NONCE, ciphertext)?;

  let mut edited_plaintext = Vec::new();
  edited_plaintext.extend(&plaintext[..offset]);
  edited_plaintext.extend(newtext);
  edited_plaintext.extend(&plaintext[offset + newtext.len()..]);

  encrypt_random_access_ctr(&edited_plaintext)
}

pub fn break_random_access_ctr(ciphertext: &[u8]) -> Result<Vec<u8>> {

  let mut result = Vec::new();
  for block in 0..ciphertext.len() / 16 + 1 {
    let start = block * 16;
    let end = cmp::min((block + 1) * 16, ciphertext.len());
    let range = start..end;
    let zeros = vec![0; range.len()];

    let edited_ciphertext = edit(ciphertext, start, &zeros)?;
    result.extend(fixed_xor(&ciphertext[range.clone()], &edited_ciphertext[range]));
  }

  Ok(result)
}

// challenge 26
lazy_static! {
  static ref CTR_BITFLIPPING_KEY: Vec<u8> = random_bytes(16).unwrap();
  static ref CTR_BITFLIPPING_NONCE: u64 = {
    let mut thread_rng = rand::thread_rng();
    Range::new(0, u64::MAX).ind_sample(&mut thread_rng)
  };
}

pub fn encrypt_userdata(userdata: &[u8]) -> Result<Vec<u8>> {
  let prefix = b"comment1=cooking%20MCs;userdata=";
  let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

  let removed_semicolons: Vec<_> = userdata.split(|&b| b == b';').collect();
  let quoted_semicolons = intersperse(&removed_semicolons, b"%3B");
  let removed_equals: Vec<_> = quoted_semicolons.split(|&b| b == b'=').collect();
  let quoted_userdata = intersperse(&removed_equals, b"%3D");

  let mut plaintext = Vec::new();
  plaintext.extend_from_slice(prefix);
  plaintext.extend(quoted_userdata);
  plaintext.extend_from_slice(suffix);

  aes_128_ctr(&CTR_BITFLIPPING_KEY, *CTR_BITFLIPPING_NONCE, &plaintext)
}


pub fn insert_admin_into_userdata(ciphertext: &[u8]) -> Vec<u8> {
  let mut result = ciphertext.to_vec();

  // %3Badmin%3Dtrue
  // %3;admin=true;e

  // B (0x42) => ; (0x3B)
  result[34] ^= 0x79;
  // % (0x25) => = (0x3D)
  result[40] ^= 0x18;
  // 3 (0x33) => t (0x74)
  result[41] ^= 0x47;
  // D (0x44) => r (0x72)
  result[42] ^= 0x36;
  // t (0x74) => u (0x75)
  result[43] ^= 0x01;
  // r (0x72) => e (0x65)
  result[44] ^= 0x17;
  // u (0x75) => ; (0x3B)
  result[45] ^= 0x4E;

  result
}

pub fn inserted_admin_into_userdata(ciphertext: &[u8]) -> Result<bool> {
  let plaintext = aes_128_ctr(&CTR_BITFLIPPING_KEY, *CTR_BITFLIPPING_NONCE, ciphertext)?;
  Ok(plaintext.split(|&b| b == b';').any(|chunk| chunk == b"admin=true"))
}

// challenge 27
lazy_static! {
  pub static ref CBC_KEY_IV: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
}

pub fn encrypt_userdata_with_same_key_iv(userdata: &[u8]) -> Result<Vec<u8>> {
  let prefix = b"comment1=cooking%20MCs;userdata=";
  let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

  let removed_semicolons: Vec<_> = userdata.split(|&b| b == b';').collect();
  let quoted_semicolons = intersperse(&removed_semicolons, b"%3B");
  let removed_equals: Vec<_> = quoted_semicolons.split(|&b| b == b'=').collect();
  let quoted_userdata = intersperse(&removed_equals, b"%3D");

  let mut plaintext = Vec::new();
  plaintext.extend_from_slice(prefix);
  plaintext.extend(quoted_userdata);
  plaintext.extend_from_slice(suffix);

  aes_128_cbc_encrypt(&CBC_KEY_IV, &CBC_KEY_IV, &plaintext)
}

#[derive(Debug)]
struct HighAsciiBytesFound(Vec<u8>);

fn decrypt_with_same_key_iv(ciphertext: &[u8]) -> Result<Option<HighAsciiBytesFound>> {
  let plaintext = aes_128_cbc_decrypt(&CBC_KEY_IV, &CBC_KEY_IV, ciphertext)?;

  for &c in &plaintext {
    if c > 127 {
      return Ok(Some(HighAsciiBytesFound(plaintext.clone())))
    }
  }

  Ok(None)
}

pub fn recover_key(ciphertext: &[u8]) -> Result<Vec<u8>> {

  let mut modified_message = Vec::new();
  modified_message.extend_from_slice(&ciphertext[..16]);
  modified_message.extend_from_slice(&vec![0; 16]);
  modified_message.extend_from_slice(&ciphertext[..16]);
  modified_message.extend_from_slice(&ciphertext[48..]);

  if let Some(HighAsciiBytesFound(plaintext)) = decrypt_with_same_key_iv(&modified_message)? {
    Ok(fixed_xor(&plaintext[..16], &plaintext[32..48]))
  } else {
    Ok(Vec::new())
  }
}
