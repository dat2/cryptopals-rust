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
