use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{self, Rng};
use rand::distributions::{IndependentSample, Range};

use errors::*;
use prelude::*;

// this is a copy of openssl::symm::decrypt, but with padding disabled on the Crypter
fn aes_128_ecb_decrypt_simple(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
  c.pad(false);
  let mut out = vec![0; data.len() + Cipher::aes_128_ecb().block_size()];
  let count = c.update(data, &mut out)?;
  let rest = c.finalize(&mut out[count..])?;
  out.truncate(count + rest);
  Ok(out)
}

pub fn aes_128_cbc_decrypt_manual(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  let mut result = Vec::new();
  let mut previous_chunk = iv.to_vec();
  for chunk in data.chunks(16) {
    let plaintext_xored = aes_128_ecb_decrypt_simple(key, chunk)?;
    let plaintext = fixed_xor(&plaintext_xored, &previous_chunk);
    previous_chunk = chunk.to_vec();
    result.extend(plaintext);
  }
  Ok(result)
}

lazy_static! {
  static ref ORACLE_KEY: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
}

pub fn encryption_oracle(data: &[u8]) -> Result<Vec<u8>> {

  let mut rng = rand::thread_rng();

  let count = Range::new(5, 10);
  let mut prefix_bytes = vec![0; count.ind_sample(&mut rng)];
  rand_bytes(&mut prefix_bytes)?;

  let mut plaintext = Vec::new();
  plaintext.extend(prefix_bytes);
  plaintext.extend(data);

  if rng.gen() {
    aes_128_ecb_encrypt(&ORACLE_KEY, &plaintext)
  } else {
    let mut iv = vec![0; 16];
    rand_bytes(&mut iv)?;
    aes_128_cbc_encrypt(&ORACLE_KEY, &iv, &plaintext)
  }
}
