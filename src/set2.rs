use std::collections::{BTreeSet, BTreeMap, HashMap};
use std::u8;

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

#[derive(Debug, PartialEq)]
pub enum CipherMode {
  ECB,
  CBC
}

pub fn encryption_oracle(data: &[u8]) -> Result<(Vec<u8>, CipherMode)> {

  let mut rng = rand::thread_rng();

  // generate random prefix
  let count = Range::new(5, 10);
  let mut prefix_bytes = vec![0; count.ind_sample(&mut rng)];
  rand_bytes(&mut prefix_bytes)?;

  // prefix to the plaintext
  let mut plaintext = Vec::new();
  plaintext.extend(prefix_bytes);
  plaintext.extend(data);

  if rng.gen() {
    let ciphertext = aes_128_ecb_encrypt(&ORACLE_KEY, &plaintext)?;
    Ok((ciphertext, CipherMode::ECB))
  } else {
    // random iv
    let mut iv = vec![0; 16];
    rand_bytes(&mut iv)?;

    let ciphertext = aes_128_cbc_encrypt(&ORACLE_KEY, &iv, &plaintext)?;
    Ok((ciphertext, CipherMode::CBC))
  }
}

pub fn detect_cipher_mode(ciphertext: &[u8]) -> CipherMode {
  let mut set = BTreeSet::new();
  for chunk in ciphertext.chunks(16) {
    if set.get(&chunk).is_some() {
      return CipherMode::ECB;
    } else {
      set.insert(chunk);
    }
  }
  CipherMode::CBC
}

lazy_static! {
  static ref ECB_ORACLE_KEY: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
  static ref ECB_ORACLE_SUFFIX: Vec<u8> = {
    from_base64_string(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG\
       Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll\
       cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ\
       pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    ).unwrap()
  };
}

pub fn encryption_ecb_oracle(data: &[u8]) -> Result<Vec<u8>> {
  let mut plaintext = Vec::new();
  plaintext.extend(data);
  plaintext.extend(ECB_ORACLE_SUFFIX.iter());
  aes_128_ecb_encrypt(&ECB_ORACLE_KEY, &plaintext)
}

pub fn decrypt_ecb(oracle: fn(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {

  // step 1: discover block size
  let ciphertext = oracle(&Vec::new())?;
  let block_size = (1..32)
    .map(|i| oracle(&vec![0; i]).unwrap())
    .find(|new_ciphertext| new_ciphertext.len() > ciphertext.len())
    .unwrap()
    .len() - ciphertext.len();

  // step 2: detect ecb
  let detection_ciphertext = oracle(&vec![0; block_size * 3])?;
  if detect_cipher_mode(&detection_ciphertext) != CipherMode::ECB {
    println!("This oracle is not using ECB.");
    return Ok(Vec::new());
  }

  let mut result = Vec::new();

  for i in 1..ciphertext.len() {
    // step 3: create an input that is 1 byte short
    let shift = block_size - i % block_size;
    let controlled_input = vec![0; shift];
    let shifted_ciphertext = oracle(&controlled_input)?;

    let current_block = i / block_size;
    let shifted_ciphertext_block = shifted_ciphertext[current_block * block_size..(current_block + 1) * block_size].to_vec();

    // make a dictionary of every last possible byte
    let mut dictionary = HashMap::new();
    for b in 0..u8::MAX {
      let mut dictionary_input = controlled_input.clone();
      dictionary_input.extend(&result);
      dictionary_input.push(b);
      let dictionary_ciphertext = oracle(&dictionary_input)?;
      let dictionary_block = dictionary_ciphertext[current_block * block_size..(current_block + 1) * block_size].to_vec();
      dictionary.insert(dictionary_block, b);
    }

    if let Some(&plaintext_byte) = dictionary.get(&shifted_ciphertext_block) {
      result.push(plaintext_byte);
    } else {
      break;
    }
  }

  Ok(result)
}

pub fn parse_kv(bytes: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
  let mut result = BTreeMap::new();
  for kv_pair in bytes.split(|&b| b == b'&') {
    let pos = kv_pair.iter().position(|&b| b == b'=').ok_or(ErrorKind::ParseKvError(kv_pair.to_vec()))?;
    let (key, value_eq) = kv_pair.split_at(pos);
    result.insert(key.to_vec(), value_eq[1..].to_vec());
  }
  Ok(result)
}

pub fn encode_as_query_string(object: BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
  let mut result = Vec::new();
  for (k, v) in &object {
    result.extend(k);
    result.push(b'=');
    result.extend(v);
    result.push(b'&');
  }
  result.pop();
  result
}

lazy_static! {
  static ref ECB_CUT_AND_PASTE_KEY: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
}

pub fn profile_for(email: &[u8]) -> Result<Vec<u8>> {
  if (email.iter().position(|&b| b == b'=').is_some()) || (email.iter().position(|&b| b == b'&').is_some()) {
    bail!(ErrorKind::InvalidEmail(email.to_vec()));
  }

  let mut object = BTreeMap::new();
  object.insert(b"email".to_vec(), email.to_vec());
  object.insert(b"uid".to_vec(), b"10".to_vec());
  object.insert(b"role".to_vec(), b"user".to_vec());
  let plaintext = encode_as_query_string(object);
  aes_128_ecb_encrypt(&ECB_CUT_AND_PASTE_KEY, &plaintext)
}

pub fn create_admin_profile() -> Result<Vec<u8>> {
  //[email=0000000000][admin<padding>][&role=user&uid=1][0<padding>]
  let mut admin_input = vec![0; 16 - b"email=".len()];
  admin_input.extend(b"admin");
  admin_input.extend(vec![11; 11]);
  let admin_ciphertext = profile_for(&admin_input)?;

  //[email=0000000000][0000000000&role=][user&uid=10<padding>]
  let role_input = vec![0; 20];
  let role_ciphertext = profile_for(&role_input)?;

  //[email=0000000000][0000000000&role=][admin<padding>]
  let mut result = Vec::new();
  result.extend(role_ciphertext[..32].to_vec());
  result.extend(admin_ciphertext[16..32].to_vec());
  Ok(result)
}

pub fn decrypt_profile(ciphertext: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
  let plaintext = aes_128_ecb_decrypt(&ECB_CUT_AND_PASTE_KEY, ciphertext)?;
  parse_kv(&plaintext)
}
