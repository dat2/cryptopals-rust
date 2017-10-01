use std::collections::{BTreeSet, BTreeMap, HashMap};
use std::u8;

use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{self, Rng};
use rand::distributions::{IndependentSample, Range};

use errors::*;
use prelude::*;

// challenge 10
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

// challenge 11
#[derive(Debug, PartialEq)]
pub enum CipherMode {
  ECB,
  CBC,
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

fn is_aes_ecb(ciphertext: &[u8]) -> bool {
  let mut set = BTreeSet::new();
  for chunk in ciphertext.chunks(16) {
    if set.get(&chunk).is_some() {
      return true;
    } else {
      set.insert(chunk);
    }
  }
  false
}

pub fn detect_cipher_mode(ciphertext: &[u8]) -> CipherMode {
  if is_aes_ecb(ciphertext) {
    CipherMode::ECB
  } else {
    CipherMode::CBC
  }
}

// challenge 12
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
  if !is_aes_ecb(&detection_ciphertext) {
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
    let shifted_ciphertext_block =
      shifted_ciphertext[current_block * block_size..(current_block + 1) * block_size].to_vec();

    // make a dictionary of every last possible byte
    let mut dictionary = HashMap::new();
    for b in 0..u8::MAX {
      let mut dictionary_input = controlled_input.clone();
      dictionary_input.extend(&result);
      dictionary_input.push(b);
      let dictionary_ciphertext = oracle(&dictionary_input)?;
      let dictionary_block = dictionary_ciphertext[current_block * block_size..(current_block + 1) *
                                                                               block_size]
        .to_vec();
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

// challenge 13
pub fn parse_kv(bytes: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
  let mut result = BTreeMap::new();
  for kv_pair in bytes.split(|&b| b == b'&') {
    let pos = kv_pair.iter()
      .position(|&b| b == b'=')
      .ok_or_else(|| ErrorKind::ParseKvError(kv_pair.to_vec()))?;
    let (key, value_eq) = kv_pair.split_at(pos);
    result.insert(key.to_vec(), value_eq[1..].to_vec());
  }
  Ok(result)
}

pub fn encode_as_query_string(object: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
  let mut result = Vec::new();
  for (k, v) in object {
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
  if email.iter().any(|&b| b == b'=') || email.iter().any(|&b| b == b'&') {
    bail!(ErrorKind::InvalidEmail(email.to_vec()));
  }

  let mut object = BTreeMap::new();
  object.insert(b"email".to_vec(), email.to_vec());
  object.insert(b"uid".to_vec(), b"10".to_vec());
  object.insert(b"role".to_vec(), b"user".to_vec());
  let plaintext = encode_as_query_string(&object);
  aes_128_ecb_encrypt(&ECB_CUT_AND_PASTE_KEY, &plaintext)
}

pub fn create_admin_profile() -> Result<Vec<u8>> {
  // [email=0000000000][admin<padding>][&role=user&uid=1][0<padding>]
  let mut admin_input = vec![0; 16 - b"email=".len()];
  admin_input.extend(b"admin");
  admin_input.extend(vec![11; 11]);
  let admin_ciphertext = profile_for(&admin_input)?;

  // [email=0000000000][0000000000&role=][user&uid=10<padding>]
  let role_input = vec![0; 20];
  let role_ciphertext = profile_for(&role_input)?;

  // [email=0000000000][0000000000&role=][admin<padding>]
  let mut result = Vec::new();
  result.extend(role_ciphertext[..32].to_vec());
  result.extend(admin_ciphertext[16..32].to_vec());
  Ok(result)
}

pub fn decrypt_profile(ciphertext: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
  let plaintext = aes_128_ecb_decrypt(&ECB_CUT_AND_PASTE_KEY, ciphertext)?;
  parse_kv(&plaintext)
}

// challenge 14
lazy_static! {
  static ref ECB_HARD_ORACLE_KEY: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
  static ref ECB_HARD_ORACLE_PREFIX: Vec<u8> = {
    let mut rng = rand::thread_rng();
    let count = Range::new(0, 100);
    let mut prefix = vec![0; count.ind_sample(&mut rng)];
    rand_bytes(&mut prefix).unwrap();
    prefix
  };
  static ref ECB_HARD_ORACLE_SUFFIX: Vec<u8> = {
    from_base64_string(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG\
       Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll\
       cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ\
       pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    ).unwrap()
  };
}

pub fn encryption_ecb_oracle_hard(data: &[u8]) -> Result<Vec<u8>> {
  let mut plaintext = Vec::new();
  plaintext.extend_from_slice(&ECB_HARD_ORACLE_PREFIX);
  plaintext.extend(data);
  plaintext.extend_from_slice(&ECB_HARD_ORACLE_SUFFIX);
  aes_128_ecb_encrypt(&ECB_HARD_ORACLE_KEY, &plaintext)
}

pub fn decrypt_ecb_hard(oracle: fn(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {

  // step 1: discover block size
  let empty_ciphertext = oracle(&Vec::new())?;
  let block_size = (1..32)
    .map(|i| oracle(&vec![0; i]).unwrap())
    .find(|new_ciphertext| new_ciphertext.len() > empty_ciphertext.len())
    .unwrap()
    .len() - empty_ciphertext.len();

  // step 2: figure out how much to pad the prefix by
  let prefix_padding = (1..block_size)
    .map(|i| (i, oracle(&vec![0; i + block_size * 2]).unwrap()))
    .find(|&(_, ref ciphertext)| is_aes_ecb(ciphertext))
    .unwrap()
    .0;

  // step 3: figure out how many blocks the prefix + padding is
  let prefix_plaintext = vec![0; prefix_padding + block_size * 2];
  let prefix_ciphertext = oracle(&prefix_plaintext)?;

  let mut prefix_blocks = 0;
  let mut set = BTreeSet::new();
  for (i, block) in prefix_ciphertext.chunks(16).enumerate() {
    // since we know that prefix_padding + block_size * 2 will cause
    // 2 blocks to be the same, then we just search for them
    if set.get(&block).is_some() {
      prefix_blocks = i - 1;
      break;
    } else {
      set.insert(block);
    }
  }

  let mut result = Vec::new();

  for i in 1..empty_ciphertext.len() {
    // step 3: create an input that is 1 byte short
    let shift = prefix_padding + block_size - i % block_size;
    let controlled_input = vec![0; shift];
    let shifted_ciphertext = oracle(&controlled_input)?;

    let current_block = prefix_blocks + i / block_size;
    let current_block_range = current_block * block_size..(current_block + 1) * block_size;
    let shifted_ciphertext_block = shifted_ciphertext[current_block_range.clone()].to_vec();

    // make a dictionary of every last possible byte
    let mut dictionary = HashMap::new();
    for b in 0..u8::MAX {
      let mut dictionary_input = controlled_input.clone();
      dictionary_input.extend(&result);
      dictionary_input.push(b);
      let dictionary_ciphertext = oracle(&dictionary_input)?;
      let dictionary_block = dictionary_ciphertext[current_block_range.clone()].to_vec();
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

lazy_static! {
  static ref CBC_BITFLIPPING_KEY: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
  static ref CBC_BITFLIPPING_IV: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
}

// challenge 16
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

  aes_128_cbc_encrypt(&CBC_BITFLIPPING_KEY, &CBC_BITFLIPPING_IV, &plaintext)
}

pub fn insert_admin_into_userdata(ciphertext: &[u8]) -> Vec<u8> {
  let mut result = ciphertext.to_vec();

  // the plaintext has    "%3Badmin%3Dtrue"
  // so, we change it to  "a3;admin=true;e"

  // % => a
  result[16] ^= 0x44;
  // B => ;
  result[18] ^= 0x79;
  // % => =
  result[24] ^= 0x18;
  // 3 => t
  result[25] ^= 0x47;
  // D => r
  result[26] ^= 0x36;
  // t => u
  result[27] ^= 0x01;
  // r => e
  result[28] ^= 0x17;
  // u => ;
  result[29] ^= 0x04E;

  result
}

pub fn inserted_admin_into_userdata(ciphertext: &[u8]) -> Result<bool> {
  let plaintext = aes_128_cbc_decrypt(&CBC_BITFLIPPING_KEY, &CBC_BITFLIPPING_IV, ciphertext)?;
  Ok(plaintext.split(|&b| b == b';').any(|chunk| chunk == b"admin=true"))
}
