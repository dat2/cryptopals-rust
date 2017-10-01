use std::collections::VecDeque;
use std::u8;

use rand::{self, Rng};

use errors::*;
use prelude::*;

lazy_static! {
  static ref CBC_PADDING_ORACLE_KEY: Vec<u8> = random_bytes(16).unwrap();
  static ref CBC_PADDING_ORACLE_IV: Vec<u8> = random_bytes(16).unwrap();
  static ref CBC_PADDING_STRINGS: Vec<Vec<u8>> = {
    let mut result = Vec::new();
    result.push(from_base64_string("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=").unwrap());
    result.push(from_base64_string("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=").unwrap());
    result.push(from_base64_string("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==").unwrap());
    result.push(from_base64_string("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==").unwrap());
    result.push(from_base64_string("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl").unwrap());
    result.push(from_base64_string("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==").unwrap());
    result.push(from_base64_string("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==").unwrap());
    result.push(from_base64_string("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=").unwrap());
    result.push(from_base64_string("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=").unwrap());
    result.push(from_base64_string("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93").unwrap());
    result
  };
}

pub fn random_ciphertext() -> Result<(Vec<u8>, Vec<u8>)> {
  let mut rng = rand::thread_rng();
  let plaintext = rng.choose(&CBC_PADDING_STRINGS).unwrap();
  let padded_plaintext = pad_pkcs7(plaintext, 16);
  println!("input : {:?}", unsafe { ::std::str::from_utf8_unchecked(&padded_plaintext) });
  aes_128_cbc_encrypt_no_padding(&CBC_PADDING_ORACLE_KEY,
                                 &CBC_PADDING_ORACLE_IV,
                                 &padded_plaintext)
    .map(|ciphertext| (ciphertext, CBC_PADDING_ORACLE_IV.to_vec()))
}

pub fn padding_oracle(ciphertext: &[u8]) -> bool {
  aes_128_cbc_decrypt_no_padding(&CBC_PADDING_ORACLE_KEY, &CBC_PADDING_ORACLE_IV, ciphertext)
    .map(|plaintext| is_pkcs7_padded(&plaintext))
    .unwrap_or(false)
}

pub fn decrypt_ciphertext(ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {

  // the key idea, is that plaintext xored with previous ciphertext block
  // creates an intermediate state.

  // however, if a server leaks information about the padding of a block
  // (by returning 500 when a block is not padded for example)
  // then we can calculate this intermediate state and xor the previous
  // real ciphertext block with the intermediate state to get the plaintext
  // instantly

  let mut result = VecDeque::new();

  // to calculate the intermediate state, we can send this:
  // c1' c2 => p1' p2'
  // where c2 is the last block of ciphertext, and c1' is attacker controlled.
  // c1 is the second last block of the ciphertext.
  // the first and only byte (z) that triggers the leak will help us calculate
  // the intermediate state
  // i = z ^ p'
  // p = c1[16] ^ i
  for n in (0..ciphertext.len() / 16).rev() {

    let current_block = &ciphertext[n * 16..(n + 1) * 16];
    let previous_block = if n == 0 {
      iv
    } else {
      &ciphertext[(n - 1) * 16..n * 16]
    };

    let mut c1_suffix = VecDeque::new();
    for i in (0..16).rev() {

      let padding = 16 - i as u8;
      for c in &mut c1_suffix {
        *c ^= (padding - 1) ^ padding;
      }

      for z in 0..u8::MAX {
        // C1' C2
        let mut oracle_blocks = vec![0; i];
        oracle_blocks.push(z);
        oracle_blocks.extend(&c1_suffix);
        oracle_blocks.extend(current_block);

        if padding_oracle(&oracle_blocks) {
          result.push_front(previous_block[i] ^ z ^ padding);
          c1_suffix.push_front(z);
          break;
        }
      }
    }
  }

  let vec = Vec::from(result);
  if is_pkcs7_padded(&vec) {
    unpad_pkcs7(&vec)
  } else {
    Ok(vec)
  }
}
