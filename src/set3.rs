use std::collections::VecDeque;
use std::u8;

use openssl::rand::rand_bytes;
use rand::{self, Rng};

use errors::*;
use prelude::*;

lazy_static! {
  static ref CBC_PADDING_ORACLE_KEY: Vec<u8> = {
    let mut key = vec![0; 16];
    rand_bytes(&mut key).unwrap();
    key
  };
  static ref CBC_PADDING_ORACLE_IV: Vec<u8> = {
    let mut iv = vec![0; 16];
    rand_bytes(&mut iv).unwrap();
    iv
  };
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

pub fn random_ciphertext() -> Result<Vec<u8>> {
  let mut rng = rand::thread_rng();
  let plaintext = rng.choose(&CBC_PADDING_STRINGS).unwrap();
  let padded_plaintext = pad_pkcs7(&plaintext, 16);
  println!("plaintext: {:?}", unsafe { ::std::str::from_utf8_unchecked(plaintext) });
  println!("plaintext_bytes: {:?}", padded_plaintext);
  aes_128_cbc_encrypt_no_padding(&CBC_PADDING_ORACLE_KEY,
                                 &CBC_PADDING_ORACLE_IV,
                                 &padded_plaintext)
}

pub fn padding_oracle(ciphertext: &[u8]) -> bool {
  aes_128_cbc_decrypt_no_padding(&CBC_PADDING_ORACLE_KEY, &CBC_PADDING_ORACLE_IV, ciphertext)
    .and_then(|plaintext| unpad_pkcs7(&plaintext))
    .is_ok()
}

pub fn decrypt_ciphertext(ciphertext: &[u8]) -> Vec<u8> {

  let mut result = VecDeque::new();

  for i in 1..17 {
    for guessed_value in 2..u8::MAX {
      let mut mask = vec![0; ciphertext.len() - 16 - i];
      mask.push(guessed_value ^ i as u8);
      for r in &result {
        mask.push(r ^ i as u8);
      }
      let rest_length = ciphertext.len() - mask.len();
      mask.extend(vec![0; rest_length]);

      let masked = fixed_xor(ciphertext, &mask);
      if padding_oracle(&masked) {
        result.push_front(guessed_value);
        break;
      }
    }
  }

  Vec::from(result)
}
