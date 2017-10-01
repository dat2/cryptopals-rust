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
  let padded_plaintext = pad_pkcs7(plaintext, 16);
  println!("plaintext_bytes: {:?}", padded_plaintext);
  aes_128_cbc_encrypt_no_padding(&CBC_PADDING_ORACLE_KEY,
                                 &CBC_PADDING_ORACLE_IV,
                                 &padded_plaintext)
}

pub fn padding_oracle(ciphertext: &[u8]) -> bool {
  aes_128_cbc_decrypt_no_padding(&CBC_PADDING_ORACLE_KEY, &CBC_PADDING_ORACLE_IV, ciphertext)
    .map(|plaintext| is_pkcs7_padded(&plaintext))
    .unwrap_or(false)
}

pub fn decrypt_ciphertext(ciphertext: &[u8]) -> Vec<u8> {

  // preconditions: ciphertext length > 16

  let mut result = VecDeque::new();

  // there are a few false positives, so we need to filter them out
  // rev protects against 0x03 being tripped up by 0x02
  let mut last_byte_candidates = Vec::new();
  for z in (2..u8::MAX).rev() {
    let mut copied_ciphertext = ciphertext.to_vec();
    copied_ciphertext[ciphertext.len() - 16 - 1] ^= z ^ 0x01;
    if padding_oracle(&copied_ciphertext) {
      last_byte_candidates.push(z);
    }
  }

  // there's only 1/256 chance (of random texts) where the last byte is actually
  // 0x01, all other bytes will have a few candidates
  if last_byte_candidates.is_empty() {
    result.push_back(0x01);
  } else {

    let mut padding = 0;
    for &candidate in &last_byte_candidates {
      // if its padding between 4 and 16, we can easily detect it
      if candidate > 2 && candidate <= 16 {
        let mut copied_ciphertext = ciphertext.to_vec();
        copied_ciphertext[ciphertext.len() - 16 - 2] ^= candidate ^ 0x02;
        copied_ciphertext[ciphertext.len() - 16 - 1] ^= candidate ^ 0x02;
        if padding_oracle(&copied_ciphertext) {
          padding = candidate;
          break;
        }
      } else if candidate == 2 {
        // however, if its 0x02 0x02, we just need to verify it
        let mut copied_ciphertext = ciphertext.to_vec();
        copied_ciphertext[ciphertext.len() - 16 - 2] ^= 0x02;
        copied_ciphertext[ciphertext.len() - 16 - 1] ^= 0x02;
        if padding_oracle(&copied_ciphertext) {
          padding = candidate;
          break;
        }
      } else {
        // if its not padding, we need to filter out the right byte
        for z in 16..u8::MAX {
          let mut copied_ciphertext = ciphertext.to_vec();
          copied_ciphertext[ciphertext.len() - 16 - 2] ^= z ^ 0x02;
          copied_ciphertext[ciphertext.len() - 16 - 1] ^= candidate ^ 0x02;
          if padding_oracle(&copied_ciphertext) {
            result.push_front(candidate);
            result.push_front(z);
            break;
          }
        }
      }
    }

    // if we detected that its padded, then pad it for us
    if padding != 0 {
      result.extend(vec![padding; padding as usize]);
    }

  }

  for i in (result.len() + 1)..(ciphertext.len() - 16) {

    let mask_prefix = vec![0; ciphertext.len() - 16 - i];

    for guessed_value in 1..u8::MAX {
      let mut mask = mask_prefix.clone();
      mask.push(guessed_value ^ i as u8);
      for r in &result {
        mask.push(r ^ i as u8);
      }
      mask.extend(vec![0; 16]);

      let xored_ciphertext = fixed_xor(ciphertext, &mask);
      if padding_oracle(&xored_ciphertext) {
        result.push_front(guessed_value);
        break;
      }
    }

  }

  let vec = Vec::from(result);
  if is_pkcs7_padded(&vec) {
    unpad_pkcs7(&vec).unwrap()
  } else {
    vec
  }
}
