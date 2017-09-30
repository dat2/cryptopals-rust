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
    // result.push(from_base64_string("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=").unwrap());
    // result.push(from_base64_string("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=").unwrap());
    // result.push(from_base64_string("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==").unwrap());
    // result.push(from_base64_string("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==").unwrap());
    // result.push(from_base64_string("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl").unwrap());
    // result.push(from_base64_string("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==").unwrap());
    // result.push(from_base64_string("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==").unwrap());
    // result.push(from_base64_string("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=").unwrap());
    // result.push(from_base64_string("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=").unwrap());
    // result.push(from_base64_string("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93").unwrap());
    for i in 1..16 {
      let mut plaintext = vec![0; 16];
      plaintext.extend(vec![0; 16 - i % 16]);
      result.push(plaintext);
    }
    result
  };
}

pub fn random_ciphertext() -> Result<Vec<u8>> {
  let mut rng = rand::thread_rng();
  let plaintext = rng.choose(&CBC_PADDING_STRINGS).unwrap();
  let padded_plaintext = pad_pkcs7(&plaintext, 16);
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

  // preconditions: ciphertext length > 16

  let mut result = VecDeque::new();

  let mut last_byte_candidates = Vec::new();
  for z in 2..u8::MAX {
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
    for &last_byte in &last_byte_candidates {
      if last_byte > 3 && last_byte <= 16 {
        let mut copied_ciphertext = ciphertext.to_vec();
        copied_ciphertext[ciphertext.len() - 16 - 2] ^= last_byte ^ 0x02;
        copied_ciphertext[ciphertext.len() - 16 - 1] ^= last_byte ^ 0x02;
        if padding_oracle(&copied_ciphertext) {
          padding = last_byte;
          break;
        }
      } else if last_byte <= 3 {
        // test if its 3 first, then test if its 2
      } else {
      }
    }

    if padding != 0 {
      result.extend(vec![padding; padding as usize]);
    }

  }


  // for i in 2..17 {
  //   for guessed_value in 2..u8::MAX {
  //     let mut mask = vec![0; ciphertext.len() - 16 - i];
  //     mask.push(guessed_value ^ i as u8);
  //     for r in &result {
  //       mask.push(r ^ i as u8);
  //     }
  //     let rest_length = ciphertext.len() - mask.len();
  //     mask.extend(vec![0; rest_length]);

  //     let masked = fixed_xor(ciphertext, &mask);
  //     if padding_oracle(&masked) {
  //       result.push_front(guessed_value);
  //       break;
  //     }
  //   }
  // }

  Vec::from(result)
}
