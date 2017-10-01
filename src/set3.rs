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
  println!("input bytes     : {:?}", padded_plaintext);
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

pub fn decrypt_ciphertext(ciphertext: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {

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
  for z in 0..u8::MAX {
    let mut oracle_blocks = vec![0; 15];
    oracle_blocks.push(z);
    oracle_blocks.extend(ciphertext[ciphertext.len() - 16..].to_vec());
    if padding_oracle(&oracle_blocks) {
      result.push_back(ciphertext[ciphertext.len() - 16 - 1] ^ z ^ 0x01);
      break;
    }
  }

  // there's only 1/256 chance (of random texts) where the last byte is actually
  // 0x01, all other bytes will have a few candidates
  // if last_byte_candidates.is_empty() {
  //   result.push_back(0x01);
  // } else {

  //   let mut padding = 0;
  //   for &candidate in &last_byte_candidates {
  //     // if its padding between 4 and 16, we can easily detect it
  //     if candidate > 2 && candidate <= 16 {
  //       let mut copied_ciphertext = ciphertext.to_vec();
  //       copied_ciphertext[ciphertext.len() - 16 - 2] ^= candidate ^ 0x02;
  //       copied_ciphertext[ciphertext.len() - 16 - 1] ^= candidate ^ 0x02;
  //       if padding_oracle(&copied_ciphertext) {
  //         padding = candidate;
  //         break;
  //       }
  //     } else if candidate == 2 {
  //       // however, if its 0x02 0x02, we just need to verify it
  //       let mut copied_ciphertext = ciphertext.to_vec();
  //       copied_ciphertext[ciphertext.len() - 16 - 2] ^= 0x02;
  //       copied_ciphertext[ciphertext.len() - 16 - 1] ^= 0x02;
  //       if padding_oracle(&copied_ciphertext) {
  //         padding = candidate;
  //         break;
  //       }
  //     } else {
  //       // if its not padding, we need to filter out the right byte
  //       for z in 16..u8::MAX {
  //         let mut copied_ciphertext = ciphertext.to_vec();
  //         copied_ciphertext[ciphertext.len() - 16 - 2] ^= z ^ 0x02;
  //         copied_ciphertext[ciphertext.len() - 16 - 1] ^= candidate ^ 0x02;
  //         if padding_oracle(&copied_ciphertext) {
  //           result.push_front(candidate);
  //           result.push_front(z);
  //           break;
  //         }
  //       }
  //     }
  //   }

  //   // if we detected that its padded, then pad it for us
  //   if padding != 0 {
  //     result.extend(vec![padding; padding as usize]);
  //   }

  // }

  // // this only works for the last block
  // for i in (result.len() + 1)..(ciphertext.len() - 16 + 1) {

  //   let mask_prefix = vec![0; ciphertext.len() - 16 - i];

  //   for guessed_value in 1..u8::MAX {
  //     let mut mask = mask_prefix.clone();
  //     mask.push(guessed_value ^ i as u8);
  //     for r in &result {
  //       mask.push(r ^ i as u8);
  //     }
  //     mask.extend(vec![0; 16]);

  //     // [0_prefix][result][0_suffix]

  //     let xored_ciphertext = fixed_xor(ciphertext, &mask);
  //     if padding_oracle(&xored_ciphertext) {
  //       result.push_front(guessed_value);
  //       break;
  //     }
  //   }

  // }

  // let vec = Vec::from(result);
  // if is_pkcs7_padded(&vec) {
  //   unpad_pkcs7(&vec).unwrap()
  // } else {
  //   vec
  // }

  Ok(Vec::from(result))
}
