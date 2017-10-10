use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{u8, u16};

use rand::{self, Rng};
use rand::distributions::{IndependentSample, Range};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use errors::*;
use prelude::*;
use set1::{decrypt_single_byte_xor_cipher, break_repeating_key_xor};

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

pub fn get_base64_strings() -> Result<Vec<Vec<u8>>> {
  let mut base64_strings = Vec::new();
  base64_strings.push(from_base64_string("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==")?);
  base64_strings.push(from_base64_string("Q29taW5nIHdpdGggdml2aWQgZmFjZXM=")?);
  base64_strings.push(from_base64_string("RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==")?);
  base64_strings.push(from_base64_string("RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=")?);
  base64_strings.push(from_base64_string("SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk")?);
  base64_strings.push(from_base64_string("T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==")?);
  base64_strings.push(from_base64_string("T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=")?);
  base64_strings.push(from_base64_string("UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==")?);
  base64_strings.push(from_base64_string("QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=")?);
  base64_strings.push(from_base64_string("T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl")?);
  base64_strings.push(from_base64_string("VG8gcGxlYXNlIGEgY29tcGFuaW9u")?);
  base64_strings.push(from_base64_string("QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==")?);
  base64_strings.push(from_base64_string("QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=")?);
  base64_strings.push(from_base64_string("QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==")?);
  base64_strings.push(from_base64_string("QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=")?);
  base64_strings.push(from_base64_string("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")?);
  base64_strings.push(from_base64_string("VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==")?);
  base64_strings.push(from_base64_string("SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==")?);
  base64_strings.push(from_base64_string("SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==")?);
  base64_strings.push(from_base64_string("VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==")?);
  base64_strings.push(from_base64_string("V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==")?);
  base64_strings.push(from_base64_string("V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==")?);
  base64_strings.push(from_base64_string("U2hlIHJvZGUgdG8gaGFycmllcnM/")?);
  base64_strings.push(from_base64_string("VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=")?);
  base64_strings.push(from_base64_string("QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=")?);
  base64_strings.push(from_base64_string("VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=")?);
  base64_strings.push(from_base64_string("V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=")?);
  base64_strings.push(from_base64_string("SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==")?);
  base64_strings.push(from_base64_string("U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==")?);
  base64_strings.push(from_base64_string("U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=")?);
  base64_strings.push(from_base64_string("VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==")?);
  base64_strings.push(from_base64_string("QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu")?);
  base64_strings.push(from_base64_string("SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=")?);
  base64_strings.push(from_base64_string("VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs")?);
  base64_strings.push(from_base64_string("WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=")?);
  base64_strings.push(from_base64_string("SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0")?);
  base64_strings.push(from_base64_string("SW4gdGhlIGNhc3VhbCBjb21lZHk7")?);
  base64_strings.push(from_base64_string("SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=")?);
  base64_strings.push(from_base64_string("VHJhbnNmb3JtZWQgdXR0ZXJseTo=")?);
  base64_strings.push(from_base64_string("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")?);

  Ok(base64_strings)
}

pub fn encrypt_plaintexts_with_same_nonce(plaintexts: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
  let key = random_bytes(16)?;
  let nonce = 0;

  let mut result = Vec::new();
  for plaintext in plaintexts {
    result.push(aes_128_ctr(&key, nonce, plaintext)?);
  }

  Ok(result)
}

pub fn break_ctr_with_same_nonce(ciphertexts: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {

  // since we used the same nonce for each ciphertext
  // it means we used a single "fixed xor" key
  // for each

  // that means, we can transpose the individual bytes of
  // the ciphertext, same way as we did before

  // however, we have to do it on a block by block basis

  // eg
  // [ d2 ab 03 ] [ b5 ]
  // [ f3 e9 b8 ] [ 6f ]
  //
  // [ K1 K2 K3 ] [ K4 ]
  // K1..K4 is fixed xor "key"
  let max_length = ciphertexts.iter()
    .map(|c| c.len())
    .max()
    .unwrap_or(1);

  let mut keystream_bytes = Vec::new();
  for i in 0..max_length {
    let mut single_byte_xor_ciphertext = Vec::new();
    for ciphertext in ciphertexts {
      if let Some(&c) = ciphertext.get(i) {
        single_byte_xor_ciphertext.push(c);
      }
    }

    let (_, byte) = decrypt_single_byte_xor_cipher(&single_byte_xor_ciphertext);
    keystream_bytes.push(byte);
  }

  let mut result = Vec::new();
  for ciphertext in ciphertexts {
    result.push(fixed_xor(ciphertext, &keystream_bytes));
  }

  Ok(result)
}

pub fn break_ctr_with_same_nonce_as_repeating_key_xor(ciphertexts: &[Vec<u8>])
                                                      -> Result<Vec<Vec<u8>>> {

  let min_length = ciphertexts.iter()
    .map(|c| c.len())
    .min()
    .unwrap_or(1);

  let mut concated_ciphertext = Vec::new();
  for ciphertext in ciphertexts {
    println!("{:?}", ciphertext.len());
    concated_ciphertext.extend(&ciphertext[..min_length]);
  }

  let (_, key) = break_repeating_key_xor(&concated_ciphertext, min_length..min_length + 1);

  let mut result = Vec::new();
  for ciphertext in ciphertexts {
    result.push(fixed_xor(ciphertext, &key));
  }
  // this only extracts min_length bytes for each ciphertext
  // TODO extract the rest of the plaintexts... but i'm lazy :)

  Ok(result)
}

pub fn mersenne_rng(seed: u32) -> u32 {
  MersenneTwister::new(seed).gen() as u32
}

pub fn crack_mt19937_seed(output: u32, unix_timestamp: u32) -> u32 {
  (0..10000)
    .map(|i| {
      let mut rng = MersenneTwister::new(unix_timestamp - i);
      (unix_timestamp - i, rng.gen() as u32)
    })
    .find(|&(_, out)| out == output)
    .unwrap()
    .0
}

pub fn crack_mt19937_state(outputs: &[u32]) -> Vec<u32> {
  outputs.iter()
    .map(|&output| {
      // state = [seed, 1812433253 * seed ^ (seed >> 30) + 1, ...], index = 624
      // x_a = (seed & 0x80000000 + (1812433253 * seed ^ (seed >> 30) + 1) & 0x7fffffff) >> 1
      // state[0] = if x_a % 2 != 0 { x_a ^ 0x9908B0DF } else { x_a }

      // y = state[0]

      let mut y = output;

      // (4) y = y ^ (y >> 18)
      // since more than half of the bits are the same, its very easy to recover
      y ^= y >> 18;

      // (3) y = y ^ ((y << 15) & 0xEFC60000)
      // since more than half of the bits are the same, its very easy to recover again
      y ^= (y << 15) & 0xEFC60000;

      // (2) y = y ^ ((y << 7) & 0x9D2C5680
      // this is harder to recover, need to rebuild it up from the right side
      let mut y2 = y & 0x0000007F;
      for i in 7..32 {
        let bit_mask = 1 << i;
        let b_bit = 0x9D2C5680 & bit_mask;
        let y2_shifted_bit = (y2 << 7) & bit_mask;
        let mask = y2_shifted_bit & b_bit;
        let y2_bit = (y ^ mask) & bit_mask;

        y2 ^= y2_bit;
      }
      y = y2;

      // (1) y = y ^ (y >> 11)
      // this is harder to recover
      let mut y1 = y & 0xFFE00000;
      for i in 12..33 {
        let bit_mask = 1 << (32 - i);
        let y1_shifted_bit = (y1 >> 11) & bit_mask;
        let y_masked_bit = y & bit_mask;
        let y_bit = y1_shifted_bit ^ y_masked_bit;
        y1 ^= y_bit;
      }
      y = y1;

      y
    })
    .collect::<Vec<_>>()
}

pub fn mt19937_fixed_xor(seed: u16, data: &[u8]) -> Vec<u8> {
  let key: Vec<_> = MersenneTwister::new(seed as u32).keystream().take(data.len()).collect();
  fixed_xor(data, &key)
}

pub fn get_mt19937_ciphertext() -> Result<(u16, Vec<u8>)> {
  let mut thread_rng = rand::thread_rng();

  let prefix_len = Range::new(0, u8::MAX).ind_sample(&mut thread_rng);
  let mut plaintext = random_bytes(prefix_len as usize)?;
  plaintext.extend(b"AAAAAAAAAAAAAA");

  let seed = Range::new(0, u16::MAX).ind_sample(&mut thread_rng);
  Ok((seed, mt19937_fixed_xor(seed, &plaintext)))
}

pub fn break_mt19937_ciphertext(ciphertext: &[u8]) -> (u16, Vec<u8>) {
  (0..u16::MAX)
    .into_par_iter()
    .map(|seed| (seed, mt19937_fixed_xor(seed, ciphertext)))
    .find_any(|&(_, ref plaintext)| &plaintext[plaintext.len() - 14..] == b"AAAAAAAAAAAAAA")
    .unwrap()
}

pub fn generate_password_reset_token() -> Result<Vec<u8>> {
  let mut thread_rng = rand::thread_rng();

  let prefix_len = Range::new(0, u8::MAX).ind_sample(&mut thread_rng);
  let mut plaintext = random_bytes(prefix_len as usize)?;
  plaintext.extend(b"user_id=123456&expires=1000");

  let unix_duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
  let unix_timestamp = unix_duration.as_secs() as u32;

  let key: Vec<_> =
    MersenneTwister::new(unix_timestamp).keystream().take(plaintext.len()).collect();
  Ok(fixed_xor(&plaintext, &key))
}

pub fn is_password_token_using_mt19937(token: &[u8]) -> Result<bool> {
  let unix_duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
  let unix_timestamp = unix_duration.as_secs() as u32;

  Ok((0u32..10000u32)
    .into_par_iter()
    .map(|i| {
      let key: Vec<_> =
        MersenneTwister::new(unix_timestamp - i).keystream().take(token.len()).collect();
      fixed_xor(token, &key)
    })
    .find_any(|plaintext| {
      plaintext.windows(b"user_id=".len()).position(|window| window == b"user_id=").is_some()
    })
    .is_some())
}
