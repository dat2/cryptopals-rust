use std::ascii::AsciiExt;
use std::cmp::Ordering;
use std::collections::{HashMap, BTreeSet};
use std::iter;

use itertools::Itertools;
use rayon::prelude::*;

use prelude::*;

#[derive(Debug)]
struct LetterCounter {
  letters: HashMap<char, usize>,
  penalty: usize,
  total_count: usize,
}

impl LetterCounter {
  fn new() -> LetterCounter {
    LetterCounter {
      letters: HashMap::new(),
      penalty: 0,
      total_count: 0,
    }
  }

  fn count(&mut self, letter: u8) {
    if letter.is_ascii_alphabetic() {
      let letter_entry = self.letters.entry((letter.to_ascii_lowercase() as char)).or_insert(0);
      *letter_entry += 1;
    } else if letter != b' ' {
      self.penalty += 1;
    }
    self.total_count += 1;
  }

  fn score(&self) -> f32 {
    let mut english_frequency = HashMap::new();
    english_frequency.insert('a', 0.08167);
    english_frequency.insert('b', 0.01492);
    english_frequency.insert('c', 0.02782);
    english_frequency.insert('d', 0.04253);
    english_frequency.insert('e', 0.12702);
    english_frequency.insert('f', 0.02228);
    english_frequency.insert('g', 0.02015);
    english_frequency.insert('h', 0.06094);
    english_frequency.insert('i', 0.06966);
    english_frequency.insert('j', 0.00153);
    english_frequency.insert('k', 0.00772);
    english_frequency.insert('l', 0.04025);
    english_frequency.insert('m', 0.02406);
    english_frequency.insert('n', 0.06749);
    english_frequency.insert('o', 0.07507);
    english_frequency.insert('p', 0.01929);
    english_frequency.insert('q', 0.00095);
    english_frequency.insert('r', 0.05987);
    english_frequency.insert('s', 0.06327);
    english_frequency.insert('t', 0.09056);
    english_frequency.insert('u', 0.02758);
    english_frequency.insert('v', 0.00978);
    english_frequency.insert('w', 0.02360);
    english_frequency.insert('x', 0.00150);
    english_frequency.insert('y', 0.01974);
    english_frequency.insert('z', 0.00074);

    let mut result = 0.0;
    for (letter, frequency) in &english_frequency {
      let self_frequency = (self.letters.get(letter).cloned().unwrap_or(0) as f32) /
                           self.total_count as f32;
      result += (self_frequency - *frequency).abs();
    }
    result += self.penalty as f32;
    result
  }
}

pub fn english_error(xor_bytes: &[u8]) -> f32 {
  let mut counter = LetterCounter::new();
  for byte in xor_bytes {
    counter.count(*byte);
  }
  counter.score()
}

pub fn decrypt_single_byte_xor_cipher(xor_bytes: &[u8]) -> (Vec<u8>, u8) {
  (0 as u8..255 as u8)
    .into_par_iter()
    .map(|byte| {
      let mask: Vec<_> = iter::repeat(byte as u8).take(xor_bytes.len()).collect();
      (fixed_xor(xor_bytes, &mask), byte)
    })
    .map(|(xored, byte)| (xored.clone(), byte, english_error(&xored)))
    .min_by(|&(_, _, a_score), &(_, _, b_score)| {
      a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal)
    })
    .map(|(xored, byte, _)| (xored, byte))
    .unwrap()
}

pub fn detect_single_character_xor(xor_bytes: Vec<Vec<u8>>) -> (Vec<u8>, u8) {
  xor_bytes.par_iter()
    .map(|bytes| decrypt_single_byte_xor_cipher(&bytes))
    .map(|(decrypted, byte)| (decrypted.clone(), byte, english_error(&decrypted)))
    .min_by(|&(_, _, a_score), &(_, _, b_score)| {
      a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal)
    })
    .map(|(decrypted, byte, _)| (decrypted, byte))
    .unwrap()
}

pub fn break_repeating_key_xor(input_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
  // figure out the key sizes with the smallest hamming distance
  let key_sizes: Vec<_> = (2..40)
    .map(|key_size| {
      let first_keysize_bytes = input_bytes.get(0..key_size).unwrap();
      let second_keysize_bytes = input_bytes.get(key_size..(key_size * 2)).unwrap();
      let third_keysize_bytes = input_bytes.get((key_size * 2)..(key_size * 3)).unwrap();
      let fourth_keysize_bytes = input_bytes.get((key_size * 3)..(key_size * 4)).unwrap();

      let first_hamming_distance = hamming_distance(&first_keysize_bytes, &second_keysize_bytes);
      let second_hamming_distance = hamming_distance(&third_keysize_bytes, &fourth_keysize_bytes);
      let average_hamming_distance =
        (first_hamming_distance as f32 + second_hamming_distance as f32) / 2.0;

      (average_hamming_distance / (key_size as f32), key_size)
    })
    .sorted_by(|&(a_score, _), &(b_score, _)| {
      a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal)
    })
    .into_iter()
    .map(|(_, result)| result)
    .collect();

  // for each key size, figure out the individual bytes of the key
  // by transposing the ciphertext into a list of blocks
  // and decrypting them
  let keys: Vec<_> = key_sizes.into_par_iter()
    .map(|key_size| {
      (0..key_size)
      .into_par_iter()
      .map(|offset| input_bytes.iter().skip(offset).step_by(key_size).cloned().collect::<Vec<_>>())
      .map(|block| decrypt_single_byte_xor_cipher(&block))
      .map(|(_, key_byte)| key_byte)
      .collect::<Vec<_>>()
    })
    .collect();

  // decrypt, return the one with the best score
  keys.into_par_iter()
    .map(|key| (encrypt_repeating_key(input_bytes, &key), key))
    .map(|(decrypted, key)| (decrypted.clone(), key, english_error(&decrypted)))
    .min_by(|&(_, _, a_score), &(_, _, b_score)| {
      a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal)
    })
    .map(|(decrypted, key, _)| (decrypted, key))
    .unwrap()
}

pub fn detect_aes_ecb_mode(hex_bytes_list: Vec<Vec<u8>>) -> Vec<u8> {
  hex_bytes_list.iter()
    .find(|bytes| {
      let mut set = BTreeSet::new();
      for chunk_iter in &bytes.into_iter().chunks(16) {
        let chunk: Vec<_> = chunk_iter.into_iter().collect();
        if let Some(_) = set.get(&chunk) {
          return true;
        } else {
          set.insert(chunk);
        }
      }
      false
    })
    .cloned()
    .unwrap_or(Vec::new())
}
