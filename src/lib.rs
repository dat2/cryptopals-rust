#![recursion_limit = "1024"]
#![feature(ascii_ctype)]

#[macro_use]
extern crate error_chain;
extern crate rayon;

use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::cmp::Ordering;
use std::iter;
use std::str;

use rayon::prelude::*;

pub mod errors;
use errors::*;

fn char_to_byte(c: char) -> Result<u8> {
  c.to_digit(16)
    .map(|r| r as u8)
    .ok_or(ErrorKind::InvalidHexChar(c).into())
}

pub fn from_hex_string(hex_str: &str) -> Result<Vec<u8>> {
  let chars: Vec<_> = hex_str.chars().collect();

  let mut result = Vec::new();
  for c in chars.chunks(2) {
    let first_nybble = char_to_byte(c[0])?;
    let second_nybble_opt = if c.len() > 1 {
      Some(char_to_byte(c[1])?)
    } else {
      None
    };
    if let Some(second_nybble) = second_nybble_opt {
      result.push((first_nybble << 4) | second_nybble)
    } else {
      result.push(first_nybble)
    }
  }
  Ok(result)
}

pub fn to_hex_string(bytes: &[u8]) -> String {
  let mut result = String::new();
  for byte in bytes {
    result.push_str(&format!("{:X}", byte))
  }
  result
}

fn to_base64_char(byte: u8) -> Result<char> {
  if byte < 26 {
    Ok((byte + ('A' as u8)) as char)
  } else if byte < 52 {
    Ok(((byte - 26) + ('a' as u8)) as char)
  } else if byte < 62 {
    Ok(((byte - 52) + ('0' as u8)) as char)
  } else if byte == 62 {
    Ok('+')
  } else if byte == 63 {
    Ok('/')
  } else {
    Err(ErrorKind::InvalidBase64Index(byte).into())
  }
}

pub fn to_base64_string(bytes: &[u8]) -> Result<String> {
  println!("");
  let mut result = String::new();
  for chunk in bytes.chunks(3) {
    let first_index = chunk[0] >> 2;
    result.push(to_base64_char(first_index)?);

    if chunk.len() > 1 {
      let second_index = ((chunk[0] & 0x03) << 4) | (chunk[1] >> 4);
      result.push(to_base64_char(second_index)?);
    } else {
      result.push('=')
    }

    if chunk.len() > 2 {
      let third_index = ((chunk[1] & 0x0F) << 2) | (chunk[2] >> 6);
      let fourth_index = chunk[2] & 0x3F;
      result.push(to_base64_char(third_index)?);
      result.push(to_base64_char(fourth_index)?);
    } else {
      let third_index = (chunk[1] & 0x0F) << 2;
      result.push(to_base64_char(third_index)?);
      result.push('=')
    }
  }
  Ok(result)
}

pub fn fixed_xor(a_bytes: &[u8], b_bytes: &[u8]) -> Vec<u8> {
  let mut result = Vec::new();
  for (a, b) in a_bytes.iter().zip(b_bytes.iter()) {
    result.push(a ^ b);
  }
  result
}

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
    if (letter as char).is_ascii_alphabetic() {
      let letter_entry = self.letters.entry((letter as char).to_ascii_lowercase()).or_insert(0);
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

pub fn decrypt_single_byte_xor_cipher(xor_bytes: &[u8]) -> Vec<u8> {
  (0..255)
    .into_par_iter()
    .map(|byte| {
      let mask: Vec<_> = iter::repeat(byte as u8).take(xor_bytes.len()).collect();
      fixed_xor(xor_bytes, &mask)
    })
    .map(|xored| (english_error(&xored), xored))
    .min_by(|&(a_score, _), &(b_score, _)| a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal))
    .map(|(_, result)| result)
    .unwrap()
}

pub fn detect_single_character_xor(xor_bytes: Vec<Vec<u8>>) -> Vec<u8> {
  xor_bytes.par_iter()
    .map(|bytes| decrypt_single_byte_xor_cipher(&bytes))
    .map(|decrypted| (english_error(&decrypted), decrypted))
    .min_by(|&(a_score, _), &(b_score, _)| a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal))
    .map(|(_, result)| result)
    .unwrap()
}

fn encrypt_repeating_key(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
  let repeated_key: Vec<_> = key.iter().cycle().cloned().take(input_bytes.len()).collect();
  fixed_xor(input_bytes, &repeated_key)
}

fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
  a.iter()
    .zip(b)
    .map(|(&a_bits, &b_bits)| {
      let mut result = 0;
      let mut differing_bits = a_bits ^ b_bits;
      while differing_bits != 0 {
        if differing_bits & 0x01 == 1 {
          result += 1;
        }

        differing_bits >>= 1;
      }
      result
    })
    .sum()
}

#[cfg(test)]
mod tests {
  use super::*;

  // challenge 1
  #[test]
  fn test_to_base64_string() {
    let expected = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGE\
      gcG9pc29ub3VzIG11c2hyb29t");
    let hex_bytes = from_hex_string(
      "49276d206b696c6c696e6720796f757220627261696e206c\
       696b65206120706f69736f6e6f7573206d757368726f6f6d")
      .unwrap();
    match to_base64_string(&hex_bytes) {
      Ok(actual) => assert_eq!(expected, actual),
      Err(e) => assert!(false, e.to_string()),
    };
  }

  // challenge 2
  #[test]
  fn test_fixed_xor() {
    let expected = from_hex_string("746865206b696420646f6e277420706c6179").unwrap();

    let a_bytes = from_hex_string("1c0111001f010100061a024b53535009181c").unwrap();
    let b_bytes = from_hex_string("686974207468652062756c6c277320657965").unwrap();
    let actual = fixed_xor(&a_bytes, &b_bytes);
    assert_eq!(expected, actual);
  }

  // challenge 5
  #[test]
  fn test_encrypt_repeating_key() {
    let expected = from_hex_string(
      "0b3637272a2b2e63622c2e69692a23693a2a3c63\
       24202d623d63343c2a26226324272765272a282b\
       2f20430a652e2c652a3124333a653e2b2027630c\
       692b20283165286326302e27282f").unwrap();

    let input_string = "Burning 'em, if you ain't quick and nimble\n\
                        I go crazy when I hear a cymbal";
    let key = "ICE";
    let actual = encrypt_repeating_key(input_string.as_bytes(), key.as_bytes());
    assert_eq!(expected, actual);
  }

  // challenge 6
  #[test]
  fn test_hamming_distance() {
    let expected = 37;

    let a = "this is a test";
    let b = "wokka wokka!!!";
    let actual = hamming_distance(a.as_bytes(), b.as_bytes());
    assert_eq!(expected, actual);
  }
}
