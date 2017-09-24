#![recursion_limit = "1024"]
#![feature(ascii_ctype)]

#[macro_use]
extern crate error_chain;

use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::cmp::Ordering;
use std::iter;

mod errors;
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
    let first_nybble = try!(char_to_byte(c[0]));
    let second_nybble_opt = if c.len() > 1 {
      Some(try!(char_to_byte(c[1])))
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
    result.push(try!(to_base64_char(first_index)));

    if chunk.len() > 1 {
      let second_index = ((chunk[0] & 0x03) << 4) | (chunk[1] >> 4);
      result.push(try!(to_base64_char(second_index)));
    } else {
      result.push('=')
    }

    if chunk.len() > 2 {
      let third_index = ((chunk[1] & 0x0F) << 2) | (chunk[2] >> 6);
      let fourth_index = chunk[2] & 0x3F;
      result.push(try!(to_base64_char(third_index)));
      result.push(try!(to_base64_char(fourth_index)));
    } else {
      let third_index = (chunk[1] & 0x0F) << 2;
      result.push(try!(to_base64_char(third_index)));
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

struct LetterCounter {
  letters: HashMap<char, usize>,
  penalty: usize
}

impl LetterCounter {
  fn new() -> LetterCounter {
    LetterCounter {
      letters: HashMap::new(),
      penalty: 0
    }
  }

  fn count(&mut self, letter: u8) {
    if (letter as char).is_ascii_alphabetic() {
      let letter_entry = self.letters.entry((letter as char).to_ascii_lowercase()).or_insert(0);
      *letter_entry += 1;
    } else {
      self.penalty += 1;
    }
  }

  fn total_count(&self) -> usize {
    let mut result = 0;
    for (_, count) in &self.letters {
      result += *count;
    }
    result
  }

  fn score(&self) -> f32 {
    let mut english_frequency = HashMap::new();
    english_frequency.insert('a', 8.167);
    english_frequency.insert('b', 1.492);
    english_frequency.insert('c', 2.782);
    english_frequency.insert('d', 4.253);
    english_frequency.insert('e', 12.702);
    english_frequency.insert('f', 2.228);
    english_frequency.insert('g', 2.015);
    english_frequency.insert('h', 6.094);
    english_frequency.insert('i', 6.966);
    english_frequency.insert('j', 0.153);
    english_frequency.insert('k', 0.772);
    english_frequency.insert('l', 4.025);
    english_frequency.insert('m', 2.406);
    english_frequency.insert('n', 6.749);
    english_frequency.insert('o', 7.507);
    english_frequency.insert('p', 1.929);
    english_frequency.insert('q', 0.095);
    english_frequency.insert('r', 5.987);
    english_frequency.insert('s', 6.327);
    english_frequency.insert('t', 9.056);
    english_frequency.insert('u', 2.758);
    english_frequency.insert('v', 0.978);
    english_frequency.insert('w', 2.360);
    english_frequency.insert('x', 0.150);
    english_frequency.insert('y', 1.974);
    english_frequency.insert('z', 0.074);

    let total_count = self.total_count() as f32;

    let mut result = 0.0;
    for (letter, frequency) in &english_frequency {
      let self_frequency = self.letters.get(letter).cloned().unwrap_or(0) as f32 / total_count;
      result += (self_frequency - *frequency).abs();
    }
    result += self.penalty as f32;
    result
  }
}

fn score_bytes(xor_bytes: &[u8]) -> f32 {
  let mut counter = LetterCounter::new();
  for byte in xor_bytes {
    counter.count(*byte);
  }
  counter.score()
}

pub fn decrypt_single_byte_xor_cipher(xor_bytes: &[u8]) -> Vec<u8> {
  (0..255)
    .map(|byte| {
      let mask: Vec<_> = iter::repeat(byte).take(xor_bytes.len()).collect();
      let xored = fixed_xor(xor_bytes, &mask);
      (score_bytes(&xored), xored)
    })
    .min_by(|&(a_score, _), &(b_score,_)| a_score.partial_cmp(&b_score).unwrap_or(Ordering::Equal))
    .map(|(_, result)| result)
    .unwrap()
}

#[cfg(test)]
mod tests {
  use super::*;

  // challenge 1
  #[test]
  fn test_to_base64_string() {
    let expected = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    let hex_bytes = from_hex_string("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    match to_base64_string(&hex_bytes) {
      Ok(actual) => assert_eq!(actual, expected),
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
    assert_eq!(actual, expected);
  }
}
