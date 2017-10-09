use std::cmp;
use std::convert::From;
use std::fs::File;
use std::io::{BufReader, Read};
use std::io::prelude::*;
use std::iter::Iterator;
use std::str;

use byteorder::{LittleEndian, WriteBytesExt};
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode, decrypt, encrypt};

use errors::*;

pub fn random_bytes(num: usize) -> Result<Vec<u8>> {
  let mut buffer = vec![0; num];
  rand_bytes(&mut buffer)?;
  Ok(buffer)
}

fn hex_byte_to_nybble(c: u8) -> Result<u8> {
  if c >= b'A' && c <= b'F' {
    Ok(c - b'A' + 10)
  } else if c >= b'a' && c <= b'f' {
    Ok(c - b'a' + 10)
  } else if c >= b'0' && c <= b'9' {
    Ok(c - b'0')
  } else {
    Err(ErrorKind::InvalidHexChar(c as char).into())
  }
}

pub fn from_hex_string(hex_str: &str) -> Result<Vec<u8>> {
  let mut result = Vec::new();
  for c in hex_str.as_bytes().chunks(2) {
    let first_nybble = hex_byte_to_nybble(c[0])?;
    let second_nybble_opt = if c.len() > 1 {
      Some(hex_byte_to_nybble(c[1])?)
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
    result.push_str(&format!("{:02x}", byte))
  }
  result
}

fn to_base64_char(byte: u8) -> Result<char> {
  if byte < 26 {
    Ok((byte + b'A') as char)
  } else if byte < 52 {
    Ok((byte - 26 + b'a') as char)
  } else if byte < 62 {
    Ok((byte - 52 + b'0') as char)
  } else if byte == 62 {
    Ok('+')
  } else if byte == 63 {
    Ok('/')
  } else {
    Err(ErrorKind::InvalidBase64Index(byte).into())
  }
}

pub fn to_base64_string(bytes: &[u8]) -> Result<String> {
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

fn from_base64_byte(c: u8) -> Result<u8> {
  if c == b'=' {
    Ok(0)
  } else if c == b'+' {
    Ok(62)
  } else if c == b'/' {
    Ok(63)
  } else if c >= b'A' && c <= b'Z' {
    Ok(c - b'A')
  } else if c >= b'a' && c <= b'z' {
    Ok(c - b'a' + 26)
  } else if c >= b'0' && c <= b'9' {
    Ok(c - b'0' + 52)
  } else {
    Err(ErrorKind::InvalidBase64Char(c as char).into())
  }
}

pub fn from_base64_string(base64_str: &str) -> Result<Vec<u8>> {

  let mut result = Vec::new();

  for chunk in base64_str.as_bytes().chunks(4) {
    let first_index = from_base64_byte(chunk[0])?;
    let second_index = from_base64_byte(chunk[1])?;
    let third_index = from_base64_byte(chunk[2])?;
    let fourth_index = from_base64_byte(chunk[3])?;

    result.push((first_index << 2) | (second_index >> 4));
    if chunk[2] != b'=' {
      result.push(((second_index & 0x0F) << 4) | (third_index >> 2));
    }
    if chunk[3] != b'=' {
      result.push(((third_index & 0x03) << 6) | fourth_index);
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

pub fn encrypt_repeating_key(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
  let repeated_key: Vec<_> = key.iter().cycle().cloned().take(input_bytes.len()).collect();
  fixed_xor(input_bytes, &repeated_key)
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
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

pub fn read_hex_lines(file: &mut File) -> Result<Vec<Vec<u8>>> {
  let f = BufReader::new(file);

  let mut hex_bytes_list = Vec::new();
  for line in f.lines() {
    let string = line?;
    let hex_bytes = from_hex_string(&string)?;
    hex_bytes_list.push(hex_bytes);
  }

  Ok(hex_bytes_list)
}

pub fn read_base64_file(file: &mut File) -> Result<Vec<u8>> {
  let mut contents = String::new();
  file.read_to_string(&mut contents)?;
  from_base64_string(&contents.replace("\n", ""))
}


pub fn read_base64_lines(file: &mut File) -> Result<Vec<Vec<u8>>> {
  let f = BufReader::new(file);

  let mut base64_bytes_list = Vec::new();
  for line in f.lines() {
    let string = line?;
    let base64_bytes = from_base64_string(&string)?;
    base64_bytes_list.push(base64_bytes);
  }

  Ok(base64_bytes_list)
}

pub fn aes_128_ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  encrypt(Cipher::aes_128_ecb(), key, None, data).map_err(|e| e.into())
}

pub fn aes_128_ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  decrypt(Cipher::aes_128_ecb(), key, None, data).map_err(|e| e.into())
}

pub fn aes_128_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  encrypt(Cipher::aes_128_cbc(), key, Some(iv), data).map_err(|e| e.into())
}

pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  decrypt(Cipher::aes_128_cbc(), key, Some(iv), data).map_err(|e| e.into())
}

pub fn aes_128_cbc_encrypt_no_padding(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  cipher_no_padding(Cipher::aes_128_cbc(), Mode::Encrypt, key, Some(iv), data).map_err(|e| e.into())
}

pub fn aes_128_cbc_decrypt_no_padding(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  cipher_no_padding(Cipher::aes_128_cbc(), Mode::Decrypt, key, Some(iv), data).map_err(|e| e.into())
}

fn cipher_no_padding(t: Cipher,
                     mode: Mode,
                     key: &[u8],
                     iv: Option<&[u8]>,
                     data: &[u8])
                     -> Result<Vec<u8>> {
  let mut c = Crypter::new(t, mode, key, iv)?;
  c.pad(false);
  let mut out = vec![0; data.len() + t.block_size()];
  let count = c.update(data, &mut out)?;
  let rest = c.finalize(&mut out[count..])?;
  out.truncate(count + rest);
  Ok(out)
}

pub fn aes_128_ctr(key: &[u8], nonce: u64, data: &[u8]) -> Result<Vec<u8>> {
  let mut result = Vec::new();
  for n in 0..data.len() / 16 + 1 {
    // generate the keystream
    let mut keystream = Vec::new();
    keystream.write_u64::<LittleEndian>(nonce)?;
    keystream.write_u64::<LittleEndian>(n as u64)?;
    let keystream_ciphertext = aes_128_ecb_encrypt(key, &keystream)?;

    let start = n * 16;
    let end = cmp::min((n + 1) * 16, data.len());
    let current_block = &data[start..end];
    result.extend(fixed_xor(current_block, &keystream_ciphertext));
  }
  Ok(result)
}

pub fn pad_pkcs7(data: &[u8], block_len: u8) -> Vec<u8> {
  if data.len() % block_len as usize == 0 {
    let mut result = data.to_vec();
    result.extend(vec![16; 16]);
    result
  } else {
    let padding = block_len - (data.len() as u8) % block_len;
    let mut result = data.to_vec();
    result.extend(vec![padding; padding as usize]);
    result
  }
}

pub fn is_pkcs7_padded(data: &[u8]) -> bool {
  let padding = data[data.len() - 1];
  padding > 0 && padding as usize <= data.len() &&
  data[(data.len() - padding as usize)..].to_vec() == vec![padding; padding as usize]
}

pub fn unpad_pkcs7(data: &[u8]) -> Result<Vec<u8>> {
  let padding = data[data.len() - 1];
  if is_pkcs7_padded(data) {
    let mut result = Vec::new();
    result.extend_from_slice(&data[..(data.len() - padding as usize)]);
    Ok(result)
  } else {
    Err(ErrorKind::InvalidPkcs7Padding(data.to_vec()).into())
  }
}

pub fn intersperse(data: &[&[u8]], between: &[u8]) -> Vec<u8> {
  let mut result = Vec::new();
  for (i, chunk) in data.iter().enumerate() {
    result.extend_from_slice(chunk);
    if i + 1 < data.len() {
      result.extend_from_slice(between);
    }
  }
  result
}

pub fn fmt_binary(data: &[u8]) -> Vec<String> {
  let mut result = Vec::new();
  for &b in data {
    result.push(format!("{:08b}", b));
  }
  result
}

// w: word size (in number of bits)
// n: degree of recurrence
// m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
// r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
//
// (w,n,m,r) = 32, 624, 397, 31
//
// a: coefficients of the rational normal form twist matrix
// b, c: TGFSR(R) tempering bitmasks
// s, t: TGFSR(R) tempering bit shifts
// u, d, l: additional Mersenne Twister tempering bit shifts/masks
//
//

#[derive(Clone)]
struct MersenneTwisterParams {
  // W left out
  w: usize,
  n: usize,
  m: usize,
  a: u32,
  f: u32,
  u: u32,
  d: u32,
  s: u32,
  b: u32,
  t: u32,
  c: u32,
  l: u32,
  lower_mask: u32,
  upper_mask: u32,
}

impl MersenneTwisterParams {
  fn mt19937() -> MersenneTwisterParams {
    MersenneTwisterParams {
      w: 32,
      n: 624,
      m: 397,
      a: 0x9908B0DF,
      f: 1812433253,
      u: 11,
      d: 0xFFFFFFFF,
      s: 7,
      b: 0x9D2C5680,
      t: 15,
      c: 0xEFC60000,
      l: 18,
      lower_mask: 0x7fffffff,
      upper_mask: 0x80000000,
    }
  }
}

#[derive(Clone)]
pub struct MersenneTwister {
  params: MersenneTwisterParams,
  mt: Vec<u32>,
  index: usize,
}

impl MersenneTwister {
  pub fn new(seed: u32) -> MersenneTwister {
    MersenneTwister::initialize(seed, MersenneTwisterParams::mt19937())
  }

  // wrapping_mul needs to be replaced
  fn initialize(seed: u32, params: MersenneTwisterParams) -> MersenneTwister {
    let mut mt = vec![0; params.n];
    mt[0] = seed;
    for i in 1..params.n {
      let s = mt[i - 1] ^ (mt[i - 1] >> (params.w - 2));
      mt[i] = params.f.wrapping_mul(s).wrapping_add(i as u32);
    }
    let index = params.n;

    MersenneTwister {
      params: params,
      mt: mt,
      index: index,
    }
  }

  fn twist(&mut self) {
    for i in 0..self.params.n {
      let x = (self.mt[i] & self.params.upper_mask) +
              (self.mt[(i + 1) % self.params.n] & self.params.lower_mask);
      let mut x_a = x >> 1;
      if x % 2 != 0 {
        x_a ^= self.params.a;
      }
      self.mt[i] = self.mt[(i + self.params.m) % self.params.n] ^ x_a;
    }
    self.index = 0;
  }

  pub fn gen(&mut self) -> u32 {
    if self.index >= self.params.n {
      self.twist();
    }

    let mut y = self.mt[self.index];
    y ^= (y >> self.params.u) & self.params.d;
    y ^= (y << self.params.s) & self.params.b;
    y ^= (y << self.params.t) & self.params.c;
    y ^= y >> self.params.l;

    self.index += 1;

    y
  }

  pub fn tap(mut self) -> Vec<u32> {
    let mut result = Vec::new();
    for _ in 0..self.params.n {
      result.push(self.gen());
    }
    result
  }

  pub fn keystream(self) -> MersenneTwisterKeystream {
    MersenneTwisterKeystream::new(self)
  }
}

impl From<Vec<u32>> for MersenneTwister {
  fn from(mt: Vec<u32>) -> MersenneTwister {
    assert_eq!(mt.len(), 624);

    MersenneTwister {
      params: MersenneTwisterParams::mt19937(),
      mt: mt,
      index: 0,
    }
  }
}

enum KeystreamState {
  One,
  Two,
  Three,
  Four,
}

impl KeystreamState {
  fn next(&self) -> KeystreamState {
    use self::KeystreamState::*;

    match self {
      &One => Two,
      &Two => Three,
      &Three => Four,
      &Four => One,
    }
  }
}

pub struct MersenneTwisterKeystream {
  mt: MersenneTwister,
  output: u32,
  state: KeystreamState,
}

impl MersenneTwisterKeystream {
  fn new(mut mt: MersenneTwister) -> MersenneTwisterKeystream {
    let output = mt.gen();
    MersenneTwisterKeystream {
      mt: mt,
      output: output,
      state: KeystreamState::One,
    }
  }
}

impl Iterator for MersenneTwisterKeystream {
  type Item = u8;

  fn next(&mut self) -> Option<Self::Item> {
    use self::KeystreamState::*;

    let result = match self.state {
      One => (self.output & 0xFF000000) >> 24,
      Two => (self.output & 0x00FF0000) >> 16,
      Three => (self.output & 0x0000FF00) >> 8,
      Four => {
        let result = self.output & 0x000000FF;
        self.output = self.mt.gen();
        result
      }
    } as u8;
    self.state = self.state.next();
    Some(result)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_hamming_distance() {
    let expected = 37;

    let a = "this is a test";
    let b = "wokka wokka!!!";
    let actual = hamming_distance(a.as_bytes(), b.as_bytes());
    assert_eq!(expected, actual);
  }

  #[test]
  fn test_pad_pkcs7() {
    let expected = "YELLOW SUBMARIN\u{1}";

    let input = b"YELLOW SUBMARIN";
    let actual = pad_pkcs7(input, 16);
    assert_eq!(expected.as_bytes().to_vec(), actual);
  }

  #[test]
  fn test_pad_pkcs7_at_boundary() {
    let expected = "YELLOW SUBMARINE\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}";

    let input = b"YELLOW SUBMARINE";
    let actual = pad_pkcs7(input, 16);
    assert_eq!(expected.as_bytes().to_vec(), actual);
  }

  #[test]
  fn test_unpad_pkcs7_unpads() {
    let expected = "YELLOW SUBMARINE";

    let padded = "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}";
    let out_bytes = unpad_pkcs7(padded.as_bytes()).unwrap();
    let actual = unsafe { str::from_utf8_unchecked(&out_bytes) };
    assert_eq!(expected, actual);
  }

  #[test]
  fn test_unpad_pkcs7_complains_when_wrong() {
    let padded = "YELLOW SUBMARINE\u{1}\u{2}\u{3}\u{4}";
    assert!(unpad_pkcs7(padded.as_bytes()).is_err());
  }

  #[test]
  fn test_unpad_pkcs7_complains_when_byte_huge() {
    let padded = "YELLOW SUBMARINE\u{1}\u{2}\u{3}\u{89}";
    assert!(unpad_pkcs7(padded.as_bytes()).is_err());
  }

  #[test]
  fn test_zero_is_not_pkcs7_padded() {
    let padded = "YELLOW SUBMARIN\u{0}";
    assert!(!is_pkcs7_padded(padded.as_bytes()));
  }
}
