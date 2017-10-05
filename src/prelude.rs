use std::cmp;
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
    let current_block = &data[start .. end];
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
