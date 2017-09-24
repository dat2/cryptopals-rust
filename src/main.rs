#[macro_use]
extern crate error_chain;

extern crate cryptopals;

use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;
use std::str;

use cryptopals::prelude::*;
use cryptopals::errors;
use cryptopals::set1;

fn challenge3() -> errors::Result<()> {
  let in_bytes =
    from_hex_string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      .unwrap();
  let (out_bytes, _) = set1::decrypt_single_byte_xor_cipher(&in_bytes);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("challenge 3");
  println!("result: {}", out_str);

  Ok(())
}

fn challenge4() -> errors::Result<()> {
  let f = File::open("data/4.txt")?;
  let f = BufReader::new(f);

  let mut hex_bytes_list = Vec::new();
  for line in f.lines() {
    let string = line?;
    hex_bytes_list.push(from_hex_string(&string)?);
  }
  let (out_bytes, _) = set1::detect_single_character_xor(hex_bytes_list);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("challenge 4");
  println!("result: {}", out_str);

  Ok(())
}

fn challenge6() -> errors::Result<()> {
  let mut f = File::open("data/6.txt")?;
  let bytes = read_base64_file(&mut f)?;
  let (out_bytes, out_key_bytes) = set1::break_repeating_key_xor(&bytes);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };
  let out_key = unsafe { str::from_utf8_unchecked(&out_key_bytes) };

  println!("challenge 6");
  println!("result: {}", out_str);
  println!("key: '{}'", out_key);

  Ok(())
}

fn challenge7() -> errors::Result<()> {
  let key = "YELLOW SUBMARINE";
  let mut f = File::open("data/7.txt")?;
  let data = read_base64_file(&mut f)?;

  let out_bytes = aes_128_ecb_decrypt(key.as_bytes(), &data)?;
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("challenge 7");
  println!("result: {}", out_str);

  Ok(())
}

fn run() -> errors::Result<()> {
  // challenge3()?;
  // println!();
  // challenge4()?;
  // println!();
  // challenge6()?;
  // println!();
  challenge7()?;
  println!();
  Ok(())
}
quick_main!(run);
