#[macro_use]
extern crate error_chain;

extern crate cryptopals;

use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;
use std::str;

use cryptopals::*;
use cryptopals::errors;

fn challenge3() -> errors::Result<()> {
  let in_bytes =
    from_hex_string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      .unwrap();
  let out_bytes = decrypt_single_byte_xor_cipher(&in_bytes);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("challenge 3");
  println!("result: {:?}", out_str);

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
  let out_bytes = detect_single_character_xor(hex_bytes_list);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("challenge 4");
  println!("result: {:?}", out_str);

  Ok(())
}

fn run() -> errors::Result<()> {
  challenge3()?;
  println!("");
  challenge4()?;
  Ok(())
}
quick_main!(run);
