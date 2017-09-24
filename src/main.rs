extern crate cryptopals;

use std::str;

use cryptopals::*;

fn challenge3() {
  let in_bytes =
    from_hex_string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
      .unwrap();
  let out_bytes = decrypt_single_byte_xor_cipher(&in_bytes);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("challenge 3");
  println!("result: {:?}", out_str);
}

fn main() {
  challenge3();
}
