#[macro_use]
extern crate error_chain;
extern crate clap;

extern crate cryptopals;

use std::collections::BTreeMap;
use std::fs::File;
use std::str;

use clap::{App, Arg};

use cryptopals::prelude::*;
use cryptopals::errors;
use cryptopals::set1;
use cryptopals::set2;

fn challenge1() -> errors::Result<()> {

  let expected = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
  let hex_bytes = from_hex_string("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?;
  let actual = to_base64_string(&hex_bytes)?;

  println!("expected : {}", expected);
  println!("actual   : {}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge2() -> errors::Result<()> {
  let expected = from_hex_string("746865206b696420646f6e277420706c6179")?;

  let a_bytes = from_hex_string("1c0111001f010100061a024b53535009181c")?;
  let b_bytes = from_hex_string("686974207468652062756c6c277320657965")?;
  let actual = fixed_xor(&a_bytes, &b_bytes);

  println!("expected : {}", to_hex_string(&expected));
  println!("actual   : {}", to_hex_string(&actual));

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge3() -> errors::Result<()> {
  let ciphertext_bytes = from_hex_string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
  let (plaintext_bytes, _) = set1::decrypt_single_byte_xor_cipher(&ciphertext_bytes);
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge4() -> errors::Result<()> {
  let mut f = File::open("data/4.txt")?;
  let ciphertext_bytes_list = read_hex_lines(&mut f)?;

  let (plaintext_bytes, _) = set1::detect_single_character_xor(&ciphertext_bytes_list);
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge5() -> errors::Result<()> {
  let expected = from_hex_string("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")?;

  let input_string = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  let key = b"ICE";
  let actual = encrypt_repeating_key(input_string, key);

  println!("expected : {}", to_hex_string(&expected));
  println!("actual   : {}", to_hex_string(&actual));

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge6() -> errors::Result<()> {
  let mut f = File::open("data/6.txt")?;
  let ciphertext = read_base64_file(&mut f)?;
  let (plaintext_bytes, key_bytes) = set1::break_repeating_key_xor(&ciphertext);
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };
  let key = unsafe { str::from_utf8_unchecked(&key_bytes) };

  println!("result: {}", plaintext);
  println!("key: '{}'", key);

  Ok(())
}

fn challenge7() -> errors::Result<()> {
  let key = b"YELLOW SUBMARINE";
  let mut f = File::open("data/7.txt")?;
  let ciphertext = read_base64_file(&mut f)?;

  let plaintext_bytes = aes_128_ecb_decrypt(key, &ciphertext)?;
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge8() -> errors::Result<()> {
  let mut f = File::open("data/8.txt")?;
  let ciphertext_bytes_list = read_hex_lines(&mut f)?;

  let ciphertext_bytes = set1::detect_aes_ecb_mode(&ciphertext_bytes_list);

  println!("challenge 8");
  println!("result: {:?}", to_hex_string(&ciphertext_bytes));

  Ok(())
}

fn challenge9() -> errors::Result<()> {
  let expected = "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}";

  let to_pad = b"YELLOW SUBMARINE";
  let padded_bytes = pad_pkcs7(to_pad, 20);
  let actual = unsafe { str::from_utf8_unchecked(&padded_bytes) };

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge10() -> errors::Result<()> {
  let key = b"YELLOW SUBMARINE";
  let iv: Vec<_> = vec![0; 16];
  let mut f = File::open("data/10.txt")?;
  let ciphertext = read_base64_file(&mut f)?;

  let plaintext_bytes = set2::aes_128_cbc_decrypt_manual(key, &iv, &ciphertext)?;
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge11() -> errors::Result<()> {
  let plaintext_key = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";
  let (ciphertext_bytes, expected) = set2::encryption_oracle(plaintext_key)?;
  let actual = set2::detect_cipher_mode(&ciphertext_bytes);

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge12() -> errors::Result<()> {

  let plaintext_bytes = set2::decrypt_ecb(set2::encryption_ecb_oracle)?;
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge13() -> errors::Result<()> {

  let expected = "admin";

  let profile = set2::create_admin_profile()?;
  let object = set2::decrypt_profile(&profile)?;
  let actual_bytes = &object[&b"role".to_vec()];
  let actual = unsafe { str::from_utf8_unchecked(actual_bytes) };

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge14() -> errors::Result<()> {

  let plaintext_bytes = set2::decrypt_ecb_hard(set2::encryption_ecb_oracle_hard)?;
  let plaintext = unsafe { str::from_utf8_unchecked(&plaintext_bytes) };

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge15() -> errors::Result<()> {

  let ice_ice_baby_four = "ICE ICE BABY\u{4}\u{4}\u{4}\u{4}";
  let is_ice_ice_baby_four_padded = unpad_pkcs7(ice_ice_baby_four.as_bytes()).is_ok();
  println!("{:?} is pkcs7 padded: {}", ice_ice_baby_four, is_ice_ice_baby_four_padded);
  assert!(is_ice_ice_baby_four_padded);

  let ice_ice_baby_five = "ICE ICE BABY\u{5}\u{5}\u{5}\u{5}";
  let is_ice_ice_baby_five_padded = unpad_pkcs7(ice_ice_baby_five.as_bytes()).is_ok();
  println!("{:?} is pkcs7 padded: {}", ice_ice_baby_five, is_ice_ice_baby_five_padded);
  assert!(!is_ice_ice_baby_five_padded);

  let ice_ice_baby_1234 = "ICE ICE BABY\u{1}\u{2}\u{3}\u{4}";
  let is_ice_ice_baby_1234_padded = unpad_pkcs7(ice_ice_baby_1234.as_bytes()).is_ok();
  println!("{:?} is pkcs7 padded: {}", ice_ice_baby_1234, is_ice_ice_baby_1234_padded);
  assert!(!is_ice_ice_baby_1234_padded);

  Ok(())
}

static MAX_CHALLENGE: usize = 15;

fn challenge_validator(arg: String) -> Result<(), String> {
  arg.parse::<usize>()
    .map_err(|e| e.to_string())
    .and_then(|challenge| if challenge <= MAX_CHALLENGE {
      Ok(())
    } else {
      Err(format!("Challenge must be in [1..{}]", MAX_CHALLENGE))
    })
}

fn run() -> errors::Result<()> {
  // arguments
  let matches = App::new("cryptopals")
    .version("1.0")
    .author("Nicholas Dujay <nickdujay@gmail.com>")
    .about("Runs Matasano's cryptopals challenges")
    .arg(Arg::with_name("challenge")
      .short("c")
      .long("challenge")
      .help("Configures which challenge to run.")
      .takes_value(true)
      .validator(challenge_validator))
    .get_matches();

  // configure challenges hashmap
  let mut challenges_map: BTreeMap<usize, fn() -> errors::Result<()>> = BTreeMap::new();
  challenges_map.insert(1, challenge1);
  challenges_map.insert(2, challenge2);
  challenges_map.insert(3, challenge3);
  challenges_map.insert(4, challenge4);
  challenges_map.insert(5, challenge5);
  challenges_map.insert(6, challenge6);
  challenges_map.insert(7, challenge7);
  challenges_map.insert(8, challenge8);
  challenges_map.insert(9, challenge9);
  challenges_map.insert(10, challenge10);
  challenges_map.insert(11, challenge11);
  challenges_map.insert(12, challenge12);
  challenges_map.insert(13, challenge13);
  challenges_map.insert(14, challenge14);
  challenges_map.insert(15, challenge15);

  // use arguments to determine what to run
  if let Some(challenge_string) = matches.value_of("challenge") {
    let challenge: usize = challenge_string.parse()?;
    let challenge_func = challenges_map[&challenge];
    println!("challenge {}", challenge);
    challenge_func()?;
    println!();
  } else {
    for (challenge_number, challenge_func) in &challenges_map {
      println!("challenge {}", challenge_number);
      challenge_func()?;
      println!();
    }
  }

  Ok(())
}

quick_main!(run);
