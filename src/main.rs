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
  let in_bytes = from_hex_string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
  let (out_bytes, _) = set1::decrypt_single_byte_xor_cipher(&in_bytes);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("result: {}", out_str);

  Ok(())
}

fn challenge4() -> errors::Result<()> {
  let mut f = File::open("data/4.txt")?;
  let hex_bytes_list = read_hex_lines(&mut f)?;

  let (out_bytes, _) = set1::detect_single_character_xor(hex_bytes_list);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("result: {}", out_str);

  Ok(())
}

fn challenge5() -> errors::Result<()> {
  let expected = from_hex_string("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")?;

  let input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  let key = "ICE";
  let actual = encrypt_repeating_key(input_string.as_bytes(), key.as_bytes());

  println!("expected : {}", to_hex_string(&expected));
  println!("actual   : {}", to_hex_string(&actual));

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge6() -> errors::Result<()> {
  let mut f = File::open("data/6.txt")?;
  let bytes = read_base64_file(&mut f)?;
  let (out_bytes, out_key_bytes) = set1::break_repeating_key_xor(&bytes);
  let out_str = unsafe { str::from_utf8_unchecked(&out_bytes) };
  let out_key = unsafe { str::from_utf8_unchecked(&out_key_bytes) };

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

  println!("result: {}", out_str);

  Ok(())
}

fn challenge8() -> errors::Result<()> {
  let mut f = File::open("data/8.txt")?;
  let hex_bytes_list = read_hex_lines(&mut f)?;

  let out_bytes = set1::detect_aes_ecb_mode(hex_bytes_list);

  println!("challenge 8");
  println!("result: {:?}", to_hex_string(&out_bytes));

  Ok(())
}

fn challenge9() -> errors::Result<()> {
  let expected = "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}";

  let input = "YELLOW SUBMARINE";
  let out_bytes = pad_pkcs7(input.as_bytes(), 20);
  let actual = unsafe { str::from_utf8_unchecked(&out_bytes) };

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

static MAX_SET: usize = 2;

fn set_validator(arg: String) -> Result<(), String> {
  arg.parse::<usize>()
    .map_err(|e| e.to_string())
    .and_then(|set| if set <= MAX_SET {
      Ok(())
    } else {
      Err(format!("Set must be in [1..{}]", MAX_SET))
    })
}

static MAX_CHALLENGE: usize = 9;

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
    .arg(Arg::with_name("set")
      .short("s")
      .long("set")
      .help("Configures which set to run. If left out, it will run all sets.")
      .takes_value(true)
      .validator(set_validator))
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

  // use arguments to determine what to run
  // TODO use set :)
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
