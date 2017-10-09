#[macro_use]
extern crate error_chain;
extern crate clap;
extern crate rand;

extern crate cryptopals;

use std::collections::BTreeMap;
use std::fs::File;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{App, Arg};
use rand::distributions::{IndependentSample, Range};

use cryptopals::prelude::*;
use cryptopals::errors;
use cryptopals::set1;
use cryptopals::set2;
use cryptopals::set3;

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
  let plaintext = str::from_utf8(&plaintext_bytes)?;

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge4() -> errors::Result<()> {
  let mut f = File::open("data/4.txt")?;
  let ciphertext_bytes_list = read_hex_lines(&mut f)?;

  let (plaintext_bytes, _) = set1::detect_single_character_xor(&ciphertext_bytes_list);
  let plaintext = str::from_utf8(&plaintext_bytes)?;

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
  let (plaintext_bytes, key_bytes) = set1::break_repeating_key_xor(&ciphertext, 5..40);
  let plaintext = str::from_utf8(&plaintext_bytes)?;
  let key = str::from_utf8(&key_bytes)?;

  println!("result: {}", plaintext);
  println!("key: '{}'", key);

  Ok(())
}

fn challenge7() -> errors::Result<()> {
  let key = b"YELLOW SUBMARINE";
  let mut f = File::open("data/7.txt")?;
  let ciphertext = read_base64_file(&mut f)?;

  let plaintext_bytes = aes_128_ecb_decrypt(key, &ciphertext)?;
  let plaintext = str::from_utf8(&plaintext_bytes)?;

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
  let actual = str::from_utf8(&padded_bytes)?;

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
  let plaintext = str::from_utf8(&plaintext_bytes)?;

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
  let plaintext = str::from_utf8(&plaintext_bytes)?;

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge13() -> errors::Result<()> {

  let expected = "admin";

  let profile = set2::create_admin_profile()?;
  let object = set2::decrypt_profile(&profile)?;
  let actual_bytes = &object[&b"role".to_vec()];
  let actual = str::from_utf8(actual_bytes)?;

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge14() -> errors::Result<()> {

  let plaintext_bytes = set2::decrypt_ecb_hard(set2::encryption_ecb_oracle_hard)?;
  let plaintext = str::from_utf8(&plaintext_bytes)?;

  println!("result: {}", plaintext);

  Ok(())
}

fn challenge15() -> errors::Result<()> {

  let ice_ice_baby_four = "ICE ICE BABY\u{4}\u{4}\u{4}\u{4}";
  let is_ice_ice_baby_four_padded = unpad_pkcs7(ice_ice_baby_four.as_bytes()).is_ok();
  println!("{:?} is pkcs7 padded: {}",
           ice_ice_baby_four,
           is_ice_ice_baby_four_padded);
  assert!(is_ice_ice_baby_four_padded);

  let ice_ice_baby_five = "ICE ICE BABY\u{5}\u{5}\u{5}\u{5}";
  let is_ice_ice_baby_five_padded = unpad_pkcs7(ice_ice_baby_five.as_bytes()).is_ok();
  println!("{:?} is pkcs7 padded: {}",
           ice_ice_baby_five,
           is_ice_ice_baby_five_padded);
  assert!(!is_ice_ice_baby_five_padded);

  let ice_ice_baby_1234 = "ICE ICE BABY\u{1}\u{2}\u{3}\u{4}";
  let is_ice_ice_baby_1234_padded = unpad_pkcs7(ice_ice_baby_1234.as_bytes()).is_ok();
  println!("{:?} is pkcs7 padded: {}",
           ice_ice_baby_1234,
           is_ice_ice_baby_1234_padded);
  assert!(!is_ice_ice_baby_1234_padded);

  Ok(())
}

fn challenge16() -> errors::Result<()> {
  let encrypted_userdata = set2::encrypt_userdata(b";admin=true;")?;
  let inserted_admin = set2::insert_admin_into_userdata(&encrypted_userdata);
  let has_inserted_admin = set2::inserted_admin_into_userdata(&inserted_admin)?;

  println!("result: {:?}", has_inserted_admin);
  assert!(has_inserted_admin);

  Ok(())
}

fn challenge17() -> errors::Result<()> {
  let (ciphertext, iv) = set3::random_ciphertext()?;

  let plaintext_bytes = set3::decrypt_ciphertext(&ciphertext, &iv)?;
  let plaintext = str::from_utf8(&plaintext_bytes);

  println!("result: {:?}", plaintext);

  Ok(())
}

fn challenge18() -> errors::Result<()> {
  let key = b"YELLOW SUBMARINE";
  let nonce = 0;
  let ciphertext = from_base64_string("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")?;
  let plaintext_bytes = aes_128_ctr(key, nonce, &ciphertext)?;
  let plaintext = str::from_utf8(&plaintext_bytes);

  println!("{:?}", plaintext);

  Ok(())
}

fn challenge19() -> errors::Result<()> {
  let base64_strings = set3::get_base64_strings()?;
  let ciphertexts = set3::encrypt_plaintexts_with_same_nonce(&base64_strings)?;
  let plaintexts = set3::break_ctr_with_same_nonce(&ciphertexts)?;

  for plaintext_bytes in &plaintexts {
    println!("{:?}", str::from_utf8(plaintext_bytes)?);
  }

  Ok(())
}

fn challenge20() -> errors::Result<()> {
  let mut f = File::open("data/20.txt")?;
  let base64_lines = read_base64_lines(&mut f)?;
  let ciphertexts = set3::encrypt_plaintexts_with_same_nonce(&base64_lines)?;
  let plaintexts = set3::break_ctr_with_same_nonce_as_repeating_key_xor(&ciphertexts)?;

  for plaintext_bytes in &plaintexts {
    println!("{:?}", str::from_utf8(plaintext_bytes)?);
  }


  Ok(())
}

fn challenge21() -> errors::Result<()> {
  let mut rng = MersenneTwister::new(0);

  for _ in 0..10 {
    println!("random number: {}", rng.gen());
  }

  Ok(())
}

fn challenge22() -> errors::Result<()> {
  let unix_duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
  let unix_timestamp = unix_duration.as_secs() as u32;

  let mut thread_rng = rand::thread_rng();
  let range = Range::new(40, 1000);
  let delay1 = range.ind_sample(&mut thread_rng);
  let delay2 = range.ind_sample(&mut thread_rng);

  let seed = unix_timestamp + delay1;
  let output = set3::mersenne_rng(seed);

  let expected = seed;
  let actual = set3::crack_mt19937_seed(output, seed + delay2);

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge23() -> errors::Result<()> {
  let rng = MersenneTwister::new(0);
  let expected = rng.tap();

  let state = set3::crack_mt19937_state(&expected);
  let rng = MersenneTwister::from(state);
  let actual = rng.tap();

  println!("expected : {:?}", expected);
  println!("actual   : {:?}", actual);

  assert_eq!(expected, actual);

  Ok(())
}

fn challenge24() -> errors::Result<()> {
  let (expected_seed, ciphertext) = set3::get_mt19937_ciphertext()?;
  let (actual_seed, _plaintext) = set3::break_mt19937_ciphertext(&ciphertext);

  println!("expected : {:?}", expected_seed);
  println!("actual   : {:?}", actual_seed);

  assert_eq!(expected_seed, actual_seed);

  Ok(())
}

static MAX_CHALLENGE: usize = 24;

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
  challenges_map.insert(16, challenge16);
  challenges_map.insert(17, challenge17);
  challenges_map.insert(18, challenge18);
  challenges_map.insert(19, challenge19);
  challenges_map.insert(20, challenge20);
  challenges_map.insert(21, challenge21);
  challenges_map.insert(22, challenge22);
  challenges_map.insert(23, challenge23);
  challenges_map.insert(24, challenge24);

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
