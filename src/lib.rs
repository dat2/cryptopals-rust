#![recursion_limit = "1024"]
#![feature(ascii_ctype)]
#![feature(iterator_step_by)]

#[macro_use]
extern crate error_chain;
extern crate itertools;
extern crate openssl;
extern crate rayon;

pub mod errors;
pub mod set1;
pub mod prelude;
