#![recursion_limit = "1024"]
#![feature(ascii_ctype)]
#![feature(iterator_step_by)]

#[macro_use]
extern crate error_chain;
extern crate byteorder;
extern crate itertools;
extern crate openssl;
#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate rayon;

pub mod errors;
pub mod prelude;
pub mod set1;
pub mod set2;
pub mod set3;
pub mod set4;
