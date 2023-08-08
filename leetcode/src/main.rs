#![allow(clippy::needless_return)]
#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]
#![allow(unused)]

#[macro_use]
extern crate rust_libs;

mod leetcode800;
use crate::leetcode800::*;

fn main() {
    println!("{}",push_dominoes("RR.L".to_string()));
}
