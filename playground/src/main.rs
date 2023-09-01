#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]
use regex::Regex;
mod mat_mul;

fn main() {

    let re = Regex::new(r"\s+").unwrap();
    for i in re.split("a b  c"){
        println!("{}",i);
    }
}
