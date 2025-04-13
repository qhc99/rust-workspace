#![cfg(target_os = "linux")]
use std::env;
fn main(){
    let args: Vec<String> = env::args().collect();
}