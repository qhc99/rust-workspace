#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]
mod mat_mul;
use crate::mat_mul::mat_mul_profile_demo;
fn main(){
    mat_mul_profile_demo();
}