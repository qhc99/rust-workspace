#![allow(clippy::needless_return)]
#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]
#![allow(unused)]

#[macro_use]
extern crate rust_libs;

mod leetcode800;
use crate::leetcode800::*;

mod inner {
    pub trait A {
        fn f(&self) -> usize {
            0
        }
    }
    pub trait B {
        fn f(&self) -> usize {
            1
        }
    }
    pub struct P;
    impl A for P {}
    impl B for P {}
}
fn main() {
    use inner::{B, P};
    println!("{}", P.f());
}
