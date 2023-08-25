#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

mod mat_mul;

fn main() {
    let x = vec![Some(1), None, Some(3)];
    for n in x.into_iter().flatten() {
        println!("{}", n);
    }
}
