#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use mat_mul::mat_mul_profile_demo;
mod mat_mul;
use std::marker::PhantomData;

struct Bounded<'a, 'b: 'a, T: ?Sized>(&'a T, PhantomData<&'b ()>);

fn helper<'a, 'b, T: ?Sized>(
    input: &'a T,
    closure: impl FnOnce(&T) -> Bounded<'b, '_, T>,
) -> &'b T {
    closure(input).0
}

fn extend<'a, 'b, T: ?Sized>(input: &'a T) -> &'b T {
    helper(input, |x| Bounded(x, PhantomData))
}

fn use_after_free(){
    // mat_mul_profile_demo();
    let s = String::from("aaaa");
    let a: &'static str = extend(s.as_str()); // turn &'a str into 'static
    drop(s);
    println!("{}",a); // <------------ Use after free!
}

fn main() {
    use_after_free()
}
