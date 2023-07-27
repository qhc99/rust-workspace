#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]
mod mat_mul;
fn main() {
    // mat_mul::mat_mul_profile_demo();

    
    let mut v = Vec::with_capacity(4);
    for i in 0 .. 3 { 
        v.push(i); 
    }
    let n = &v[0] as *const i32;
    v.push(4);
    println!("{}", unsafe { *n });
}
