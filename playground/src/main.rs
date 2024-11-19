// #![allow(clippy::needless_range_loop)]
// #![allow(dead_code)]

use sobel::sobel;
// mod mat_mul;
// mod dir_tree_size;
// mod claire_voyant;
mod sobel;
fn main(){
    let t: Vec<u8> = vec![1,2];
    let mut t2 = vec![1.0f32];
    sobel(&t, &mut t2, 100, 100);
}