#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]
mod mat_mul;
mod dir_tree_size;
fn main()->std::io::Result<()>{
    dir_tree_size::main()
}