#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

mod leetcode400;
mod leetcode800;
mod leetcode900;

fn main() {
    leetcode800::num_buses_to_destination(vec![vec![1, 2, 7], vec![3, 6, 7]], 1, 6);
}
