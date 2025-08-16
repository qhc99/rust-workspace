#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use rand::{Rng, rngs::ThreadRng};

mod leetcode400;
mod leetcode800;
mod leetcode900;

fn main() {
    leetcode800::num_buses_to_destination(vec![vec![1, 2, 7], vec![3, 6, 7]], 1, 6);
}

struct Solution {}
use std::cmp::max;
use std::cmp::min;

impl Solution {
    pub fn new21_game(n: i32, k: i32, max_pts: i32) -> f64 {
        let mut arr = vec![0f64; (n + 1) as usize];
        let mut sum = vec![0f64; (n + 2) as usize];
        let max_pts = max_pts as f64;
        arr[0] = 1f64;
        sum[1] = 1f64;
        // 0 1 2 3 ... 10
        for i in 1..=min(n, k - 1 + max_pts as i32) {
            // for j in max(0, i - max_pts as i32)..min(i, k) {
            //     arr[i as usize] += arr[j as usize] / max_pts;
            // }
            let start = max(0, i - max_pts as i32) as usize;
            let end = min(i, k) as usize;
            arr[i as usize] = (sum[end] - sum[start+1])/max_pts;

            sum[i as usize + 1] = arr[i as usize] + sum[i as usize];
        }
        arr.iter().skip(k as usize).sum()
    }
}
