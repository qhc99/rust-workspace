use std::collections::HashMap;

#[allow(dead_code)]
/// #813
pub fn largest_sum_of_averages(nums: Vec<i32>, k: i32) -> f64 {
    let n = nums.len();

    let mut prefix_sum = vec![0];
    prefix_sum.reserve(n);
    prefix_sum.extend(nums);
    for i in 1..prefix_sum.len() {
        prefix_sum[i] += prefix_sum[i - 1];
    }

    let mut dp: Vec<f64> = Vec::new();
    dp.reserve(prefix_sum.len());
    prefix_sum.iter().for_each(|v|->(){
        dp.push(v.clone() as f64);
    });

    for i in 1..dp.len() {
        dp[i] /= i as f64;
    }

    for j in 2..=k {
        for i in (1..=n).rev() {
            for x in (j - 1) as usize..=(i - 1) {
                dp[i] = f64::max(
                    dp[i],
                    dp[x] + (prefix_sum[i] - prefix_sum[x]) as f64 / (i - x) as f64,
                );
            }
        }
    }

    return dp[n];
}

#[allow(dead_code)]
/// #815
pub fn num_buses_to_destination(routes: Vec<Vec<i32>>, source: i32, target: i32) -> i32 {
    if source == target {
        return 0;
    }
    let mut but_stop2_routes: HashMap<i32, i32> = HashMap::new();
    return 0;
}
