use std::time::Instant;

fn big_decimal_array(start: i32, end_inclusive: i32, step: i32, scale: i32) -> Vec<f64> {
    (start..=end_inclusive)
        .step_by(step as usize)
        .map(|i| i as f64 / scale as f64)
        .collect()
}

fn get_futures(idx: usize, arr: &[f64]) -> (f64, f64) {
    let min = arr[idx..]
        .iter()
        .map(|&a| a.min(1.0 - a))
        .product();

    let max = arr[idx..]
        .iter()
        .map(|&a| a.max(1.0 - a))
        .product();

    (min, max)
}

fn generate_table_recursive(
    current_idx: usize,
    prev_choice_1_result: f64,
    prev_choice_2_result: f64,
    arr: &[f64],
    min_futures: &[f64],
    max_futures: &[f64],
    total: &mut f64,
) {
    if current_idx >= arr.len() {
        *total += prev_choice_1_result.max(prev_choice_2_result);
    } else {
        let min_future = min_futures[current_idx];
        let max_future = max_futures[current_idx];
        let min_choice = prev_choice_1_result.min(prev_choice_2_result);
        let max_choice = prev_choice_1_result.max(prev_choice_2_result);

        if min_choice * max_future <= max_choice * min_future {
            *total += max_choice;
            return;
        }

        generate_table_recursive(
            current_idx + 1,
            prev_choice_1_result * arr[current_idx],
            prev_choice_2_result * (1.0 - arr[current_idx]),
            arr,
            min_futures,
            max_futures,
            total,
        );

        generate_table_recursive(
            current_idx + 1,
            prev_choice_1_result * (1.0 - arr[current_idx]),
            prev_choice_2_result * arr[current_idx],
            arr,
            min_futures,
            max_futures,
            total,
        );
    }
}

fn generate(a: &[f64]) -> f64 {
    let mut min_futures = Vec::new();
    let mut max_futures = Vec::new();

    for i in 0..a.len() {
        let (min, max) = get_futures(i, a);
        min_futures.push(min);
        max_futures.push(max);
    }

    let mut total = 0.0;
    generate_table_recursive(1, a[0], 1.0 - a[0], a, &min_futures, &max_futures, &mut total);
    total
}

pub fn run() {
    let start = Instant::now();
    let arr = big_decimal_array(25, 58, 1, 100);
    println!("{:.15}", generate(&arr));
    let duration = start.elapsed();
    println!("{:.6} seconds", duration.as_secs_f64());
}
