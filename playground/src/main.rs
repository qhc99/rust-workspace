mod mat_mul;
mod rayon_bench;

fn main() {
    // mat_mul::mat_mul_profile_demo();
    // let mut mat = vec![vec![1.; 3]; 3];
    // let p1 = &mut mat as * mut Vec<Vec<f64>>;
    // let p2 = &mut mat as * mut Vec<Vec<f64>>;
    rayon_bench::bench_matmul_strassen();
}
