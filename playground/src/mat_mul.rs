use rand::Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::cmp;
use std::time::Instant;

#[derive(Debug)]
struct MatBlock {
    r1: usize,
    c1: usize,
    r2: usize,
    c2: usize,
}

#[derive(Debug)]
struct MatPartition {
    size_block: usize,
    m: usize,
    n: usize,
    pub rows_idx: usize,
    pub cols_idx: usize,
}

impl MatPartition {
    pub fn new(mat: &[Vec<f32>], size_block: usize) -> Self {
        let m = mat.len();
        let n = mat[0].len();
        let rows = (m as f32 / size_block as f32).ceil() as usize;
        let cols = (n as f32 / size_block as f32).ceil() as usize;

        MatPartition {
            size_block,
            m,
            n,
            rows_idx: rows,
            cols_idx: cols,
        }
    }

    fn at(&self, i: usize, j: usize) -> MatBlock {
        MatBlock {
            r1: i * self.size_block,
            c1: j * self.size_block,
            r2: cmp::min(i * self.size_block + self.size_block, self.m),
            c2: cmp::min(j * self.size_block + self.size_block, self.n),
        }
    }
}

fn reset_mat(a1: &mut [Vec<f32>], a2: &mut [Vec<f32>]) {
    let mut rng = rand::thread_rng();
    let size_a: usize = a1.len();
    let size_b: usize = a2.len();
    let size_c: usize = a2[0].len();
    for i in 0..size_a {
        for j in 0..size_b {
            a1[i][j] = rng.gen::<f32>();
        }
    }

    for i in 0..size_b {
        for j in 0..size_c {
            a2[i][j] = rng.gen::<f32>();
        }
    }
}

fn mul_mat_block(
    m1: &[Vec<f32>],
    m1r: &MatBlock,
    m2: &[Vec<f32>],
    m2r: &MatBlock,
    m3: &mut [Vec<f32>],
    m3r: &MatBlock,
) {
    let mut cache: Vec<Vec<f32>> = vec![vec![0.; m3r.c2 - m3r.c1]; m3r.r2 - m3r.r1];
    for i in 0..m3r.r2 - m3r.r1 {
        for j in 0..m3r.c2 - m3r.c1 {
            for k in 0..m2r.r2 - m2r.r1 {
                cache[i][j] += m1[i + m1r.r1][k + m1r.c1] * m2[k + m2r.r1][j + m2r.c1];
            }
        }
    }

    for i in 0..m3r.r2 - m3r.r1 {
        for j in 0..m3r.c2 - m3r.c1 {
            m3[i + m3r.r1][j + m3r.c1] += cache[i][j];
        }
    }
}

pub fn naive_mat_mul(arr1: &mut [Vec<f32>], arr2: &mut [Vec<f32>], arr_res: &mut [Vec<f32>]) {
    reset_mat(arr1, arr2);
    let size_a: usize = arr1.len();
    let size_b: usize = arr2.len();
    let size_c: usize = arr2[0].len();

    let start = Instant::now();
    for i in 0..size_a {
        for j in 0..size_c {
            arr_res[i][j] = 0.;
            for k in 0..size_b {
                arr_res[i][j] += arr1[i][k] * arr2[k][j];
            }
        }
    }
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..size_a {
        for j in 0..size_c {
            ans += arr_res[i][j] as f64;
        }
    }
    println!("native: time elapsed {:?}", duration);
    println!("ans = {:}", ans);
}

fn locality_mat_mul(
    arr1: &mut [Vec<f32>],
    arr2: &mut [Vec<f32>],
    arr_res: &mut [Vec<f32>],
    w_s: usize,
) {
    let size_a: usize = arr1.len();
    let size_c: usize = arr2[0].len();

    let p1 = MatPartition::new(arr1, w_s);
    let p2 = MatPartition::new(arr2, w_s);
    let p3 = MatPartition::new(arr_res, w_s);

    reset_mat(arr1, arr2);

    let start = Instant::now();
    for i in 0..p3.rows_idx {
        locality_mat_mul_row(i, arr1, arr2, arr_res, &p1, &p2, &p3);
    }
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..size_a {
        for j in 0..size_c {
            ans += arr_res[i][j] as f64;
        }
    }
    println!("space locality: time elapsed {:?}", duration);
    println!("ans = {:}", ans);
}

fn locality_mat_mul_row(
    i: usize,
    arr1: &[Vec<f32>],
    arr2: &[Vec<f32>],
    arr_res: &mut [Vec<f32>],
    p1: &MatPartition,
    p2: &MatPartition,
    p3: &MatPartition,
) {
    for j in 0..p3.cols_idx {
        let arr3_block = p3.at(i, j);
        for p in 0..arr3_block.r2 - arr3_block.r1 {
            for q in 0..arr3_block.c2 - arr3_block.c1 {
                arr_res[p + arr3_block.r1][q + arr3_block.c1] = 0.;
            }
        }
        for k in 0..p1.cols_idx {
            let arr1_block = p1.at(i, k);
            let arr2_block = p2.at(k, j);
            mul_mat_block(arr1, &arr1_block, arr2, &arr2_block, arr_res, &arr3_block);
        }
    }
}

fn locality_mat_mul_par(
    arr1: &mut Vec<Vec<f32>>,
    arr2: &mut Vec<Vec<f32>>,
    arr_res: &mut Vec<Vec<f32>>,
    w_s: usize,
) {
    let size_a: usize = arr1.len();
    let size_c: usize = arr2[0].len();

    let p1 = MatPartition::new(arr1, w_s);
    let p2 = MatPartition::new(arr2, w_s);
    let p3 = MatPartition::new(arr_res, w_s);
    let loop_size = p3.rows_idx;

    reset_mat(arr1, arr2);

    let arr1 = arr1 as *mut Vec<Vec<f32>> as usize;
    let arr2 = arr2 as *mut Vec<Vec<f32>> as usize;
    let arr3 = arr_res as *mut Vec<Vec<f32>> as usize;

    let p1 = &p1 as *const MatPartition as usize;
    let p2 = &p2 as *const MatPartition as usize;
    let p3 = &p3 as *const MatPartition as usize;

    let start = Instant::now();

    let data: Vec<Vec<usize>> = (0..loop_size)
        .map(|i| -> Vec<usize> { vec![i, arr1, arr2, arr3, p1, p2, p3] })
        .collect();
    data.par_iter().for_each(|v| {
        let i = v[0];
        unsafe {
            let arr1 = &*(v[1] as *mut Vec<Vec<f32>>);
            let arr2 = &*(v[2] as *mut Vec<Vec<f32>>);
            let arr_res = &mut *(v[3] as *mut Vec<Vec<f32>>);

            let p1 = &*(v[4] as *const MatPartition);
            let p2 = &*(v[5] as *const MatPartition);
            let p3 = &*(v[6] as *const MatPartition);
            locality_mat_mul_row(i, arr1, arr2, arr_res, p1, p2, p3);
        }
    });
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..size_a {
        for j in 0..size_c {
            ans += arr_res[i][j] as f64;
        }
    }
    println!("rayon space locality: time elapsed {:?}", duration);
    println!("ans = {:}", ans);
}

pub fn mat_mul_profile_demo() {
    const SIZE_A: usize = 1000;
    const SIZE_B: usize = 1000;
    const SIZE_C: usize = 1000;
    let mut arr1 = vec![vec![0.; SIZE_B]; SIZE_A];
    let mut arr2 = vec![vec![0.; SIZE_C]; SIZE_B];
    let mut arr_res = vec![vec![0.; SIZE_C]; SIZE_A];

    naive_mat_mul(&mut arr1, &mut arr2, &mut arr_res);
    // locality_mat_mul(&mut arr1, &mut arr2, &mut arr_res, 64);
    // locality_mat_mul_par(&mut arr1, &mut arr2, &mut arr_res, 64)
}
