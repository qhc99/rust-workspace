use rand::Rng;

use std::cmp;
use std::ops::Deref;
use std::time::Instant;

/// A container for values that can only be deref'd immutably.
struct Immutable<T> {
    value: T,
}

impl<T> Immutable<T> {
    pub fn new(value: T) -> Self {
        return Immutable { value };
    }
}

impl<T> Deref for Immutable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        return &self.value;
    }
}

struct MatBlock {
    r1: usize,
    c1: usize,
    r2: usize,
    c2: usize,
}

struct MatPartition {
    size_block: usize,
    m: usize,
    n: usize,
    pub rows_ptr: Immutable<usize>,
    pub cols_ptr: Immutable<usize>,
}

impl MatPartition {
    pub fn new(mat: &Vec<Vec<f32>>, size_block: usize) -> Self {
        let m = mat.len();
        let n = mat[0].len();
        let rows = (m as f32 / size_block as f32).ceil() as usize;
        let cols = (n as f32 / size_block as f32).ceil() as usize;

        return MatPartition {
            size_block,
            m,
            n,
            rows_ptr: Immutable::new(rows),
            cols_ptr: Immutable::new(cols),
        };
    }

    fn at(&self, i: usize, j: usize) -> MatBlock {
        return MatBlock {
            r1: i * self.size_block,
            c1: j * self.size_block,
            r2: cmp::min(i * self.size_block + self.size_block, self.m),
            c2: cmp::min(j * self.size_block + self.size_block, self.n),
        };
    }
}

fn reset_mat(a1: &mut Vec<Vec<f32>>, a2: &mut Vec<Vec<f32>>) {
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
    m1: &mut Vec<Vec<f32>>,
    m1r: &MatBlock,
    m2: &mut Vec<Vec<f32>>,
    m2r: &MatBlock,
    m3: &mut Vec<Vec<f32>>,
    m3r: &MatBlock,
) {
    let mut cache: Vec<Vec<f32>> = vec![vec![0.;m3r.c2-m3r.c1];m3r.r2-m3r.r1];
    for i in 0..m3r.r2 - m3r.r1 {
        for j in 0..m3r.c2 - m3r.c1 {
            for k in 0..m2r.r2 - m2r.r1 {
                cache[i][j] +=
                    m1[i + m1r.r1][k + m1r.c1] * m2[k + m2r.r1][j + m2r.c1];
            }
        }
    }

    for i in 0..m3r.r2 - m3r.r1 {
        for j in 0..m3r.c2 - m3r.c1 {
            m3[i + m3r.r1][j + m3r.c1] += cache[i][j];
        }
    }

    
}

pub fn mat_mul_profile_demo() {
    const SIZE_A: usize = 1300;
    const SIZE_B: usize = 1300;
    const SIZE_C: usize = 1300;
    let mut arr1 = vec![vec![0.; SIZE_B]; SIZE_A];
    let mut arr2 = vec![vec![0.; SIZE_C]; SIZE_B];
    let mut arr_res = vec![vec![0.; SIZE_C]; SIZE_A];

    reset_mat(&mut arr1, &mut arr2);

    let start = Instant::now();
    for i in 0..SIZE_A {
        for j in 0..SIZE_C {
            for k in 0..SIZE_B {
                arr_res[i][j] += arr1[i][k] * arr2[k][j];
            }
        }
    }
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..SIZE_A {
        for j in 0..SIZE_C {
            ans += arr_res[i][j] as f64;
        }
    }
    println!("native: time elapsed {:?}", duration);
    println!("ans = {:}", ans);

    let w_s = 64;
    let p1 = MatPartition::new(&arr1, w_s);
    let p2 = MatPartition::new(&arr2, w_s);
    let p3 = MatPartition::new(&arr_res, w_s);

    reset_mat(&mut arr1, &mut arr2);

    let start = Instant::now();
    for i in 0..*p3.rows_ptr {
        for j in 0..*p3.cols_ptr {
            let arr3_block = p3.at(i, j);
            for p in 0..arr3_block.r2 - arr3_block.r1 {
                for q in 0..arr3_block.c2 - arr3_block.c1 {
                    arr_res[p + arr3_block.r1][q + arr3_block.c1] = 0.;
                }
            }
            for k in 0..*p1.cols_ptr {
                let arr1_block = p1.at(i, k);
                let arr2_block = p2.at(k, j);
                mul_mat_block(
                    &mut arr1,
                    &arr1_block,
                    &mut arr2,
                    &arr2_block,
                    &mut arr_res,
                    &arr3_block,
                );
            }
        }
    }
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..SIZE_A {
        for j in 0..SIZE_C {
            ans += arr_res[i][j] as f64;
        }
    }
    println!("space locality: time elapsed {:?}", duration);
    println!("ans = {:}", ans);
}
