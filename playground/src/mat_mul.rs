use rand::Rng;
use std::borrow::BorrowMut;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{cmp, thread};

#[derive(Clone, Copy)]
struct NoCheckSync<T> {
    pub ptr: *mut T,
}

unsafe impl<T> Sync for NoCheckSync<T> {}

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
    pub rows_idx: usize,
    pub cols_idx: usize,
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
            rows_idx: rows,
            cols_idx: cols,
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
    m1: &Vec<Vec<f32>>,
    m1r: &MatBlock,
    m2: &Vec<Vec<f32>>,
    m2r: &MatBlock,
    m3: &mut Vec<Vec<f32>>,
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

// unsafe fn mul_mat_block_par(
//     m1: NoCheckSync<Vec<Vec<f32>>>,
//     m1r: &MatBlock,
//     m2: NoCheckSync<Vec<Vec<f32>>>,
//     m2r: &MatBlock,
//     m3: NoCheckSync<Vec<Vec<f32>>>,
//     m3r: &MatBlock,
// ) {
//     let mut cache: Vec<Vec<f32>> = vec![vec![0.; (*m3r).c2 - (*m3r).c1]; (*m3r).r2 - (*m3r).r1];
//     for i in 0..(*m3r).r2 - (*m3r).r1 {
//         for j in 0..(*m3r).c2 - (*m3r).c1 {
//             for k in 0..(*m2r).r2 - (*m2r).r1 {
//                 cache[i][j] += (*m1.ptr)[i + (*m1r).r1][k + (*m1r).c1]
//                     * (*m2.ptr)[k + (*m2r).r1][j + (*m2r).c1];
//             }
//         }
//     }

//     for i in 0..(*m3r).r2 - (*m3r).r1 {
//         for j in 0..(*m3r).c2 - (*m3r).c1 {
//             (*m3.ptr)[i + (*m3r).r1][j + (*m3r).c1] += cache[i][j];
//         }
//     }
// }

pub fn naive_mat_mul(
    arr1: &mut Vec<Vec<f32>>,
    arr2: &mut Vec<Vec<f32>>,
    arr_res: &mut Vec<Vec<f32>>,
) {
    reset_mat(arr1, arr2);
    let size_a: usize = arr1.len();
    let size_b: usize = arr2.len();
    let size_c: usize = arr2[0].len();

    let start = Instant::now();
    for i in 0..size_a {
        for j in 0..size_c {
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
    arr1: &mut Vec<Vec<f32>>,
    arr2: &mut Vec<Vec<f32>>,
    arr_res: &mut Vec<Vec<f32>>,
    w_s: usize
) {

    let size_a: usize = arr1.len();
    let size_c: usize = arr2[0].len();

    let p1 = MatPartition::new(&arr1, w_s);
    let p2 = MatPartition::new(&arr2, w_s);
    let p3 = MatPartition::new(&arr_res, w_s);

    let pp1 = &p1 as *const MatPartition;
    let pp2 = &p2 as *const MatPartition;
    let pp3 = &p3 as *const MatPartition;

    reset_mat(arr1, arr2);

    let start = Instant::now();
    for i in 0..p3.rows_idx {
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
                mul_mat_block(
                    arr1,
                    &arr1_block,
                    arr2,
                    &arr2_block,
                    arr_res,
                    &arr3_block,
                );
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
    println!("space locality: time elapsed {:?}", duration);
    println!("ans = {:}", ans);
}

#[allow(dead_code)]
pub fn mat_mul_profile_demo() {
    const SIZE_A: usize = 1300;
    const SIZE_B: usize = 1300;
    const SIZE_C: usize = 1300;
    let mut arr1 = vec![vec![0.; SIZE_B]; SIZE_A];
    let mut arr2 = vec![vec![0.; SIZE_C]; SIZE_B];
    let mut arr_res = vec![vec![0.; SIZE_C]; SIZE_A];

    //--------------------------------------------------------------
    reset_mat(&mut arr1, &mut arr2);

    let start = Instant::now();

    thread::spawn(move || -> () {});

    // for i in 0..p3.rows_idx {
    //     for j in 0..p3.cols_idx {
    //         let arr3_block = p3.at(i, j);
    //         for p in 0..arr3_block.r2 - arr3_block.r1 {
    //             for q in 0..arr3_block.c2 - arr3_block.c1 {
    //                 arr_res[p + arr3_block.r1][q + arr3_block.c1] = 0.;
    //             }
    //         }
    //         for k in 0..p1.cols_idx {
    //             let arr1_block = p1.at(i, k);
    //             let arr2_block = p2.at(k, j);

    //             unsafe {
    //                 mul_mat_block_par(
    //                     &mut arr1 as *mut _,
    //                     &arr1_block as *const _,
    //                     &mut arr2 as *mut _,
    //                     &arr2_block as *const _,
    //                     &mut arr_res as *mut _,
    //                     &arr3_block as *const _,
    //                 )
    //             }
    //         }
    //     }
    // }
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..SIZE_A {
        for j in 0..SIZE_C {
            ans += arr_res[i][j] as f64;
        }
    }
    println!("space locality par: time elapsed {:?}", duration);
    println!("ans = {:}", ans);
}
