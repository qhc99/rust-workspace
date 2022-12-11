use rand::Rng;

use std::time::{Instant};

fn main() {
    let mut rng = rand::thread_rng();
    const SIZE: usize = 1300;
    let mut arr1=  vec![vec![0.; SIZE]; SIZE];
    let mut arr2 =  vec![vec![0.; SIZE]; SIZE];
    let mut arr3 =  vec![vec![0.; SIZE]; SIZE];



    for i in 0..SIZE {
        for j in 0..SIZE {
            arr1[i][j] = rng.gen::<f32>();
            arr2[i][j] = rng.gen::<f32>();

        }
    }

    let start = Instant::now();
    for i in 0..SIZE {
        for j in 0..SIZE {
            for k in 0..SIZE {
                arr3[i][j] += arr1[i][k] * arr2[k][j];
                
            }
        }
    }
    let duration = start.elapsed();

    let mut ans = 0.;
    for i in 0..SIZE {
        for j in 0..SIZE {
            ans += arr3[i][j] as f64;
        }
    }

    println!("Time elapsed is: {:?}", duration);
    println!("ans = {:}", ans);

}
