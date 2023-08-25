#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use std::ops::Add;
mod mat_mul;

struct Point<T> where T :std::ops::Add<Output = T>{
    x: T,
    y: T
}

impl<T> Add<Point<T>> for i32 where T :std::ops::Add<Output = T>{
    type Output = Point<T>;

    fn add(self, rhs: Point<T>) -> Self::Output {
        todo!()
    }
}

fn just_return<T>(t: T)->T{
    t
}

fn main() {

    let mut t = "a".to_owned();
    let tt = just_return(&mut t);
}
