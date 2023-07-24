use leetcode800::*;

mod leetcode800;
pub fn main(){

    println!("{}",num_buses_to_destination(vec![vec![1,2,7],vec![3,6,7]], 1, 6));
    println!("{}",num_buses_to_destination(vec![vec![7,12],vec![4,5,15],vec![6],vec![15,19],vec![9,12,13]], 15, 12));
    println!("{}",num_buses_to_destination(vec![vec![7,12],vec![4,5,15],vec![6],vec![15,19],vec![9,12,13]], 7, 13));
    // println!("{}",largest_sum_of_averages(vec![1,2,3,4,5,6,7], 4));
}
