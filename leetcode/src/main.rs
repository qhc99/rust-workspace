use crate::leetcode800::sum_of_distances_in_tree;
mod leetcode800;

pub fn main(){
    let t = [[0,1],[0,2],[2,3],[2,4],[2,5]];
    let t: Vec<Vec<i32>> = t.iter().map(|v|->Vec<i32>{v.to_vec()}).collect();
    
    println!("{:?}", sum_of_distances_in_tree(6, t))
}

