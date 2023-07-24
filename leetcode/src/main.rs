use leetcode800::*;

mod leetcode800;
pub fn main(){
    println!("{:?}", ambiguous_coordinates("(123)".to_string()));
    println!("{:?}", ambiguous_coordinates("(0123)".to_string()));
    println!("{:?}", ambiguous_coordinates("(00011)".to_string()));
}
