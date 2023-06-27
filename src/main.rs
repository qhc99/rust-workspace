mod mat_mul;
mod shared_list;
mod rc_refcell_option;

struct A {
    val: i64,
}

enum e {}

// mat_mul::mat_mul_profile_demo();
// shared_list::double_link_list_demo();


#[derive(Debug)]
enum Either {
  Left(usize),
  Right(String)
}
fn main() {
    shared_list::double_link_list_demo()
}
