mod mat_mul;
mod shared_list;
mod nullable_ptr;
mod dlink_list;
mod smart_pointer;


fn main() {
    println!("start of program");
    dlink_list::double_link_list_demo();
    println!("end of program");
}
