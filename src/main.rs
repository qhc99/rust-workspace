mod dlink_list;
mod mat_mul;
mod nullable_ptr;
mod shared_list;

trait Pet {
    fn name(&self) -> String;
}

struct Dog {
    name: String,
}

struct Cat;

impl Pet for Dog {
    fn name(&self) -> String {
        self.name.clone()
    }
}

impl Pet for Cat {
    fn name(&self) -> String {
        String::from("The cat") // No name, cats won't respond to it anyway.
    }
}

fn main() {
    dlink_list::double_link_list_demo();
    let mut v = vec![1;3];
    v.iter();

}
