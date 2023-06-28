use std::rc::Rc;

#[allow(dead_code)]
struct SharedList<T> {
    val: T,
    parent: Option<Rc<SharedList<T>>>,
}


#[allow(dead_code)]
pub fn shared_list_demo() {
    let head = SharedList {
        val: 1,
        parent: None,
    };
}
