use std::rc::Rc;


struct SharedList<T> {
    val: T,
    parent: Option<Rc<SharedList<T>>>,
}



pub fn shared_list_demo() {
    let head = SharedList {
        val: 1,
        parent: None,
    };
}
