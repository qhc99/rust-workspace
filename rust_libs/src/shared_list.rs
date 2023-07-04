use std::rc::Rc;

#[allow(dead_code)]
struct SharedList<T> {
    val: T,
    parent: Option<Rc<SharedList<T>>>,
}



