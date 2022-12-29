use std::{rc::{Rc, Weak}, cell::RefCell};


struct SharedList<T> {
    val: T,
    parent: Rc<Option<SharedList<T>>>
}


struct DList<T> {
    val: T,
    prev_w: WeakLink<T>,
    next: Link<T>,
}

impl<T> DList<T> {
    fn new(item: T) -> Self {
        Self {
            val: item,
            prev_w: None,
            next: None,
        }
    }
}

type Link<T> = Option<Rc<RefCell<DList<T>>>>;
type WeakLink<T> = Option<Weak<RefCell<DList<T>>>>;

pub fn shared_list_demo(){
    let head = SharedList {val: 1, parent: Rc::new(None)};
}

pub fn double_link_list_demo(){
    let mut head: Rc<DList<i32>>;
    head = Rc::new(DList {val: 1, prev_w: None, next: None});
    

}