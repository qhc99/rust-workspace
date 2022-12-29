use std::{rc::{Rc, Weak}, cell::RefCell, ops::{DerefMut, Deref}};


struct SharedList<T> {
    val: T,
    parent: Rc<Option<SharedList<T>>>
}


struct DList<T> {
    pub val: T,
    pub prev_w: WeakLink<T>,
    pub next: Link<T>,
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
    
    let head = Rc::new(RefCell::new(DList{val: 0, prev_w: None, next: None}));
    head.borrow_mut().prev_w = Some(Rc::downgrade(&head.to_owned()));
    head.borrow_mut().next = Some(head.to_owned());

    let node_1 = Rc::new(RefCell::new(DList{val: 1, prev_w: None, next: None}));
}