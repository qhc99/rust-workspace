use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};
#[allow(dead_code)]
struct SharedList<T> {
    val: T,
    parent: Option<Rc<SharedList<T>>>,
}

#[allow(dead_code)]
struct DListNode<T> {
    pub val: T,
    pub prev_w: WeakLink<T>,
    pub next: Link<T>,
}

#[allow(dead_code)]
struct DoubleLinkList<T>{
    head: DListNode<T>,
    tail: DListNode<T>
}


impl<T> DListNode<T> {
    fn new(val: T) -> Self {
        Self {
            val,
            prev_w: None,
            next: None,
        }
    }
}

type Link<T> = Option<Rc<RefCell<DListNode<T>>>>;
type WeakLink<T> = Option<Weak<RefCell<DListNode<T>>>>;

#[allow(dead_code)]
pub fn shared_list_demo() {
    let head = SharedList {
        val: 1,
        parent: None,
    };
}

#[allow(dead_code)]
pub fn double_link_list_demo() {
    let head = Rc::new(RefCell::new(DListNode::new(0)));
    head.borrow_mut().prev_w = Some(Rc::downgrade(&head));
    head.borrow_mut().next = Some(head.clone());
    
    let node_1 = Rc::new(RefCell::new(DListNode::new(1)));
    head.borrow_mut().prev_w = Some(Rc::downgrade(&&node_1.clone()));
    head.borrow_mut().next = Some(node_1.clone());

    node_1.borrow_mut().prev_w = Some(Rc::downgrade(&head.clone()));
    node_1.borrow_mut().next = Some(head.clone());

    let node_2 = Rc::new(RefCell::new(DListNode::new(2)));

    node_2.borrow_mut().prev_w = Some(Rc::downgrade(&&node_1.clone()));
    node_1.borrow_mut().next = Some(node_2.clone());

    node_2.borrow_mut().next = Some(head.clone());
    head.borrow_mut().prev_w = Some(Rc::downgrade(&&node_2.clone()));

    head.borrow_mut().next = None;

    for _i in 0..100000000 {
        let head = Rc::new(RefCell::new(DListNode::new(0)));
        head.borrow_mut().next = Some(head.clone());
        // disable the line below will cause memory leak
        head.borrow_mut().next = None;
    }
}
