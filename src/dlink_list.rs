use crate::nullable_ptr::NullablePtr;
use crate::nullable_ptr::RcRefCell;

struct DNode<T>
where
    T: std::fmt::Debug,
{
    pub val: NullablePtr<T>,
    pub prev: NullablePtr<DNode<T>>,
    pub next: NullablePtr<DNode<T>>,
}

#[allow(dead_code)]
impl<T> DNode<T>
where
    T: std::fmt::Debug,
{
    fn new(val: T) -> Self {
        Self {
            val: NullablePtr::new(val),
            prev: NullablePtr::<DNode<T>>::nullptr(),
            next: NullablePtr::<DNode<T>>::nullptr(),
        }
    }

    fn empty() -> Self {
        Self {
            val: NullablePtr::<T>::nullptr(),
            prev: NullablePtr::<DNode<T>>::nullptr(),
            next: NullablePtr::<DNode<T>>::nullptr(),
        }
    }

    fn unwrap_val(&self) -> RcRefCell<T> {
        self.val.unwrap()
    }

    fn detach(&mut self) {
        let p = self.prev.unwrap();
        let n = self.next.unwrap();
        p.borrow_mut().next = NullablePtr::of(n.clone());
        n.borrow_mut().prev = NullablePtr::of(p);

        self.next = NullablePtr::<DNode<T>>::nullptr();
        self.prev = NullablePtr::<DNode<T>>::nullptr();
    }
}

impl<T> PartialEq for DNode<T>
where
    T: std::fmt::Debug,
{
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(&self.val as *const _, &other.val as *const _)
    }
}

#[cfg(debug_assertions)]
impl<T> Drop for DNode<T>
where
    T: std::fmt::Debug,
{
    fn drop(&mut self) {
        if self.val.not_null() {
            eprintln!("Drop val {:?}.", self.val.unwrap());
        } else {
            eprintln!("Drop head or tail.");
        }
    }
}

struct DLinkList<T>
where
    T: std::fmt::Debug,
{
    size: usize,
    head: NullablePtr<DNode<T>>,
    tail: NullablePtr<DNode<T>>,
}

#[allow(dead_code)]
impl<T> DLinkList<T>
where
    T: std::fmt::Debug,
{
    pub fn new() -> Self {
        let head = NullablePtr::new(DNode::empty());
        let tail = NullablePtr::new(DNode::empty());

        let h = head.unwrap();
        let t = tail.unwrap();

        h.borrow_mut().next = tail.clone();
        t.borrow_mut().next = head.clone();

        h.borrow_mut().prev = tail.clone();
        t.borrow_mut().prev = head.clone();
        return DLinkList {
            head,
            tail,
            size: 0,
        };
    }

    pub fn get_first(&self) -> RcRefCell<T> {
        if self.size > 0 {
            self.head.borrow().next.borrow().unwrap_val().clone()
        } else {
            panic!("extract from empty list");
        }
    }

    pub fn get_last(&self) -> RcRefCell<T> {
        if self.size > 0 {
            self.tail.borrow().prev.borrow().unwrap_val().clone()
        } else {
            panic!("extract from empty list");
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn insert_first(&mut self, val: T) {
        self.size = self.size + 1;
        DLinkList::insert_after(val, self.head.unwrap());
    }

    pub fn insert_last(&mut self, val: T) {
        self.size = self.size + 1;
        let at = self.tail.borrow().prev.unwrap();
        DLinkList::insert_after(val, at);
    }

    pub fn remove_first(&mut self) -> Option<RcRefCell<T>> {
        let n = self.head.borrow_mut().next.unwrap();
        if self.size == 0 {
            return None;
        }
        self.size = self.size - 1;

        return DLinkList::remove_node(n);
    }

    pub fn remove_last(&mut self) -> Option<RcRefCell<T>> {
        let n = self.tail.borrow_mut().prev.unwrap();
        if self.size == 0 {
            return None;
        }
        self.size = self.size - 1;

        return DLinkList::remove_node(n);
    }

    fn remove_node(n: RcRefCell<DNode<T>>) -> Option<RcRefCell<T>> {
        n.borrow_mut().detach();
        return Some(n.borrow().unwrap_val().clone());
    }

    fn insert_after(val: T, at: RcRefCell<DNode<T>>) {
        let in_node = DNode::new(val);
        let in_node_ptr = NullablePtr::new(in_node);

        let n = at;
        let n_next = n.borrow().next.unwrap();

        let node = in_node_ptr.unwrap();
        node.borrow_mut().prev = NullablePtr::of(n.clone());
        node.borrow_mut().next = NullablePtr::of(n_next.clone());

        n.borrow_mut().next = in_node_ptr.clone();
        n_next.borrow_mut().prev = in_node_ptr;
    }
}

impl<Val> Drop for DLinkList<Val>
where
    Val: std::fmt::Debug,
{
    fn drop(&mut self) {
        let mut p = self.head.unwrap().clone();
        let mut p1 = p.borrow().prev.unwrap().clone();
        if cfg!(debug_assertions) {
            eprintln!("---Drop dlink list---");
        }
        loop {
            p1.borrow_mut().next = NullablePtr::<DNode<Val>>::nullptr();
            p1 = p.clone();
            if p.borrow().next.is_null() {
                break;
            } else {
                let temp = p.borrow().next.unwrap().clone();
                p = temp;
            }
        }
        self.head.borrow_mut().prev = NullablePtr::<DNode<Val>>::nullptr();
    }
}

pub fn double_link_list_demo() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    println!("exit function")
}

#[test]
fn dlink_list_drop_insert_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    assert_eq!(3, l.len());

    l.insert_last(4);
    l.insert_last(5);
    l.insert_last(6);

    assert_eq!(6, l.len());
}

#[test]
// Drop val RefCell { value: 1 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 3 }.
// ---Drop dlink list---
// Drop head or tail.
// Drop head or tail.
fn dlink_list_drop_remove_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    assert_eq!(3, l.len());

    l.remove_last();
    l.remove_last();
    l.remove_last();

    assert_eq!(0, l.len());
}

#[test]
// Drop val RefCell { value: 3 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 1 }.
// ---Drop dlink list---
// Drop head or tail.
// Drop head or tail.
fn dlink_list_drop_remove_reverse_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);
    assert_eq!(3, l.len());

    l.remove_first();
    l.remove_first();
    l.remove_first();
    assert_eq!(0, l.len());
}

#[test]
///---Drop dlink list---
// Drop head or tail.
// Drop val RefCell { value: 1 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 0 }.
// Drop head or tail.
fn dlink_list_head_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    let h = l.get_first();
    let mut t = 1;
    t = t + h.take();

    assert_eq!(4, t);
    assert_eq!(0, h.borrow().clone());
}
