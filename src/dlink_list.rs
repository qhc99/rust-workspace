
use crate::nullable_ptr::NullablePtr;
use crate::nullable_ptr::Pointer;

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

    fn unwrap_val(&self) -> Pointer<T> {
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
impl<T> Drop for DNode<T>
where
    T: std::fmt::Debug,
{
    fn drop(&mut self) {
        if cfg!(debug_assertions) {
            if self.val.not_null() {
                eprintln!("Drop val {:?}.", self.val.unwrap());
            } else {
                eprintln!("Drop head or tail.");
            }
        }
    }
}

struct DLinkList<T>
where
    T: std::fmt::Debug,
{
    size: i32,
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

    pub fn insert_first(&mut self, val: T) {
        self.size = self.size + 1;
        self.insert_after(val, self.head.unwrap());
    }

    pub fn insert_last(&mut self, val: T) {
        self.size = self.size + 1;
        let at = self.tail.borrow().prev.unwrap();
        self.insert_after(val, at);
    }

    pub fn remove_first(&mut self) -> Option<Pointer<T>> {
        if self.size == 0 {
            return None;
        }
        self.size = self.size - 1;
        let n = self.head.borrow_mut().next.unwrap();
        n.borrow_mut().detach();
        return Some(n.borrow().unwrap_val());
    }

    pub fn remove_last(&mut self) -> Option<Pointer<T>> {
        if self.size == 0 {
            return None;
        }
        self.size = self.size - 1;
        let n = self.tail.borrow_mut().prev.unwrap();
        n.borrow_mut().detach();
        return Some(n.borrow().unwrap_val());
    }

    fn insert_after(&mut self, val: T, at: Pointer<DNode<T>>) {
        let in_node = DNode::new(val);
        let in_node_ptr = NullablePtr::new(in_node);

        let n = at;
        let n_next = n.borrow().next.clone().unwrap();

        n.borrow_mut().next = in_node_ptr.clone();
        n_next.borrow_mut().prev = in_node_ptr.clone();

        let node = in_node_ptr.unwrap();
        let mut node = node.borrow_mut();
        node.prev = NullablePtr::of(n);
        node.next = NullablePtr::of(n_next);
    }
}

impl<Val> Drop for DLinkList<Val>
where
    Val: std::fmt::Debug,
{
    fn drop(&mut self) {
        let mut p = self.head.unwrap();
        let mut p1 = p.borrow().prev.unwrap();
        if cfg!(debug_assertions) {
            eprintln!("---Drop dlink list---");
        }
        loop {
            p1.borrow_mut().next = NullablePtr::<DNode<Val>>::nullptr();
            p1 = p.clone();
            if p.borrow().next.is_null() {
                break;
            } else {
                let t = p.borrow().next.unwrap();
                p = t;
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

    l.insert_last(4);
    l.insert_last(5);
    l.insert_last(6);

    println!("exit function")
}

#[test]
fn dlink_list_drop_test_1() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    l.insert_last(4);
    l.insert_last(5);
    l.insert_last(6);

    println!("exit function");
    assert_eq!(4, 4);
}

#[test]
fn dlink_list_drop_test_2() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    l.remove_last();
    l.remove_last();
    l.remove_last();

    println!("exit function");
    assert_eq!(4, 4);
}

#[test]
fn dlink_list_drop_test_3() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    l.remove_first();
    l.remove_first();
    l.remove_first();

    println!("exit function");
    assert_eq!(4, 4);
}
