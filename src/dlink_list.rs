use crate::nullable_ptr::NullablePtr;
use crate::nullable_ptr::Pointer;

struct DNode<T>
where
    T: std::fmt::Debug,
{
    pub val: Option<T>,
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
            val: Some(val),
            prev: NullablePtr::<DNode<T>>::nullptr(),
            next: NullablePtr::<DNode<T>>::nullptr(),
        }
    }

    fn empty() -> Self {
        Self {
            val: None,
            prev: NullablePtr::<DNode<T>>::nullptr(),
            next: NullablePtr::<DNode<T>>::nullptr(),
        }
    }

    fn detach(&mut self) {
        let p = self.prev.unwrap();
        let n = self.next.unwrap();
        p.borrow_mut().next = NullablePtr::of(n.clone());
        n.borrow_mut().prev = NullablePtr::of(p);
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
        if self.val.is_some() {
            println!("Drop val {:?}.", self.val.as_ref().unwrap());
        } else {
            println!("Drop head or tail.");
        }
    }
}

struct DLinkList<T>
where
    T: std::fmt::Debug,
{
    head: NullablePtr<DNode<T>>,
    tail: NullablePtr<DNode<T>>,
}

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
        return DLinkList { head, tail };
    }

    pub fn insert_head(&mut self, val: T) {
        self.insert_after(val, self.head.clone().unwrap());
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

    pub fn insert_tail(&mut self, val: T) {
        let at = self.tail.unwrap().borrow().prev.unwrap();
        self.insert_after(val, at);
    }
}

impl<Val> Drop for DLinkList<Val>
where
    Val: std::fmt::Debug,
{
    fn drop(&mut self) {
        let mut p = self.head.unwrap();
        let mut p1 = p.borrow().prev.unwrap();
        println!("---Drop dlink list---");
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
        self.head.unwrap().borrow_mut().prev = NullablePtr::<DNode<Val>>::nullptr();
    }
}

pub fn double_link_list_demo() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_head(1);
    l.insert_head(2);
    l.insert_head(3);

    l.insert_tail(4);
    l.insert_tail(5);
    l.insert_tail(6);

    println!("exit function")
}

#[test]
fn dlink_list_drop_test(){
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_head(1);
    l.insert_head(2);
    l.insert_head(3);

    l.insert_tail(4);
    l.insert_tail(5);
    l.insert_tail(6);

    println!("exit function");
    assert_eq!(4, 4);
}
