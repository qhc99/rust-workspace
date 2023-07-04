use crate::nullable_ptr::NullablePtr;
use crate::nullable_ptr::RcRefCell;
use std::fmt::Debug;
use std::iter::Rev;

#[derive(Debug)]
struct DNode<Val>
where
    Val: Debug,
{
    pub val: NullablePtr<Val>,
    pub prev: NullablePtr<DNode<Val>>,
    pub next: NullablePtr<DNode<Val>>,
}

impl<Val> DNode<Val>
where
    Val: Debug,
{
    fn new(val: Val) -> Self {
        Self {
            val: NullablePtr::new(val),
            prev: NullablePtr::<DNode<Val>>::nullptr(),
            next: NullablePtr::<DNode<Val>>::nullptr(),
        }
    }

    fn empty() -> Self {
        Self {
            val: NullablePtr::<Val>::nullptr(),
            prev: NullablePtr::<DNode<Val>>::nullptr(),
            next: NullablePtr::<DNode<Val>>::nullptr(),
        }
    }

    fn get_val(&self) -> RcRefCell<Val> {
        self.val.unwrap()
    }

    fn detach(&mut self) {
        let p = self.prev.unwrap_ref();
        let n = self.next.unwrap_ref();
        p.borrow_mut().next = NullablePtr::of(n.clone());
        n.borrow_mut().prev = NullablePtr::of(p.clone());

        self.next = NullablePtr::<DNode<Val>>::nullptr();
        self.prev = NullablePtr::<DNode<Val>>::nullptr();
    }
}

impl<Val> PartialEq for DNode<Val>
where
    Val: Debug,
{
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(&self.val as *const _, &other.val as *const _)
    }
}

#[cfg(test)]
impl<Val> Drop for DNode<Val>
where
    Val: Debug,
{
    fn drop(&mut self) {
        if self.val.not_null() {
            eprintln!("Drop val {:?}.", self.val.unwrap());
        } else {
            eprintln!("Drop head or tail.");
        }
    }
}

#[derive(Debug)]
pub struct DLinkList<Val>
where
    Val: Debug,
{
    size: usize,
    head: NullablePtr<DNode<Val>>,
    tail: NullablePtr<DNode<Val>>,
}

impl<Val> DLinkList<Val>
where
    Val: Debug,
{
    pub fn new() -> Self {
        let head = NullablePtr::new(DNode::empty());
        let tail = NullablePtr::new(DNode::empty());

        let h = head.unwrap_ref();
        let t = tail.unwrap_ref();

        h.borrow_mut().next = tail.clone();
        t.borrow_mut().prev = head.clone();
        return DLinkList {
            head,
            tail,
            size: 0,
        };
    }

    pub fn get_first(&self) -> RcRefCell<Val> {
        if self.size > 0 {
            self.head.borrow().next.borrow().get_val()
        } else {
            panic!("extract from empty list");
        }
    }

    pub fn get_last(&self) -> RcRefCell<Val> {
        if self.size > 0 {
            self.tail.borrow().prev.borrow().get_val()
        } else {
            panic!("extract from empty list");
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn insert_first(&mut self, val: Val) {
        self.size = self.size + 1;
        DLinkList::insert_after(val, self.head.unwrap_ref());
    }

    pub fn insert_last(&mut self, val: Val) {
        self.size = self.size + 1;
        // cannot use unwrap because borrow() create a temporary object
        let at = self.tail.borrow().prev.unwrap();
        DLinkList::insert_after(val, &at);
    }

    pub fn remove_first(&mut self) -> Option<RcRefCell<Val>> {
        let n = self.head.borrow_mut().next.unwrap();
        if self.size == 0 {
            return None;
        }
        self.size = self.size - 1;

        return DLinkList::remove_node(&n);
    }

    pub fn remove_last(&mut self) -> Option<RcRefCell<Val>> {
        let n = self.tail.borrow_mut().prev.unwrap();
        if self.size == 0 {
            return None;
        }
        self.size = self.size - 1;

        return DLinkList::remove_node(&n);
    }

    fn remove_node(n: &RcRefCell<DNode<Val>>) -> Option<RcRefCell<Val>> {
        n.borrow_mut().detach();
        return Some(n.borrow().get_val());
    }

    fn insert_after(val: Val, n: &RcRefCell<DNode<Val>>) {
        let in_node = DNode::new(val);
        let in_node_ptr = NullablePtr::new(in_node);

        let n_next = n.borrow().next.unwrap();

        let node = in_node_ptr.unwrap_ref();
        node.borrow_mut().prev = NullablePtr::of(n.clone());
        node.borrow_mut().next = NullablePtr::of(n_next.clone());

        n.borrow_mut().next = in_node_ptr.clone();
        n_next.borrow_mut().prev = in_node_ptr;
    }
}

impl<Val> Drop for DLinkList<Val>
where
    Val: Debug,
{
    fn drop(&mut self) {
        let mut p = self.head.unwrap();
        if cfg!(test) {
            eprintln!("---Drop dlink list---");
        }
        loop {
            let next = p.borrow().next.clone();
            if next.is_null() {
                break;
            } else {
                p.borrow_mut().next = NullablePtr::<DNode<Val>>::nullptr();
                p = next.unwrap();
            }
        }
        self.tail.borrow_mut().prev = NullablePtr::<DNode<Val>>::nullptr();
    }
}

// TODO fix into_iter result is none
impl<V> IntoIterator for DLinkList<V>
where
    V: Debug,
{
    type Item = RcRefCell<V>;

    type IntoIter = DLinkListIter<V>;

    fn into_iter(self) -> Self::IntoIter {
        let c = self.head.borrow().next.unwrap();
        DLinkListIter {
            current: c,
            list: self,
        }
    }
}

#[derive(Debug)]
pub struct DLinkListIter<Val>
where
    Val: Debug,
{
    list: DLinkList<Val>,
    current: RcRefCell<DNode<Val>>,
}

impl<Val> Iterator for DLinkListIter<Val>
where
    Val: Debug,
{
    type Item = RcRefCell<Val>;

    fn next(&mut self) -> Option<Self::Item> {
        return if self.current != self.list.tail.unwrap() {
            let ans = self.current.borrow().val.clone();
            let next = self.current.borrow().next.unwrap();
            self.current = next;
            return if ans.is_null() {
                None
            } else {
                Some(ans.unwrap())
            };
        } else {
            None
        };
    }
}

impl<Val> DoubleEndedIterator for DLinkListIter<Val>
where
    Val: Debug,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.current != self.list.head.unwrap() {
            let ans = self.current.borrow().val.clone();
            let next = self.current.borrow().prev.unwrap();
            self.current = next;
            return if ans.is_null() {
                None
            } else {
                Some(ans.unwrap())
            };
        } else {
            return None;
        }
    }
}

pub fn double_link_list_demo() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);
}
