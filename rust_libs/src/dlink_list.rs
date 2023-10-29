use crate::nullable_ptr::NullablePtr;
use crate::nullable_ptr::RcRefCell;
use std::fmt::Debug;

#[derive(Debug)]
pub struct DNode<V> {
    pub val: NullablePtr<V>,
    prev: NullablePtr<DNode<V>>,
    next: NullablePtr<DNode<V>>,
}

#[allow(dead_code)]
impl<V> DNode<V> {
    fn new(val: V) -> Self {
        Self {
            val: NullablePtr::new(val),
            prev: NullablePtr::<DNode<V>>::nullptr(),
            next: NullablePtr::<DNode<V>>::nullptr(),
        }
    }

    fn empty() -> Self {
        Self {
            val: NullablePtr::<V>::nullptr(),
            prev: NullablePtr::<DNode<V>>::nullptr(),
            next: NullablePtr::<DNode<V>>::nullptr(),
        }
    }

    fn get_val(&self) -> RcRefCell<V> {
        self.val.unwrap()
    }

    fn detach(&mut self) {
        let p = self.prev.unwrap_ref();
        let n = self.next.unwrap_ref();
        p.borrow_mut().next = NullablePtr::of(n.clone());
        n.borrow_mut().prev = NullablePtr::of(p.clone());

        self.next = NullablePtr::<DNode<V>>::nullptr();
        self.prev = NullablePtr::<DNode<V>>::nullptr();
    }
}

impl<V> PartialEq for DNode<V> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(&self.val as *const _, &other.val as *const _)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DLinkList<V> {
    size: usize,
    head: NullablePtr<DNode<V>>,
    tail: NullablePtr<DNode<V>>,
}

#[allow(dead_code)]
impl<V> DLinkList<V> {
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

    pub fn peek_first(&self) -> RcRefCell<V> {
        if self.size > 0 {
            self.head.borrow().next.borrow().get_val()
        } else {
            panic!("extract from empty list");
        }
    }

    pub fn peek_last(&self) -> RcRefCell<V> {
        if self.size > 0 {
            self.tail.borrow().prev.borrow().get_val()
        } else {
            panic!("extract from empty list");
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn insert_first(&mut self, val: V) {
        self.size += 1;
        DLinkList::insert_after(val, self.head.unwrap_ref());
    }

    pub fn insert_last(&mut self, val: V) {
        self.size += 1;
        // cannot use unwrap because borrow() create a temporary object
        let at = self.tail.borrow().prev.unwrap();
        DLinkList::insert_after(val, &at);
    }

    pub fn remove_first(&mut self) -> Option<RcRefCell<V>> {
        let n = self.head.borrow_mut().next.unwrap();
        if self.size == 0 {
            return None;
        }
        self.size -= 1;

        return DLinkList::remove_node(&n);
    }

    pub fn remove_last(&mut self) -> Option<RcRefCell<V>> {
        let n = self.tail.borrow_mut().prev.unwrap();
        if self.size == 0 {
            return None;
        }
        self.size -= 1;

        return DLinkList::remove_node(&n);
    }

    fn remove_node(n: &RcRefCell<DNode<V>>) -> Option<RcRefCell<V>> {
        n.borrow_mut().detach();
        return Some(n.borrow().get_val());
    }

    pub fn insert_after(val: V, n: &RcRefCell<DNode<V>>) {
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

impl<V> Default for DLinkList<V> {
    fn default() -> Self {
        DLinkList::new()
    }
}

impl<V> Drop for DLinkList<V> {
    fn drop(&mut self) {
        let mut p = self.head.unwrap();
        loop {
            let next = p.borrow().next.clone();
            if next.is_null() {
                break;
            } else {
                p.borrow_mut().next = NullablePtr::<DNode<V>>::nullptr();
                p = next.unwrap();
            }
        }
        self.tail.borrow_mut().prev = NullablePtr::<DNode<V>>::nullptr();
    }
}

impl<V> IntoIterator for DLinkList<V> {
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
pub struct DLinkListIter<V> {
    list: DLinkList<V>,
    current: RcRefCell<DNode<V>>,
}

impl<V> Iterator for DLinkListIter<V> {
    type Item = RcRefCell<V>;

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

pub struct DLinkListView<V> {
    current: RcRefCell<DNode<V>>,
}

#[allow(dead_code)]
impl<V> DLinkListView<V> {
    fn prev(&self) -> Option<Self> {
        if self.current.borrow().prev.not_null() {
            Some(DLinkListView {
                current: self.current.borrow().prev.unwrap(),
            })
        } else {
            None
        }
    }

    fn next(&self) -> Option<Self> {
        if self.current.borrow().next.not_null() {
            Some(DLinkListView {
                current: self.current.borrow().next.unwrap(),
            })
        } else {
            None
        }
    }

    fn val(&self) -> NullablePtr<V> {
        self.current.borrow().val.clone()
    }
}
