use crate::rc_refcell_option::{create_nullable_ptr, mut_ref_data, unwrap_copy_ptr, NullablePtr};
use std::{borrow::BorrowMut, ops::Deref, rc::Rc};

use crate::rc_refcell_option::Pointer;

struct DNode<T>
where
    T: std::fmt::Debug,
{
    pub val: Option<T>,
    pub prev: NullablePtr<DNode<T>>,
    pub next: NullablePtr<DNode<T>>,
}

impl<T> DNode<T>
where
    T: std::fmt::Debug,
{
    fn new(val: T) -> Self {
        Self {
            val: Some(val),
            prev: None,
            next: None,
        }
    }

    fn empty() -> Self {
        Self {
            val: None,
            prev: None,
            next: None,
        }
    }

    fn detach(&mut self) {
        let p = unwrap_copy_ptr(&self.prev);
        let n = unwrap_copy_ptr(&self.next);
        p.deref().borrow_mut().next = Some(n.clone());
        n.deref().borrow_mut().prev = Some(p);
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
        let head = create_nullable_ptr(DNode::empty());
        let tail = create_nullable_ptr(DNode::empty());

        let h = unwrap_copy_ptr(&head);
        let t = unwrap_copy_ptr(&tail);

        mut_ref_data(&h).next = tail.clone();
        mut_ref_data(&t).next = head.clone();

        mut_ref_data(&h).prev = tail.clone();
        mut_ref_data(&t).prev = head.clone();
        return DLinkList { head, tail };
    }

    pub fn insert_head(&mut self, val: T) {
        self.insert_after(val, self.head.clone().unwrap());
    }

    fn insert_after(&mut self, val: T, at: Pointer<DNode<T>>) {
        let in_node = DNode::new(val);
        let in_node_ptr = create_nullable_ptr(in_node);

        let n = at;
        let n_next = n.deref().borrow().next.clone().unwrap();

        mut_ref_data(&n).next = in_node_ptr.clone();
        n_next.deref().borrow_mut().prev = in_node_ptr.clone();

        let node = unwrap_copy_ptr(&in_node_ptr);
        let mut node = mut_ref_data(&node);
        node.prev = Some(n);
        node.next = Some(n_next);
    }

    pub fn insert_tail(&mut self, val: T) {
        let at = self
            .tail
            .clone()
            .unwrap()
            .deref()
            .borrow()
            .prev
            .clone()
            .unwrap();
        self.insert_after(val, at);
    }
}

impl<Val> Drop for DLinkList<Val>
where
    Val: std::fmt::Debug,
{
    fn drop(&mut self) {
        let mut p = unwrap_copy_ptr(&self.head);
        let mut p1 = unwrap_copy_ptr(&mut_ref_data(&p).prev);
        println!("start drop dlink list");
        loop {
            mut_ref_data(&p1).next = None;
            p1 = p.clone();
            if p.deref().borrow().next == None {
                break;
            } else {
                let t = unwrap_copy_ptr(&mut_ref_data(&p).next);
                p = t;
            }
        }
        let p = unwrap_copy_ptr(&self.head);
        mut_ref_data(&p).prev = None;
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
