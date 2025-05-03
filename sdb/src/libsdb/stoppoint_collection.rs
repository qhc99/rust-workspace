use super::breakpoint_site::IdType;
use super::types::VirtualAddress;
use std::{cell::RefCell, rc::Rc};

pub struct StoppointCollection<T> {
    stoppoints: Vec<Rc<RefCell<T>>>,
}

impl<T> StoppointCollection<T> {
    pub fn push(&mut self, bs: T) -> Rc<RefCell<T>> {
        let res = Rc::new(RefCell::new(bs));
        self.stoppoints.push(res.clone());
        res
    }

    pub fn contain_id(&self, id: IdType) -> bool {
        todo!()
    }

    pub fn contain_address(&self, address: VirtualAddress) -> bool {
        todo!()
    }

    pub fn enabled_breakpoint_at_address(&self, address: VirtualAddress) -> bool {
        todo!()
    }

    pub fn get_by_id(&self, id: IdType) -> Rc<RefCell<T>> {
        todo!()
    }

    pub fn get_by_address(&self, address: VirtualAddress) -> Rc<RefCell<T>> {
        todo!()
    }

    pub fn remove_by_id(&self, id: IdType) {
        todo!()
    }

    pub fn remove_by_address(&self, address: VirtualAddress) {
        todo!()
    }

    pub fn for_each(&self, f: impl Fn(&Rc<RefCell<T>>)) {}

    pub fn size(&self) -> usize {
        self.stoppoints.len()
    }

    pub fn empty(&self) -> bool {
        self.stoppoints.is_empty()
    }
}

impl<T> Default for StoppointCollection<T> {
    fn default() -> Self {
        Self {
            stoppoints: Default::default(),
        }
    }
}
