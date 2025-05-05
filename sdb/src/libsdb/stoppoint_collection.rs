use super::breakpoint_site::IdType;
use super::sdb_error::SdbError;
use super::traits::StoppointTrait;
use super::types::VirtualAddress;
use std::{cell::RefCell, rc::Rc};

pub struct StoppointCollection<T: StoppointTrait> {
    stoppoints: Vec<Rc<RefCell<T>>>,
}

impl<T: StoppointTrait> StoppointCollection<T> {
    pub fn push(&mut self, bs: T) -> Rc<RefCell<T>> {
        let res = Rc::new(RefCell::new(bs));
        self.stoppoints.push(res.clone());
        res
    }

    pub fn contain_id(&self, id: IdType) -> bool {
        self.stoppoints
            .iter()
            .find(|t| t.borrow().id() == id)
            .is_some()
    }

    pub fn contain_address(&self, address: VirtualAddress) -> bool {
        self.stoppoints
            .iter()
            .find(|t| t.borrow().at_address(address))
            .is_some()
    }

    pub fn enabled_breakpoint_at_address(&self, address: VirtualAddress) -> bool {
        self.contain_address(address)
            && self
                .get_by_address(address)
                .unwrap()
                .borrow()
                .at_address(address)
    }

    pub fn get_by_id(&self, id: IdType) -> Result<Rc<RefCell<T>>, SdbError> {
        match self
            .stoppoints
            .iter()
            .find(|t| t.borrow().id() == id)
            .cloned()
        {
            Some(v) => Ok(v),
            None => SdbError::err("Invalid stoppoint id"),
        }
    }

    pub fn get_by_address(&self, address: VirtualAddress) -> Result<Rc<RefCell<T>>, SdbError> {
        match self
            .stoppoints
            .iter()
            .find(|t| t.borrow().at_address(address))
            .cloned()
        {
            Some(v) => Ok(v),
            None => SdbError::err("Invalid stoppoint id"),
        }
    }

    pub fn remove_by_id(&mut self, id: IdType) -> Result<(), SdbError> {
        if let Some(pos) = self.stoppoints.iter().position(|s| s.borrow().id() == id) {
            self.stoppoints[pos].borrow_mut().disable()?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn remove_by_address(&mut self, address: VirtualAddress) -> Result<(), SdbError> {
        if let Some(pos) = self
            .stoppoints
            .iter()
            .position(|s| s.borrow().at_address(address))
        {
            self.stoppoints[pos].borrow_mut().disable()?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn for_each_mut(&mut self, mut f: impl FnMut(&Rc<RefCell<T>>)) {
        self.stoppoints.iter_mut().for_each(|s| f(s));
    }

    pub fn for_each(&self, f: impl Fn(&Rc<RefCell<T>>)) {
        self.stoppoints.iter().for_each(|s| f(s));
    }

    pub fn size(&self) -> usize {
        self.stoppoints.len()
    }

    pub fn empty(&self) -> bool {
        self.stoppoints.is_empty()
    }
}

impl<T: StoppointTrait> Default for StoppointCollection<T> {
    fn default() -> Self {
        Self {
            stoppoints: Default::default(),
        }
    }
}
