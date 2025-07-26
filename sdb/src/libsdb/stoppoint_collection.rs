use super::breakpoint_site::IdType;
use super::sdb_error::SdbError;
use super::traits::MaybeRc;
use super::traits::StoppointTrait;
use super::types::VirtualAddress;
use std::rc::Weak;
use std::{cell::RefCell, rc::Rc};

#[derive(Default, Clone)]
pub struct StoppointCollection {
    stoppoints: Vec<Rc<dyn MaybeRc>>,
}

impl StoppointCollection {
    pub fn push_strong<T>(&mut self, bs: Rc<RefCell<T>>) -> Weak<RefCell<T>>
    where
        T: StoppointTrait + ?Sized,
        Rc<RefCell<T>>: MaybeRc,
    {
        let res = bs.clone();
        self.stoppoints.push(Rc::new(bs));
        Rc::downgrade(&res)
    }

    pub fn push_weak<T>(&mut self, bs: Weak<RefCell<T>>) -> Weak<RefCell<T>>
    where
        T: StoppointTrait + ?Sized,
        Weak<RefCell<T>>: MaybeRc,
    {
        let res = bs.upgrade().unwrap();
        self.stoppoints.push(Rc::new(bs));
        Rc::downgrade(&res)
    }

    pub fn contain_id(&self, id: IdType) -> bool {
        self.stoppoints
            .iter()
            .any(|t| t.get_rc().borrow().id() == id)
    }

    pub fn contains_address(&self, address: VirtualAddress) -> bool {
        self.stoppoints
            .iter()
            .any(|t| t.get_rc().borrow().at_address(address))
    }

    pub fn enabled_breakpoint_at_address(&self, address: VirtualAddress) -> bool {
        self.contains_address(address)
            && self.get_by_address(address).unwrap().borrow().is_enabled()
    }

    pub fn get_by_id(&self, id: IdType) -> Result<Rc<RefCell<dyn StoppointTrait>>, SdbError> {
        match self
            .stoppoints
            .iter()
            .find(|t| t.get_rc().borrow().id() == id)
        {
            Some(v) => Ok(v.get_rc()),
            None => SdbError::err("Invalid stoppoint id"),
        }
    }

    pub fn get_by_address(
        &self,
        address: VirtualAddress,
    ) -> Result<Rc<RefCell<dyn StoppointTrait>>, SdbError> {
        match self
            .stoppoints
            .iter()
            .find(|t| t.get_rc().borrow().at_address(address))
        {
            Some(v) => Ok(v.get_rc()),
            None => SdbError::err("Invalid stoppoint id"),
        }
    }

    pub fn remove_by_id(&mut self, id: IdType) -> Result<(), SdbError> {
        if let Some(pos) = self
            .stoppoints
            .iter()
            .position(|s| s.get_rc().borrow().id() == id)
        {
            self.stoppoints[pos].get_rc().borrow_mut().disable()?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn remove_by_address(&mut self, address: VirtualAddress) -> Result<(), SdbError> {
        if let Some(pos) = self
            .stoppoints
            .iter()
            .position(|s| s.get_rc().borrow().at_address(address))
        {
            self.stoppoints[pos].get_rc().borrow_mut().disable()?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn for_each_mut(&mut self, mut f: impl FnMut(&Rc<RefCell<dyn StoppointTrait>>)) {
        self.stoppoints.iter_mut().for_each(|s| f(&s.get_rc()));
    }

    pub fn for_each(&self, f: impl Fn(&Rc<RefCell<dyn StoppointTrait>>)) {
        self.stoppoints
            .iter()
            .map(|s| s.get_rc())
            .for_each(|s| f(&s));
    }

    pub fn size(&self) -> usize {
        self.stoppoints.len()
    }

    pub fn empty(&self) -> bool {
        self.stoppoints.is_empty()
    }

    pub fn get_in_region(
        &self,
        low: VirtualAddress,
        high: VirtualAddress,
    ) -> Vec<Rc<RefCell<dyn StoppointTrait>>> {
        let mut ret: Vec<Rc<RefCell<dyn StoppointTrait>>> = vec![];
        for site in self.stoppoints.iter() {
            if site.get_rc().borrow().in_range(low, high) {
                ret.push(site.get_rc());
            }
        }
        ret
    }

    pub fn iter(&self) -> impl Iterator<Item = Rc<RefCell<dyn StoppointTrait>>> {
        self.stoppoints.iter().map(|s| s.get_rc())
    }
}
