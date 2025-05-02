use super::process::Process;
use super::types::VirtualAddress;
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
    sync::atomic::AtomicI32,
};

use std::sync::atomic::Ordering;

static NEXT_ID: AtomicI32 = AtomicI32::new(0);

pub fn get_next_id() -> IdType {
    NEXT_ID.fetch_add(1, Ordering::SeqCst) + 1
}

type IdType = i32;

pub struct BreakpointSite {
    process: Weak<RefCell<Process>>,
    address: VirtualAddress,
    is_enabled: bool,
    saved_data: u8,
    id: IdType,
}

impl BreakpointSite {
    fn new(process: &Rc<RefCell<Process>>, addr: VirtualAddress) -> Self {
        Self {
            process: Rc::downgrade(process),
            address: addr,
            is_enabled: false,
            saved_data: 0,
            id: get_next_id(),
        }
    }
    pub fn id(&self) -> IdType {
        self.id
    }

    pub fn disable(&mut self) {}

    pub fn enable(&mut self) {}

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn at_address(&self, addr: VirtualAddress) -> bool {
        self.address == addr
    }

    pub fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        low <= self.address && high > self.address
    }
}
