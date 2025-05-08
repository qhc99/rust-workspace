use super::process::Process;
use super::sdb_error::SdbError;
use super::traits::StoppointTrait;
use super::types::VirtualAddress;
use nix::sys::ptrace::{AddressType, read, write};
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

pub type IdType = i32;

#[derive(Debug)]
pub struct BreakpointSite {
    process: Weak<RefCell<Process>>,
    address: VirtualAddress,
    is_enabled: bool,
    saved_data: u8,
    id: IdType,
}

impl StoppointTrait for BreakpointSite {
    fn id(&self) -> IdType {
        self.id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        self.address == addr
    }

    fn address(&self) -> VirtualAddress {
        self.address
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        if self.is_enabled {
            return Ok(());
        }
        let pid = self.process.upgrade().unwrap().borrow().pid();
        let address = self.address.get_addr() as AddressType;
        let data = read(pid, address).map_err(|errno| {
            SdbError::errno::<()>("Enabling breakpoint site failed", errno).unwrap_err()
        })? as u64;
        self.saved_data = (data & 0xff) as u8;
        let int3: u64 = 0xcc;
        let data_with_int3 = (data & !0xff) | int3;
        write(pid, address, data_with_int3 as i64).map_err(|errno| {
            SdbError::errno::<()>("Enabling breakpoint site failed", errno).unwrap_err()
        })?;
        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        if !self.is_enabled {
            return Ok(());
        }
        let pid = self.process.upgrade().unwrap().borrow().pid();
        let address = self.address.get_addr() as AddressType;
        let data = read(pid, address).map_err(|errno| {
            SdbError::errno::<()>("Disabling breakpoint site failed", errno).unwrap_err()
        })? as u64;

        let restored_data = (data & !0xff) | self.saved_data as u64;
        write(pid, address, restored_data as i64).map_err(|errno| {
            SdbError::errno::<()>("Disabling breakpoint site failed", errno).unwrap_err()
        })?;
        self.is_enabled = false;
        Ok(())
    }
}

impl BreakpointSite {
    pub fn new(process: &Rc<RefCell<Process>>, addr: VirtualAddress) -> Self {
        Self {
            process: Rc::downgrade(process),
            address: addr,
            is_enabled: false,
            saved_data: 0,
            id: get_next_id(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        low <= self.address && high > self.address
    }
}
