use super::stoppoint_collection::StoppointCollection;

use super::breakpoint::Breakpoint;

use super::process::Process;
use super::sdb_error::SdbError;
use super::traits::StoppointTrait;
use super::types::VirtualAddress;
use nix::sys::ptrace::{AddressType, read, write};
use std::cell::RefCell;
use std::{
    rc::{Rc, Weak},
    sync::atomic::AtomicI32,
};
use typed_builder::TypedBuilder;

use std::sync::atomic::Ordering;

static NEXT_ID: AtomicI32 = AtomicI32::new(0);

fn get_next_id() -> IdType {
    NEXT_ID.fetch_add(1, Ordering::SeqCst) + 1
}

pub type IdType = i32;

#[derive(Debug, TypedBuilder)]
pub struct BreakpointSite {
    process: Weak<Process>,
    address: VirtualAddress,
    #[builder(default = false)]
    is_enabled: bool,
    #[builder(default = 0)]
    saved_data: u8,
    id: IdType,
    #[builder(default = false)]
    is_hardware: bool,
    #[builder(default = false)]
    is_internal: bool,
    #[builder(default = -1)]
    hardware_register_index: i32,
    #[builder(default = Weak::new())]
    parent: Weak<RefCell<Breakpoint>>,
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
        if self.is_hardware {
            self.hardware_register_index = self
                .process
                .upgrade()
                .unwrap()
                .set_hardware_breakpoint(self.id, self.address)?;
        } else {
            let pid = self.process.upgrade().unwrap().pid();
            let address = self.address.addr() as AddressType;
            let data = read(pid, address).map_err(|errno| {
                SdbError::errno::<()>("Enabling breakpoint site failed", errno).unwrap_err()
            })? as u64;
            self.saved_data = (data & 0xff) as u8;
            let int3: u64 = 0xcc;
            let data_with_int3 = (data & !0xff) | int3;
            write(pid, address, data_with_int3 as i64).map_err(|errno| {
                SdbError::errno::<()>("Enabling breakpoint site failed", errno).unwrap_err()
            })?;
        }
        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        if !self.is_enabled {
            return Ok(());
        }
        if self.is_hardware {
            self.process
                .upgrade()
                .unwrap()
                .clear_hardware_stoppoint(self.hardware_register_index)?;
            self.hardware_register_index = -1;
        } else {
            let pid = self.process.upgrade().unwrap().pid();
            let address = self.address.addr() as AddressType;
            let data = read(pid, address).map_err(|errno| {
                SdbError::errno::<()>("Disabling breakpoint site failed", errno).unwrap_err()
            })? as u64;

            let restored_data = (data & !0xff) | self.saved_data as u64;
            write(pid, address, restored_data as i64).map_err(|errno| {
                SdbError::errno::<()>("Disabling breakpoint site failed", errno).unwrap_err()
            })?;
            self.is_enabled = false;
        }
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        low <= self.address && high > self.address
    }

    fn is_hardware(&self) -> bool {
        self.is_hardware
    }

    fn is_internal(&self) -> bool {
        self.is_internal
    }

    fn breakpoint_sites(&self) -> StoppointCollection {
        unimplemented!()
    }
}

impl BreakpointSite {
    pub fn new(
        process: &Rc<Process>,
        addr: VirtualAddress,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Self {
        let id = if is_internal { -1 } else { get_next_id() };
        Self {
            process: Rc::downgrade(process),
            address: addr,
            is_enabled: false,
            saved_data: 0,
            id,
            is_hardware,
            is_internal,
            hardware_register_index: -1,
            parent: Weak::new(),
        }
    }
    pub fn from_breakpoint(
        parent: &Rc<RefCell<Breakpoint>>,
        id: IdType,
        process: &Rc<Process>,
        addr: VirtualAddress,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Self {
        Self {
            process: Rc::downgrade(process),
            address: addr,
            is_enabled: false,
            saved_data: 0,
            id,
            is_hardware,
            is_internal,
            hardware_register_index: -1,
            parent: Rc::downgrade(parent),
        }
    }

    pub fn saved_data(&self) -> u8 {
        self.saved_data
    }
}
