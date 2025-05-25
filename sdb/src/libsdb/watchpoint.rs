use bytemuck::bytes_of_mut;

use super::breakpoint_site::IdType;
use super::process::Process;
use super::sdb_error::SdbError;
use super::traits::StoppointTrait;
use super::types::{StoppointMode, VirtualAddress};
use std::mem::swap;
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::{cell::RefCell, rc::Weak};

static NEXT_ID: AtomicI32 = AtomicI32::new(0);

fn get_next_id() -> IdType {
    NEXT_ID.fetch_add(1, Ordering::SeqCst) + 1
}

#[derive(Debug)]
pub struct WatchPoint {
    id: IdType,
    process: Weak<RefCell<Process>>,
    address: VirtualAddress,
    mode: StoppointMode,
    size: usize,
    is_enabled: bool,
    hardware_register_index: i32, // -1
    data: u64,
    previous_data: u64,
}

impl StoppointTrait for WatchPoint {
    fn id(&self) -> IdType {
        self.id
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        if self.is_enabled {
            return Ok(());
        }
        self.hardware_register_index = self.process.upgrade().unwrap().borrow().set_watchpoint(
            self.id,
            self.address,
            self.mode,
            self.size,
        )?;
        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        if !self.is_enabled {
            return Ok(());
        }
        self.process
            .upgrade()
            .unwrap()
            .borrow()
            .clear_hardware_stoppoint(self.hardware_register_index)?;
        self.is_enabled = false;
        Ok(())
    }

    fn address(&self) -> VirtualAddress {
        self.address
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn at_address(&self, address: VirtualAddress) -> bool {
        self.address == address
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        self.address >= low && self.address < high
    }
}

impl WatchPoint {
    pub fn new(
        process: &Rc<RefCell<Process>>,
        address: VirtualAddress,
        mode: StoppointMode,
        size: usize,
    ) -> Result<Self, SdbError> {
        if (address.get_addr() as usize & (size - 1)) != 0 {
            return SdbError::err("Watchpoint must be aligned to size");
        }
        let mut ret = Self {
            id: get_next_id(),
            process: Rc::downgrade(process),
            address,
            mode,
            size,
            is_enabled: false,
            hardware_register_index: -1,
            data: 0,
            previous_data: 0,
        };
        ret.update_data()?;
        Ok(ret)
    }

    pub fn mode(&self) -> StoppointMode {
        self.mode
    }
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn data(&self) -> u64 {
        self.data
    }
    pub fn previous_data(&self) -> u64 {
        self.previous_data
    }

    pub fn update_data(&mut self) -> Result<(), SdbError> {
        let mut new_data = 0u64;
        let read = self
            .process
            .upgrade()
            .unwrap()
            .borrow()
            .read_memory(self.address, self.size)?;
        bytes_of_mut(&mut new_data)[..self.size].copy_from_slice(&read[..self.size]);
        swap(&mut self.data, &mut self.previous_data);
        Ok(())
    }
}
