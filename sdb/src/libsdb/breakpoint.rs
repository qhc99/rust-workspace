use std::any::Any;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicI32, Ordering};

use typed_builder::TypedBuilder;

use super::process::ProcessExt;

use super::traits::BreakpointType;

use super::stoppoint_collection::StoppointCollection;

use super::{sdb_error::SdbError, traits::StoppointTrait, types::VirtualAddress};

use super::target::Target;

pub type IdType = i32;

static NEXT_ID: AtomicI32 = AtomicI32::new(0);

fn get_next_id() -> IdType {
    NEXT_ID.fetch_add(1, Ordering::SeqCst) + 1
}

#[derive(TypedBuilder)]
pub struct Breakpoint {
    id: IdType,
    target: Weak<Target>,
    #[builder(default = false)]
    is_enabled: bool,
    #[builder(default = false)]
    is_hardware: bool,
    #[builder(default = false)]
    is_internal: bool,
    breakpoint_sites: StoppointCollection,
    #[builder(default = 1)]
    next_site_id: IdType,
}

impl Breakpoint {
    pub fn new(target: &Rc<Target>, is_hardware: bool, is_internal: bool) -> Self {
        let id = if is_internal { -1 } else { get_next_id() };
        Self {
            id,
            target: Rc::downgrade(target),
            is_enabled: false,
            is_hardware,
            is_internal,
            breakpoint_sites: StoppointCollection::default(),
            next_site_id: 1,
        }
    }
}

impl StoppointTrait for Breakpoint {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn breakpoint_type(&self) -> BreakpointType {
        BreakpointType::BreakPoint
    }

    fn id(&self) -> IdType {
        self.id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        self.breakpoint_sites.contains_address(addr)
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        self.is_enabled = false;
        for i in self.breakpoint_sites.iter() {
            i.borrow_mut().disable()?;
        }
        Ok(())
    }

    fn address(&self) -> VirtualAddress {
        unimplemented!()
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        self.is_enabled = true;
        for i in self.breakpoint_sites.iter() {
            i.borrow_mut().enable()?;
        }
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        !self.breakpoint_sites.get_in_region(low, high).is_empty()
    }

    fn is_hardware(&self) -> bool {
        self.is_hardware
    }

    fn is_internal(&self) -> bool {
        self.is_internal
    }

    fn breakpoint_sites(&self) -> StoppointCollection {
        self.breakpoint_sites.clone()
    }
}

pub struct FunctionBreakpoint {
    breakpoint: Breakpoint,
    function_name: String,
}

impl FunctionBreakpoint {
    pub fn new(
        target: &Rc<Target>,
        function_name: &str,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Self {
        let mut ret = Self {
            breakpoint: Breakpoint::new(target, is_hardware, is_internal),
            function_name: function_name.to_string(),
        };
        ret.resolve();
        ret
    }

    pub fn resolve(&mut self) {
        todo!()
    }

    fn function_name(&self) -> &str {
        &self.function_name
    }
}

impl StoppointTrait for FunctionBreakpoint {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn breakpoint_type(&self) -> BreakpointType {
        BreakpointType::FunctionBreakPoint
    }

    fn id(&self) -> IdType {
        self.breakpoint.id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        self.breakpoint.at_address(addr)
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        self.breakpoint.disable()
    }

    fn address(&self) -> VirtualAddress {
        self.breakpoint.address()
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        self.breakpoint.enable()
    }

    fn is_enabled(&self) -> bool {
        self.breakpoint.is_enabled()
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        self.breakpoint.in_range(low, high)
    }

    fn is_hardware(&self) -> bool {
        self.breakpoint.is_hardware()
    }

    fn is_internal(&self) -> bool {
        self.breakpoint.is_internal()
    }

    fn breakpoint_sites(&self) -> StoppointCollection {
        self.breakpoint.breakpoint_sites()
    }
}

pub struct LineBreakpoint {
    breakpoint: Breakpoint,
    file: PathBuf,
    line: u32,
}

impl LineBreakpoint {
    pub fn new(
        target: &Rc<Target>,
        file: &Path,
        line: u32,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Self {
        let mut ret = Self {
            breakpoint: Breakpoint::new(target, is_hardware, is_internal),
            file: file.to_path_buf(),
            line,
        };
        ret.resolve();
        ret
    }

    pub fn resolve(&mut self) {
        todo!()
    }

    fn file(&self) -> &Path {
        &self.file
    }

    fn line(&self) -> u32 {
        self.line
    }
}

impl StoppointTrait for LineBreakpoint {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn breakpoint_type(&self) -> BreakpointType {
        BreakpointType::LineBreakPoint
    }

    fn id(&self) -> IdType {
        self.breakpoint.id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        self.breakpoint.at_address(addr)
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        self.breakpoint.disable()
    }

    fn address(&self) -> VirtualAddress {
        self.breakpoint.address()
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        self.breakpoint.enable()
    }

    fn is_enabled(&self) -> bool {
        self.breakpoint.is_enabled()
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        self.breakpoint.in_range(low, high)
    }

    fn is_hardware(&self) -> bool {
        self.breakpoint.is_hardware()
    }

    fn is_internal(&self) -> bool {
        self.breakpoint.is_internal()
    }

    fn breakpoint_sites(&self) -> StoppointCollection {
        self.breakpoint.breakpoint_sites()
    }
}

pub struct AddressBreakpoint {
    breakpoint: Rc<RefCell<Breakpoint>>,
    address: VirtualAddress,
}

impl AddressBreakpoint {
    pub fn new(
        target: &Rc<Target>,
        address: VirtualAddress,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Result<Self, SdbError> {
        let mut ret = Self {
            breakpoint: Rc::new(RefCell::new(Breakpoint::new(
                target,
                is_hardware,
                is_internal,
            ))),
            address,
        };
        ret.resolve()?;
        Ok(ret)
    }

    pub fn resolve(&mut self) -> Result<(), SdbError> {
        if self.breakpoint.borrow().breakpoint_sites.empty() {
            let new_site = self
                .breakpoint
                .borrow()
                .target
                .upgrade()
                .unwrap()
                .get_process()
                .create_breakpoint_site_from_breakpoint(
                    &self.breakpoint,
                    {
                        self.breakpoint.borrow_mut().next_site_id += 1;
                        self.breakpoint.borrow().next_site_id
                    },
                    self.address,
                    self.breakpoint.borrow().is_hardware,
                    self.breakpoint.borrow().is_internal,
                )?;
            self.breakpoint
                .borrow_mut()
                .breakpoint_sites
                .push_strong(new_site.clone());
            if self.breakpoint.borrow().is_enabled {
                new_site.borrow_mut().enable()?;
            }
        }
        Ok(())
    }

    fn address(&self) -> VirtualAddress {
        self.address
    }
}

impl StoppointTrait for AddressBreakpoint {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn breakpoint_type(&self) -> BreakpointType {
        BreakpointType::AddressBreakPoint
    }

    fn id(&self) -> IdType {
        self.breakpoint.borrow().id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        self.breakpoint.borrow().at_address(addr)
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        self.breakpoint.borrow_mut().disable()
    }

    fn address(&self) -> VirtualAddress {
        self.breakpoint.borrow().address()
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        self.breakpoint.borrow_mut().enable()
    }

    fn is_enabled(&self) -> bool {
        self.breakpoint.borrow().is_enabled()
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        self.breakpoint.borrow().in_range(low, high)
    }

    fn is_hardware(&self) -> bool {
        self.breakpoint.borrow().is_hardware()
    }

    fn is_internal(&self) -> bool {
        self.breakpoint.borrow().is_internal()
    }

    fn breakpoint_sites(&self) -> StoppointCollection {
        self.breakpoint.borrow().breakpoint_sites()
    }
}
