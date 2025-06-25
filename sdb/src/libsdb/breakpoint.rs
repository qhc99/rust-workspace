use std::any::Any;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicI32, Ordering};

use gimli::{DW_AT_low_pc, DW_AT_ranges, DW_TAG_inlined_subroutine};
use typed_builder::TypedBuilder;

use super::dwarf::LineTableExt;

use super::types::FileAddress;

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
    breakpoint: Rc<RefCell<Breakpoint>>,
    function_name: String,
}

impl FunctionBreakpoint {
    pub fn new(
        target: &Rc<Target>,
        function_name: &str,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Result<Self, SdbError> {
        let mut ret = Self {
            breakpoint: Rc::new(RefCell::new(Breakpoint::new(
                target,
                is_hardware,
                is_internal,
            ))),
            function_name: function_name.to_string(),
        };
        ret.resolve()?;
        Ok(ret)
    }

    pub fn resolve(&mut self) -> Result<(), SdbError> {
        let target = self.breakpoint.borrow().target.upgrade().unwrap();
        let found_functions = target.find_functions(&self.function_name)?;
        for die in &found_functions.dwarf_functions {
            if die.contains(DW_AT_low_pc.0 as u64) || die.contains(DW_AT_ranges.0 as u64) {
                let addr: FileAddress =
                    if die.abbrev_entry().tag == DW_TAG_inlined_subroutine.0 as u64 {
                        die.low_pc()?
                    } else {
                        let mut function_line =
                            die.cu().lines().get_entry_by_address(&die.low_pc()?)?;
                        function_line.step()?;
                        function_line.get_current().address.clone()
                    };
                let load_address = addr.to_virt_addr();
                if !self
                    .breakpoint
                    .borrow()
                    .breakpoint_sites
                    .contains_address(load_address)
                {
                    let new_site = target
                        .get_process()
                        .create_breakpoint_site_from_breakpoint(
                            &self.breakpoint,
                            {
                                let ret = self.breakpoint.borrow().next_site_id;
                                self.breakpoint.borrow_mut().next_site_id += 1;
                                ret
                            },
                            load_address,
                            self.breakpoint.borrow().is_hardware,
                            self.breakpoint.borrow().is_internal,
                        )?;
                    let new_site_weak = new_site.clone();
                    let new_site = new_site.upgrade().unwrap();
                    self.breakpoint
                        .borrow_mut()
                        .breakpoint_sites
                        .push_weak(new_site_weak);
                    if self.breakpoint.borrow().is_enabled {
                        new_site.borrow_mut().enable()?;
                    }
                }
            }
        }
        for sym in &found_functions.elf_functions {
            let file_address = FileAddress::new(&sym.0, sym.1.0.st_value);
            let load_address = file_address.to_virt_addr();
            if !self
                .breakpoint
                .borrow()
                .breakpoint_sites
                .contains_address(load_address)
            {
                let new_site = target
                    .get_process()
                    .create_breakpoint_site_from_breakpoint(
                        &self.breakpoint,
                        {
                            let ret = self.breakpoint.borrow().next_site_id;
                            self.breakpoint.borrow_mut().next_site_id += 1;
                            ret
                        },
                        load_address,
                        self.breakpoint.borrow().is_hardware,
                        self.breakpoint.borrow().is_internal,
                    )?;
                let new_site_weak = new_site.clone();
                let new_site = new_site.upgrade().unwrap();
                self.breakpoint
                    .borrow_mut()
                    .breakpoint_sites
                    .push_weak(new_site_weak);
                if self.breakpoint.borrow().is_enabled {
                    new_site.borrow_mut().enable()?;
                }
            }
        }
        Ok(())
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

pub struct LineBreakpoint {
    breakpoint: Rc<RefCell<Breakpoint>>,
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
    ) -> Result<Self, SdbError> {
        let mut ret = Self {
            breakpoint: Rc::new(RefCell::new(Breakpoint::new(
                target,
                is_hardware,
                is_internal,
            ))),
            file: file.to_path_buf(),
            line,
        };
        ret.resolve()?;
        Ok(ret)
    }

    /*
    void sdb::line_breakpoint::resolve() {
        auto& dwarf = target_->get_elf().get_dwarf();
        for (auto& cu : dwarf.compile_units()) {
            auto entries = cu->lines().get_entries_by_line(file_, line_);
            for (auto entry : entries) {
                auto& dwarf = entry->address.elf_file()->get_dwarf();
                auto stack = dwarf.inline_stack_at_address(entry->address);
                auto no_inline_stack = stack.size() == 1;
                auto should_skip_prologue = no_inline_stack and
                (stack[0].contains(DW_AT_ranges) or stack[0].contains(DW_AT_low_pc)) and
                stack[0].low_pc() == entry->address;
                if (should_skip_prologue) {
                    ++entry;
                }
                auto load_address = entry->address.to_virt_addr();
                if (!breakpoint_sites_.contains_address(load_address)) {
                    auto& new_site = target_->get_process()
                    .create_breakpoint_site(
                    this, next_site_id_++, load_address, is_hardware_, is_internal_);
                    breakpoint_sites_.push(&new_site);
                    if (is_enabled_) new_site.enable();
                }
            }
        }
    }
     */
    pub fn resolve(&mut self) -> Result<(), SdbError> {
        let dwarf = self
            .breakpoint
            .borrow()
            .target
            .upgrade()
            .unwrap()
            .get_elf()
            .get_dwarf();
        for cu in dwarf.compile_units().iter() {
            let entries = cu
                .lines()
                .get_entries_by_line(&self.file, self.line as u64)?;
            for mut entry in entries {
                let dwarf = entry.get_current().address.elf_file().get_dwarf();
                let stack = dwarf.inline_stack_at_address(&entry.get_current().address)?;
                let no_inline_stack = stack.len() == 1;
                let should_skip_prologue = no_inline_stack
                    && (stack[0].contains(DW_AT_ranges.0 as u64)
                        || stack[0].contains(DW_AT_low_pc.0 as u64))
                    && stack[0].low_pc()? == entry.get_current().address;
                if should_skip_prologue {
                    entry.step()?;
                }
                let load_address = entry.get_current().address.to_virt_addr();
                if !self
                    .breakpoint
                    .borrow()
                    .breakpoint_sites
                    .contains_address(load_address)
                {
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
                                let ret = self.breakpoint.borrow().next_site_id;
                                self.breakpoint.borrow_mut().next_site_id += 1;
                                ret
                            },
                            load_address,
                            self.breakpoint.borrow().is_hardware,
                            self.breakpoint.borrow().is_internal,
                        )?;
                    let new_site_weak = new_site.clone();
                    let new_site = new_site.upgrade().unwrap();
                    self.breakpoint
                        .borrow_mut()
                        .breakpoint_sites
                        .push_weak(new_site_weak);
                    if self.breakpoint.borrow().is_enabled {
                        new_site.borrow_mut().enable()?;
                    }
                }
            }
        }
        Ok(())
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
                        let ret = self.breakpoint.borrow().next_site_id;
                        self.breakpoint.borrow_mut().next_site_id += 1;
                        ret
                    },
                    self.address,
                    self.breakpoint.borrow().is_hardware,
                    self.breakpoint.borrow().is_internal,
                )?;
            let new_site_weak = new_site.clone();
            let new_site = new_site.upgrade().unwrap();
            self.breakpoint
                .borrow_mut()
                .breakpoint_sites
                .push_weak(new_site_weak);
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
