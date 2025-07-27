use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicI32, Ordering};

use bytes::Bytes;
use gimli::{
    DW_AT_low_pc, DW_AT_ranges, DW_CFA_advance_loc, DW_CFA_advance_loc1, DW_CFA_advance_loc2,
    DW_CFA_advance_loc4, DW_CFA_def_cfa, DW_CFA_def_cfa_expression, DW_CFA_def_cfa_offset,
    DW_CFA_def_cfa_offset_sf, DW_CFA_def_cfa_register, DW_CFA_def_cfa_sf, DW_CFA_expression,
    DW_CFA_offset, DW_CFA_offset_extended, DW_CFA_offset_extended_sf, DW_CFA_register,
    DW_CFA_remember_state, DW_CFA_restore, DW_CFA_restore_extended, DW_CFA_restore_state,
    DW_CFA_same_value, DW_CFA_set_loc, DW_CFA_undefined, DW_CFA_val_expression, DW_CFA_val_offset,
    DW_CFA_val_offset_sf, DW_EH_PE_absptr, DW_EH_PE_datarel, DW_EH_PE_funcrel, DW_EH_PE_pcrel,
    DW_EH_PE_sdata2, DW_EH_PE_sdata4, DW_EH_PE_sdata8, DW_EH_PE_sleb128, DW_EH_PE_textrel,
    DW_EH_PE_udata2, DW_EH_PE_udata4, DW_EH_PE_udata8, DW_EH_PE_uleb128, DW_TAG_inlined_subroutine,
    DwCfa, DwEhPe,
};
use typed_builder::TypedBuilder;

use super::bit::from_bytes;

use super::dwarf::Cursor;
use super::dwarf::Dwarf;
use super::dwarf::LineTableExt;
use super::dwarf::OffsetRule;
use super::dwarf::RegisterRule;
use super::dwarf::Rule;
use super::dwarf::SameRule;
use super::dwarf::UndefinedRule;
use super::dwarf::UnwindContext;
use super::dwarf::ValOffsetRule;
use super::elf::Elf;
use super::elf::ElfExt;
use super::process::Process;
use super::process::ProcessExt;
use super::register_info::RegisterId;
use super::register_info::register_info_by_dwarf;
use super::registers::RegisterValue;
use super::registers::Registers;
use super::stoppoint_collection::StoppointCollection;
use super::target::Target;
use super::types::FileAddress;
use super::types::FileOffset;
use super::{sdb_error::SdbError, traits::StoppointTrait, types::VirtualAddress};

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
    on_hit: Option<Box<dyn Fn() -> Result<bool, SdbError>>>,
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
            on_hit: None,
        }
    }

    pub fn install_hit_handler<F>(&mut self, on_hit: F)
    where
        F: Fn() -> Result<bool, SdbError> + 'static,
    {
        self.on_hit = Some(Box::new(on_hit));
    }

    pub fn notify_hit(&self) -> Result<bool, SdbError> {
        if let Some(on_hit) = &self.on_hit {
            (*on_hit)()
        } else {
            Ok(false)
        }
    }
}

impl StoppointTrait for Breakpoint {
    fn resolve(&mut self) -> Result<(), SdbError> {
        unimplemented!()
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
                            self.breakpoint.borrow().next_site_id,
                            load_address,
                            self.breakpoint.borrow().is_hardware,
                            self.breakpoint.borrow().is_internal,
                        )?;
                    self.breakpoint.borrow_mut().next_site_id += 1;
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
                        self.breakpoint.borrow().next_site_id,
                        load_address,
                        self.breakpoint.borrow().is_hardware,
                        self.breakpoint.borrow().is_internal,
                    )?;
                self.breakpoint.borrow_mut().next_site_id += 1;
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

    pub fn function_name(&self) -> &str {
        &self.function_name
    }
}

impl StoppointTrait for FunctionBreakpoint {
    fn resolve(&mut self) -> Result<(), SdbError> {
        self.resolve()
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
    line: usize,
}

impl LineBreakpoint {
    pub fn new(
        target: &Rc<Target>,
        file: &Path,
        line: usize,
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

    pub fn resolve(&mut self) -> Result<(), SdbError> {
        let entries = self
            .breakpoint
            .borrow()
            .target
            .upgrade()
            .unwrap()
            .get_line_entries_by_line(&self.file, self.line)?;
        for mut entry in entries {
            let dwarf = entry.get_current().address.rc_elf_file().get_dwarf();
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
                        self.breakpoint.borrow().next_site_id,
                        load_address,
                        self.breakpoint.borrow().is_hardware,
                        self.breakpoint.borrow().is_internal,
                    )?;
                self.breakpoint.borrow_mut().next_site_id += 1;
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

    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn line(&self) -> usize {
        self.line
    }
}

impl StoppointTrait for LineBreakpoint {
    fn resolve(&mut self) -> Result<(), SdbError> {
        self.resolve()
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
    pub breakpoint: Rc<RefCell<Breakpoint>>,
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
                    self.breakpoint.borrow().next_site_id,
                    self.address,
                    self.breakpoint.borrow().is_hardware,
                    self.breakpoint.borrow().is_internal,
                )?;
            self.breakpoint.borrow_mut().next_site_id += 1;
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
    fn resolve(&mut self) -> Result<(), SdbError> {
        self.resolve()
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

#[derive(Debug)]
pub struct CallFrameInformation {
    dwarf: Weak<Dwarf>,
    cie_map: HashMap<u32, Rc<CommonInformationEntry>>,
    eh_hdr: EhHdr,
}

#[derive(Debug, Clone)]
pub struct CommonInformationEntry {
    pub length: u32,
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub fde_has_augmentation: bool,
    pub fde_pointer_encoding: u8,
    pub instructions: Bytes,
}

pub struct FrameDescriptionEntry {
    pub length: u32,
    pub cie: Rc<CommonInformationEntry>,
    pub initial_location: FileAddress,
    pub address_range: u64,
    pub instructions: Bytes,
}

impl CallFrameInformation {
    pub fn new(dwarf: &Rc<Dwarf>, eh_hdr: EhHdr) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            dwarf: Rc::downgrade(dwarf),
            cie_map: HashMap::new(),
            eh_hdr,
        }))
    }
    pub fn dwarf_info(&self) -> Rc<Dwarf> {
        self.dwarf.upgrade().unwrap()
    }

    pub fn get_cie(&mut self, at: FileOffset) -> Result<Rc<CommonInformationEntry>, SdbError> {
        let offset = at.off() as u32;

        let cie = self.cie_map.entry(offset);
        match cie {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let section = at.elf_file().get_section_contents(".eh_frame");
                let start = at.elf_file().file_offset_as_data_pointer(at);
                let cursor = Cursor::new(&start.slice(
                    ..(section.len() + section.as_ptr() as usize - start.as_ptr() as usize),
                ));
                let cie = parse_cie(cursor)?;
                Ok(entry.insert(Rc::new(cie)).clone())
            }
        }
    }

    pub fn unwind(
        &mut self,
        proc: &Process,
        pc: &FileAddress,
        regs: &mut Registers,
    ) -> Result<Registers, SdbError> {
        let fde_start = self.eh_hdr.index(pc)?;
        let eh_frame_end = self
            .dwarf_info()
            .elf_file()
            .get_section_contents(".eh_frame");
        let eh_frame_end = eh_frame_end.as_ptr() as usize + eh_frame_end.len();
        let cursor = Cursor::new(&fde_start.slice(..(eh_frame_end - fde_start.as_ptr() as usize)));
        let fde = parse_fde(self, cursor)?;
        if pc.clone() < fde.initial_location
            || pc.clone()
                >= fde.initial_location.clone() + (fde.address_range as u64).try_into().unwrap()
        {
            return SdbError::err("No unwind information at PC");
        }
        let mut ctx = UnwindContext {
            cursor: Cursor::new(&fde.cie.instructions),
            ..Default::default()
        };
        while !ctx.cursor.finished() {
            execute_cfi_instruction(&self.dwarf_info().elf_file(), &fde, &mut ctx, pc)?;
        }
        ctx.cie_register_rules = ctx.register_rules.clone();
        ctx.cursor = Cursor::new(&fde.instructions);
        ctx.location = fde.initial_location.clone();
        while !ctx.cursor.finished() && ctx.location <= pc.clone() {
            execute_cfi_instruction(&self.dwarf_info().elf_file(), &fde, &mut ctx, pc)?;
        }
        execute_unwind_rules(&mut ctx, regs, proc)
    }
}

#[allow(non_upper_case_globals)]
fn execute_cfi_instruction(
    elf: &Rc<Elf>,
    fde: &FrameDescriptionEntry,
    ctx: &mut UnwindContext,
    _pc: &FileAddress,
) -> Result<(), SdbError> {
    let cie = fde.cie.clone();
    let cur = &mut ctx.cursor;
    let text_section_start = elf.get_section_start_address(".text").unwrap();
    let plt_start = elf
        .get_section_start_address(".got.plt")
        .unwrap_or(FileAddress::null());

    let opcode = cur.u8();
    let primary_opcode = opcode & 0xc0;
    let extended_opcode = opcode & 0x3f;
    if primary_opcode != 0 {
        match DwCfa(primary_opcode) {
            DW_CFA_advance_loc => {
                ctx.location += ((extended_opcode as u64) * cie.code_alignment_factor) as i64;
            }
            DW_CFA_offset => {
                let offset = (cur.uleb128() as i64) * cie.data_alignment_factor;
                ctx.register_rules
                    .insert(extended_opcode as u32, Rule::Offset(OffsetRule { offset }));
            }
            DW_CFA_restore => {
                ctx.register_rules.insert(
                    extended_opcode as u32,
                    ctx.cie_register_rules[&(extended_opcode as u32)].clone(),
                );
            }
            _ => {}
        }
    } else if extended_opcode != 0 {
        match DwCfa(extended_opcode) {
            DW_CFA_set_loc => {
                let current_offset = elf.data_pointer_as_file_offset(&cur.position());
                let loc = parse_eh_frame_pointer(
                    elf,
                    cur,
                    cie.fde_pointer_encoding,
                    current_offset.off(),
                    text_section_start.addr(),
                    plt_start.addr(),
                    fde.initial_location.addr(),
                )?;
                ctx.location = FileAddress::new(elf, loc);
            }
            DW_CFA_advance_loc1 => {
                ctx.location += (cur.u8() as u64 * cie.code_alignment_factor) as i64;
            }
            DW_CFA_advance_loc2 => {
                ctx.location += (cur.u16() as u64 * cie.code_alignment_factor) as i64;
            }
            DW_CFA_advance_loc4 => {
                ctx.location += (cur.u32() as u64 * cie.code_alignment_factor) as i64;
            }
            DW_CFA_def_cfa => {
                ctx.cfa_rule.reg = cur.uleb128() as u32;
                ctx.cfa_rule.offset = cur.uleb128() as i64;
            }
            DW_CFA_def_cfa_sf => {
                ctx.cfa_rule.reg = cur.uleb128() as u32;
                ctx.cfa_rule.offset = cur.sleb128() * cie.data_alignment_factor;
            }
            DW_CFA_def_cfa_register => {
                ctx.cfa_rule.reg = cur.uleb128() as u32;
            }
            DW_CFA_def_cfa_offset => {
                ctx.cfa_rule.offset = cur.uleb128() as i64;
            }
            DW_CFA_def_cfa_offset_sf => {
                ctx.cfa_rule.offset = cur.sleb128() * cie.data_alignment_factor;
            }
            DW_CFA_def_cfa_expression => {
                return SdbError::err("DWARF expressions not yet implemented");
            }
            DW_CFA_undefined => {
                ctx.register_rules
                    .insert(cur.uleb128() as u32, Rule::Undefined(UndefinedRule {}));
            }
            DW_CFA_same_value => {
                ctx.register_rules
                    .insert(cur.uleb128() as u32, Rule::Same(SameRule {}));
            }
            DW_CFA_offset_extended => {
                let reg = cur.uleb128();
                let offset = cur.uleb128() as i64 * cie.data_alignment_factor;
                ctx.register_rules
                    .insert(reg as u32, Rule::Offset(OffsetRule { offset }));
            }
            DW_CFA_offset_extended_sf => {
                let reg = cur.uleb128();
                let offset = cur.sleb128() * cie.data_alignment_factor;
                ctx.register_rules
                    .insert(reg as u32, Rule::Offset(OffsetRule { offset }));
            }
            DW_CFA_val_offset => {
                let reg = cur.uleb128();
                let offset = (cur.uleb128()) as i64 * cie.data_alignment_factor;
                ctx.register_rules
                    .insert(reg as u32, Rule::ValOffset(ValOffsetRule { offset }));
            }
            DW_CFA_val_offset_sf => {
                let reg = cur.uleb128();
                let offset = cur.sleb128() * cie.data_alignment_factor;
                ctx.register_rules
                    .insert(reg as u32, Rule::ValOffset(ValOffsetRule { offset }));
            }
            DW_CFA_register => {
                let reg = cur.uleb128();
                ctx.register_rules.insert(
                    reg as u32,
                    Rule::Register(RegisterRule {
                        reg: (cur.uleb128()) as u32,
                    }),
                );
            }
            DW_CFA_expression => {
                return SdbError::err("DWARF expressions not yet implemented");
            }
            DW_CFA_val_expression => {
                return SdbError::err("DWARF expressions not yet implemented");
            }
            DW_CFA_restore_extended => {
                let reg = cur.uleb128();
                ctx.register_rules
                    .insert(reg as u32, ctx.cie_register_rules[&(reg as u32)].clone());
            }
            DW_CFA_remember_state => {
                ctx.rule_stack
                    .push((ctx.register_rules.clone(), ctx.cfa_rule));
            }
            DW_CFA_restore_state => {
                ctx.register_rules = ctx.rule_stack.last().unwrap().0.clone();
                ctx.cfa_rule = ctx.rule_stack.last().unwrap().1;
                ctx.rule_stack.pop();
            }
            _ => {}
        }
    }
    Ok(())
}

fn execute_unwind_rules(
    ctx: &mut UnwindContext,
    old_regs: &mut Registers,
    proc: &Process,
) -> Result<Registers, SdbError> {
    let mut unwound_regs = old_regs.clone();
    let cfa_reg_info = register_info_by_dwarf(ctx.cfa_rule.reg as i32)?;
    let cfa = match old_regs.read(&cfa_reg_info)? {
        RegisterValue::U64(v) => v,
        _ => return SdbError::err("Unexpected register value type"),
    } + ctx.cfa_rule.offset as u64;
    old_regs.set_cfa(VirtualAddress::new(cfa));
    unwound_regs.write_by_id(RegisterId::rsp, cfa, false)?;
    for (reg, rule) in &ctx.register_rules {
        let reg_info = register_info_by_dwarf(*reg as i32)?;
        match &rule {
            Rule::Undefined(_) => {
                unwound_regs.undefine(reg_info.id)?;
            }
            Rule::Same(_) => {
                // Do nothing.
            }
            Rule::Register(reg) => {
                let other_reg = register_info_by_dwarf(reg.reg as i32)?;
                unwound_regs.write(&reg_info, old_regs.read(&other_reg)?, false)?;
            }
            Rule::Offset(offset) => {
                let addr = VirtualAddress::new(cfa.wrapping_add(offset.offset as u64));
                let value = from_bytes::<u64>(&proc.read_memory(addr, 8)?);
                unwound_regs.write(&reg_info, RegisterValue::U64(value), false)?;
            }
            Rule::ValOffset(val_offset) => {
                let addr = cfa + val_offset.offset as u64;
                unwound_regs.write(&reg_info, RegisterValue::U64(addr), false)?;
            }
            _ => {}
        }
    }
    Ok(unwound_regs)
}

fn parse_cie(mut cursor: Cursor) -> Result<CommonInformationEntry, SdbError> {
    let start = cursor.position();
    let length = cursor.u32() + 4;
    let _id = cursor.u32();
    let version = cursor.u8();
    if !(version == 1 || version == 3 || version == 4) {
        return SdbError::err("Invalid CIE version");
    }

    let augmentation = cursor.string();
    if !augmentation.is_empty() && !augmentation.starts_with('z') {
        return SdbError::err("Invalid CIE augmentation");
    }
    if version == 4 {
        let address_size = cursor.u8();
        let segment_size = cursor.u8();
        if address_size != 8 {
            return SdbError::err("Invalid address size");
        }
        if segment_size != 0 {
            return SdbError::err("Invalid segment size");
        }
    }
    let code_alignment_factor = cursor.uleb128();
    let data_alignment_factor = cursor.sleb128();
    let _return_address_register = if version == 1 {
        cursor.u8() as u64
    } else {
        cursor.uleb128()
    };

    let mut fde_pointer_encoding = DW_EH_PE_udata8.0 | DW_EH_PE_absptr.0;
    for c in augmentation.chars() {
        match c {
            'z' => {
                cursor.uleb128();
            }
            'R' => {
                fde_pointer_encoding = cursor.u8();
            }
            'L' => {
                cursor.u8();
            }
            'P' => {
                let encoding = cursor.u8();
                let _ = parse_eh_frame_pointer_with_base(&mut cursor, encoding, 0)?;
            }
            _ => return SdbError::err("Invalid CIE augmentation"),
        };
    }
    let instructions = cursor
        .position()
        .slice(..(start.as_ptr() as usize + length as usize - cursor.position().as_ptr() as usize));
    let fde_has_augmentation = !augmentation.is_empty();
    let ret = CommonInformationEntry {
        length,
        code_alignment_factor,
        data_alignment_factor,
        fde_has_augmentation,
        fde_pointer_encoding,
        instructions,
    };
    Ok(ret)
}

fn parse_eh_frame_pointer_with_base(
    cursor: &mut Cursor,
    encoding: u8,
    base: u64,
) -> Result<u64, SdbError> {
    #[allow(non_upper_case_globals)]
    match DwEhPe(encoding & 0x0f) {
        DW_EH_PE_absptr => Ok(base + cursor.u64()),
        DW_EH_PE_uleb128 => Ok(base + cursor.uleb128()),
        DW_EH_PE_udata2 => Ok(base + cursor.u16() as u64),
        DW_EH_PE_udata4 => Ok(base + cursor.u32() as u64),
        DW_EH_PE_udata8 => Ok(base + cursor.u64()),
        DW_EH_PE_sleb128 => Ok((base as i64 + cursor.sleb128()) as u64),
        DW_EH_PE_sdata2 => Ok((base as i16 + cursor.s16()) as u64),
        DW_EH_PE_sdata4 => Ok((base as i32 + cursor.s32()) as u64),
        DW_EH_PE_sdata8 => Ok((base as i64 + cursor.s64()) as u64),
        _ => SdbError::err("Unknown eh_frame pointer encoding"),
    }
}

fn parse_eh_frame_pointer(
    _elf: &Rc<Elf>,
    cursor: &mut Cursor,
    encoding: u8,
    pc: u64,
    text_section_start: u64,
    data_section_start: u64,
    func_start: u64,
) -> Result<u64, SdbError> {
    #[allow(non_upper_case_globals)]
    let base = match DwEhPe(encoding & 0x70) {
        DW_EH_PE_absptr => 0,
        DW_EH_PE_pcrel => pc,
        DW_EH_PE_textrel => text_section_start,
        DW_EH_PE_datarel => data_section_start,
        DW_EH_PE_funcrel => func_start,
        _ => return SdbError::err("Unknown eh_frame pointer encoding"),
    };
    parse_eh_frame_pointer_with_base(cursor, encoding, base)
}

fn parse_fde(
    cfi: &mut CallFrameInformation,
    mut cursor: Cursor,
) -> Result<FrameDescriptionEntry, SdbError> {
    let start = cursor.position();
    let length = cursor.u32() + 4;
    let elf = cfi.dwarf_info().elf_file();
    let mut current_offset = elf.data_pointer_as_file_offset(&cursor.position());
    let cie_offset = FileOffset::new(&elf, (current_offset.off() as i32 - cursor.s32()) as u64);
    let cie = cfi.get_cie(cie_offset)?;
    current_offset = elf.data_pointer_as_file_offset(&cursor.position());
    let text_section_start = elf
        .get_section_start_address(".text")
        .unwrap_or(FileAddress::null());
    let initial_location_addr = parse_eh_frame_pointer(
        &elf,
        &mut cursor,
        cie.fde_pointer_encoding,
        current_offset.off(),
        text_section_start.addr(),
        0,
        0,
    )?;
    let initial_location = FileAddress::new(&elf, initial_location_addr);
    let address_range = parse_eh_frame_pointer_with_base(&mut cursor, cie.fde_pointer_encoding, 0)?;
    if cie.fde_has_augmentation {
        let augmentation_length = cursor.uleb128() as usize;
        cursor += augmentation_length;
    }
    let instructions = cursor
        .position()
        .slice(..(start.as_ptr() as usize + length as usize - cursor.position().as_ptr() as usize));
    Ok(FrameDescriptionEntry {
        length,
        cie,
        initial_location,
        address_range,
        instructions,
    })
}

#[derive(Debug)]
pub struct EhHdr {
    start: Bytes,
    search_table: Bytes,
    count: usize,
    encoding: u8,
    parent: Option<Rc<RefCell<CallFrameInformation>>>,
}

impl EhHdr {
    pub fn index(&self, file_addr: &FileAddress) -> Result<Bytes, SdbError> {
        let elf = file_addr.rc_elf_file();
        let text_section_start = elf.get_section_start_address(".text").unwrap();
        let encoding_size = eh_frame_pointer_encoding_size(self.encoding)?;
        let row_size = encoding_size * 2;
        let mut low = 0;
        let mut high = self.count - 1;
        while low <= high {
            let mid = (low + high) / 2;
            let mut cursor = Cursor::new(
                &self
                    .search_table
                    .slice(mid * row_size..self.count * row_size),
            );
            let current_offset = elf.data_pointer_as_file_offset(&cursor.position());
            let eh_hdr_offset = elf.data_pointer_as_file_offset(&self.start);
            let entry_address = parse_eh_frame_pointer(
                &elf,
                &mut cursor,
                self.encoding,
                current_offset.off(),
                text_section_start.addr(),
                eh_hdr_offset.off(),
                0,
            )?;
            if entry_address < file_addr.addr() {
                low = mid + 1;
            } else if entry_address > file_addr.addr() {
                if mid == 0 {
                    return SdbError::err("Address not found in eh_hdr");
                }
                high = mid - 1;
            } else {
                high = mid;
                break;
            }
        }
        let mut cursor = Cursor::new(
            &self
                .search_table
                .slice(high * row_size + encoding_size..self.count * row_size),
        );
        let current_offset = elf.data_pointer_as_file_offset(&cursor.position());
        let eh_hdr_offset = elf.data_pointer_as_file_offset(&self.start);
        let fde_offset_int = parse_eh_frame_pointer(
            &elf,
            &mut cursor,
            self.encoding,
            current_offset.off(),
            text_section_start.addr(),
            eh_hdr_offset.off(),
            0,
        )
        .unwrap();
        let fde_offset = FileOffset::new(&elf, fde_offset_int);
        return Ok(elf.file_offset_as_data_pointer(fde_offset));
    }
}

pub fn parse_eh_hdr(dwarf: &Rc<Dwarf>) -> Result<EhHdr, SdbError> {
    let elf = dwarf.elf_file();
    let _eh_hdr_start = elf.get_section_start_address(".eh_frame_hdr").unwrap();
    let _text_section_start = elf.get_section_start_address(".text").unwrap();
    let eh_hdr_data = elf.get_section_contents(".eh_frame_hdr");
    let mut cursor = Cursor::new(&eh_hdr_data);
    let start = cursor.position();
    let _version = cursor.u8();
    let eh_frame_ptr_enc = cursor.u8();
    let fde_count_enc = cursor.u8();
    let table_enc = cursor.u8();
    let _ = parse_eh_frame_pointer_with_base(&mut cursor, eh_frame_ptr_enc, 0);
    let fde_count = parse_eh_frame_pointer_with_base(&mut cursor, fde_count_enc, 0)?;
    let search_table = cursor.position();
    Ok(EhHdr {
        start,
        search_table,
        count: fde_count as usize,
        encoding: table_enc,
        parent: None,
    })
}

fn eh_frame_pointer_encoding_size(encoding: u8) -> Result<usize, SdbError> {
    #[allow(non_upper_case_globals)]
    match DwEhPe(encoding & 0x7) {
        DW_EH_PE_absptr => Ok(8),
        DW_EH_PE_udata2 => Ok(2),
        DW_EH_PE_udata4 => Ok(4),
        DW_EH_PE_udata8 => Ok(8),
        _ => SdbError::err("Invalid pointer encoding"),
    }
}
