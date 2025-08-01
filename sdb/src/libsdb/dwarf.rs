use std::cell::{OnceCell, Ref, RefCell};
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::rc::Weak;
use std::{collections::HashMap, ops::AddAssign, rc::Rc};

use bytemuck::Pod;
use bytes::Bytes;
use gimli::{
    DW_AT_abstract_origin, DW_AT_call_file, DW_AT_call_line, DW_AT_comp_dir, DW_AT_decl_file,
    DW_AT_decl_line, DW_AT_high_pc, DW_AT_low_pc, DW_AT_name, DW_AT_ranges, DW_AT_sibling,
    DW_AT_specification, DW_AT_stmt_list, DW_FORM_addr, DW_FORM_block, DW_FORM_block1,
    DW_FORM_block2, DW_FORM_block4, DW_FORM_data1, DW_FORM_data2, DW_FORM_data4, DW_FORM_data8,
    DW_FORM_exprloc, DW_FORM_flag, DW_FORM_flag_present, DW_FORM_indirect, DW_FORM_ref_addr,
    DW_FORM_ref_udata, DW_FORM_ref1, DW_FORM_ref2, DW_FORM_ref4, DW_FORM_ref8, DW_FORM_sdata,
    DW_FORM_sec_offset, DW_FORM_string, DW_FORM_strp, DW_FORM_udata, DW_LNE_define_file,
    DW_LNE_end_sequence, DW_LNE_set_address, DW_LNE_set_discriminator, DW_LNS_advance_line,
    DW_LNS_advance_pc, DW_LNS_const_add_pc, DW_LNS_copy, DW_LNS_fixed_advance_pc,
    DW_LNS_negate_stmt, DW_LNS_set_basic_block, DW_LNS_set_column, DW_LNS_set_epilogue_begin,
    DW_LNS_set_file, DW_LNS_set_isa, DW_LNS_set_prologue_end, DW_TAG_inlined_subroutine,
    DW_TAG_subprogram, DwForm, DwLne, DwLns,
};
use multimap::MultiMap;
use typed_builder::TypedBuilder;

use super::process::Process;
use super::registers::Registers;
use super::breakpoint::{CallFrameInformation, parse_eh_hdr};
use super::bit::from_bytes;
use super::elf::Elf;
use super::sdb_error::SdbError;
use super::types::FileAddress;

type AbbrevTable = HashMap<u64, Rc<Abbrev>>;

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: Rc<LineTableFile>,
    pub line: u64,
}

#[derive(Debug, Clone, TypedBuilder, Default)]
pub struct LineTableEntry {
    #[builder(default = FileAddress::null())]
    pub address: FileAddress,
    #[builder(default = 1)]
    pub file_index: u64,
    #[builder(default = 1)]
    pub line: u64,
    #[builder(default = 0)]
    pub column: u64,
    #[builder(default = false)]
    pub is_stmt: bool,
    #[builder(default = false)]
    pub basic_block_start: bool,
    #[builder(default = false)]
    pub end_sequence: bool,
    #[builder(default = false)]
    pub prologue_end: bool,
    #[builder(default = false)]
    pub epilogue_begin: bool,
    #[builder(default = 0)]
    pub discriminator: u64,
    #[builder(default = None)]
    pub file_entry: Option<Rc<LineTableFile>>,
}

impl PartialEq for LineTableEntry {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.file_index == other.file_index
            && self.line == other.line
            && self.column == other.column
            && self.discriminator == other.discriminator
    }
}

impl Eq for LineTableEntry {}

#[derive(Debug, Clone, Default)]
pub struct LineTableIter {
    table: Rc<LineTable>,
    current: Option<LineTableEntry>,
    registers: LineTableEntry,
    pos: Bytes,
}

impl PartialEq for LineTableIter {
    fn eq(&self, other: &Self) -> bool {
        self.current == other.current && self.pos == other.pos
    }
}

impl LineTableIter {
    pub fn new(table: &Rc<LineTable>) -> Result<Self, SdbError> {
        let registers = LineTableEntry::builder()
            .is_stmt(table.default_is_stmt)
            .build();
        let mut ret = Self {
            table: table.clone(),
            current: None,
            registers,
            pos: table.data.clone(),
        };
        ret.step()?;
        Ok(ret)
    }

    pub fn step(&mut self) -> Result<(), SdbError> {
        if self.pos.is_empty() {
            self.pos = Bytes::new();
            return Ok(());
        }
        let mut emitted;
        loop {
            emitted = self.execute_instruction()?;
            if emitted {
                break;
            }
        }
        self.current.as_mut().unwrap().file_entry = Some(Rc::new(
            self.table.file_names()[self.get_current().file_index as usize - 1].clone(),
        ));
        Ok(())
    }

    pub fn is_end(&self) -> bool {
        self.pos.is_empty()
    }

    pub fn get_current(&self) -> &LineTableEntry {
        self.current.as_ref().unwrap()
    }

    #[allow(non_upper_case_globals)]
    pub fn execute_instruction(&mut self) -> Result<bool, SdbError> {
        let elf = self.table.cu().dwarf_info().elf_file();
        let mut cursor = Cursor::new(&self.pos.slice(
            ..(self.table.data.as_ptr() as usize + self.table.data.len()
                - self.pos.as_ptr() as usize),
        ));
        let opcode = cursor.u8();
        let mut emitted = false;
        if opcode > 0 && opcode < self.table.opcode_base {
            match DwLns(opcode) {
                DW_LNS_copy => {
                    self.current = Some(self.registers.clone());
                    self.registers.basic_block_start = false;
                    self.registers.prologue_end = false;
                    self.registers.epilogue_begin = false;
                    self.registers.discriminator = 0;
                    emitted = true;
                }
                DW_LNS_advance_pc => {
                    self.registers.address += cursor.uleb128() as i64;
                }
                DW_LNS_advance_line => {
                    self.registers.line =
                        (self.registers.line as i64).wrapping_add(cursor.sleb128()) as u64;
                }
                DW_LNS_set_file => {
                    self.registers.file_index = cursor.uleb128();
                }
                DW_LNS_set_column => {
                    self.registers.column = cursor.uleb128();
                }
                DW_LNS_negate_stmt => {
                    self.registers.is_stmt = !self.registers.is_stmt;
                }
                DW_LNS_set_basic_block => {
                    self.registers.basic_block_start = true;
                }
                DW_LNS_const_add_pc => {
                    self.registers.address +=
                        ((255 - self.table.opcode_base) / self.table.line_range) as i64;
                }
                DW_LNS_fixed_advance_pc => {
                    self.registers.address += cursor.u16() as i64;
                }
                DW_LNS_set_prologue_end => {
                    self.registers.prologue_end = true;
                }
                DW_LNS_set_epilogue_begin => {
                    self.registers.epilogue_begin = true;
                }
                DW_LNS_set_isa => {
                    // Do nothing
                }
                _ => {
                    return SdbError::err("Unexpected standard opcode");
                }
            }
        } else if opcode == 0 {
            let _length = cursor.uleb128();
            let extended_opcode = cursor.u8();
            match DwLne(extended_opcode) {
                DW_LNE_end_sequence => {
                    self.registers.end_sequence = true;
                    self.current = Some(self.registers.clone());
                    self.registers = LineTableEntry::builder()
                        .is_stmt(self.table.default_is_stmt)
                        .build();
                    emitted = true;
                }
                DW_LNE_set_address => {
                    self.registers.address = FileAddress::new(&elf, cursor.u64());
                }
                DW_LNE_define_file => {
                    let compilation_dir = self
                        .table
                        .cu()
                        .root()
                        .index(DW_AT_comp_dir.0 as u64)?
                        .as_string()?;
                    let file = parse_line_table_file(
                        &mut cursor,
                        &compilation_dir,
                        &self.table.include_directories,
                    );
                    self.table.file_names.borrow_mut().push(file);
                }
                DW_LNE_set_discriminator => {
                    self.registers.discriminator = cursor.uleb128();
                }
                _ => {
                    return SdbError::err("Unexpected extended opcode");
                }
            }
        } else {
            let adjusted_opcode = opcode - self.table.opcode_base;
            self.registers.address += (adjusted_opcode / self.table.line_range) as i64;
            self.registers.line = self.registers.line.wrapping_add(
                ((self.table.line_base as i16)
                    .wrapping_add((adjusted_opcode % self.table.line_range) as i16))
                    as u64,
            );
            self.current = Some(self.registers.clone());
            self.registers.basic_block_start = false;
            self.registers.prologue_end = false;
            self.registers.epilogue_begin = false;
            self.registers.discriminator = 0;
            emitted = true;
        }
        self.pos = cursor.position();
        Ok(emitted)
    }
}

impl Iterator for LineTableIter {
    type Item = LineTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.is_end() {
            let ret = self.get_current().clone();
            self.step().unwrap();
            Some(ret)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct LineTableFile {
    pub path: PathBuf,
    pub modification_time: u64,
    pub file_length: u64,
}

#[derive(Debug, Default)]
pub struct LineTable {
    data: Bytes,
    cu: Weak<CompileUnit>,
    default_is_stmt: bool,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    include_directories: Vec<PathBuf>,
    file_names: RefCell<Vec<LineTableFile>>,
}

impl LineTable {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data: Bytes,
        cu: &Rc<CompileUnit>,
        default_is_stmt: bool,
        line_base: i8,
        line_range: u8,
        opcode_base: u8,
        include_directories: Vec<PathBuf>,
        file_names: Vec<LineTableFile>,
    ) -> Rc<Self> {
        Rc::new(Self {
            data,
            cu: Rc::downgrade(cu),
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            include_directories,
            file_names: RefCell::new(file_names),
        })
    }

    pub fn cu(&self) -> Rc<CompileUnit> {
        self.cu.upgrade().unwrap()
    }

    pub fn file_names(&self) -> Ref<Vec<LineTableFile>> {
        self.file_names.borrow()
    }
}

pub trait LineTableExt {
    fn get_entry_by_address(&self, address: &FileAddress) -> Result<LineTableIter, SdbError>;

    fn get_entries_by_line(&self, path: &Path, line: u64) -> Result<Vec<LineTableIter>, SdbError>;

    fn iter(&self) -> Result<LineTableIter, SdbError>;
}

impl LineTableExt for Rc<LineTable> {
    fn get_entry_by_address(&self, address: &FileAddress) -> Result<LineTableIter, SdbError> {
        let mut prev = LineTableIter::new(self)?;
        if prev.current.is_none() {
            return Ok(LineTableIter::default());
        }
        let mut it = prev.clone();
        it.step()?;
        while it.current.is_some() {
            if prev.get_current().address <= *address
                && it.get_current().address > *address
                && !prev.get_current().end_sequence
            {
                return Ok(prev);
            }
            prev = it.clone();
            it.step()?;
        }
        Ok(LineTableIter::default())
    }

    fn get_entries_by_line(&self, path: &Path, line: u64) -> Result<Vec<LineTableIter>, SdbError> {
        let mut entries = Vec::new();
        let mut it = LineTableIter::new(self)?;
        while !it.is_end() {
            let entry_path = &it.get_current().file_entry.as_ref().unwrap().path;
            #[allow(clippy::collapsible_if)]
            if it.get_current().line == line {
                if (path.is_absolute() && entry_path == path)
                    || (path.is_relative() && entry_path.ends_with(path))
                {
                    entries.push(it.clone());
                }
            }
            it.step()?;
        }
        Ok(entries)
    }

    fn iter(&self) -> Result<LineTableIter, SdbError> {
        LineTableIter::new(self)
    }
}

#[derive(Debug, Clone)]
pub struct Die {
    pos: Bytes,
    cu: Weak<CompileUnit>,
    abbrev: Option<Rc<Abbrev>>,
    next: Bytes,
    attr_locs: Vec<Bytes>,
}

impl Die {
    pub fn new(
        pos: Bytes,
        cu: &Rc<CompileUnit>,
        abbrev: Rc<Abbrev>,
        attr_locs: Vec<Bytes>,
        next: Bytes,
    ) -> Rc<Self> {
        Rc::new(Self {
            pos,
            cu: Rc::downgrade(cu),
            abbrev: Some(abbrev),
            next,
            attr_locs,
        })
    }

    pub fn null(next: Bytes) -> Rc<Self> {
        Rc::new(Self {
            pos: Bytes::new(),
            cu: Weak::new(),
            abbrev: None,
            next,
            attr_locs: Vec::new(),
        })
    }

    pub fn cu(&self) -> Rc<CompileUnit> {
        self.cu.upgrade().unwrap()
    }

    pub fn abbrev_entry(&self) -> Rc<Abbrev> {
        self.abbrev.as_ref().unwrap().clone()
    }

    pub fn position(&self) -> Bytes {
        self.pos.clone()
    }

    pub fn next(&self) -> Bytes {
        self.next.clone()
    }

    pub fn contains(&self, attribute: u64) -> bool {
        if let Some(abbrev) = &self.abbrev {
            return abbrev.attr_specs.iter().any(|spec| spec.attr == attribute);
        }
        false
    }

    pub fn index(&self, attribute: u64) -> Result<DieAttr, SdbError> {
        if let Some(abbrev) = &self.abbrev
            && let Some((i, spec)) = abbrev
                .attr_specs
                .iter()
                .enumerate()
                .find(|(_, spec)| spec.attr == attribute)
        {
            return Ok(DieAttr::new(
                &self.cu(),
                spec.attr,
                spec.form,
                self.attr_locs[i].clone(),
            ));
        }
        SdbError::err("Attribute not found")
    }

    pub fn low_pc(&self) -> Result<FileAddress, SdbError> {
        if self.contains(DW_AT_ranges.0 as u64) {
            let first_entry = self
                .index(DW_AT_ranges.0 as u64)?
                .as_range_list()?
                .into_iter()
                .next()
                .unwrap();
            return Ok(first_entry.low);
        } else if self.contains(DW_AT_low_pc.0 as u64) {
            return self.index(DW_AT_low_pc.0 as u64)?.as_address();
        }
        SdbError::err("DIE does not have low PC")
    }

    pub fn high_pc(&self) -> Result<FileAddress, SdbError> {
        if self.contains(DW_AT_ranges.0 as u64) {
            let last_entry = self
                .index(DW_AT_ranges.0 as u64)?
                .as_range_list()?
                .into_iter()
                .last()
                .unwrap();
            return Ok(last_entry.high);
        } else if self.contains(DW_AT_high_pc.0 as u64) {
            let attr = self.index(DW_AT_high_pc.0 as u64)?;
            let addr: u64 = if attr.form() == DW_FORM_addr.0.into() {
                attr.as_address()?.addr()
            } else {
                self.low_pc()?.addr() + attr.as_int()?
            };
            return Ok(FileAddress::new(
                &self.cu.upgrade().unwrap().dwarf_info().elf_file(),
                addr,
            ));
        }
        SdbError::err("DIE does not have high PC")
    }

    pub fn contains_address(&self, addr: &FileAddress) -> Result<bool, SdbError> {
        if !Rc::ptr_eq(
            &self.cu.upgrade().unwrap().dwarf_info().elf_file(),
            &addr.rc_elf_file(),
        ) {
            return Ok(false);
        }
        if self.contains(DW_AT_ranges.0 as u64) {
            return Ok(self
                .index(DW_AT_ranges.0 as u64)?
                .as_range_list()?
                .contains(addr));
        } else if self.contains(DW_AT_low_pc.0 as u64) {
            let low_pc = self.low_pc()?;
            let high_pc = self.high_pc()?;
            return Ok(&low_pc <= addr && &high_pc > addr);
        }
        Ok(false)
    }

    pub fn name(&self) -> Result<Option<String>, SdbError> {
        if self.contains(DW_AT_name.0 as u64) {
            return Ok(Some(self.index(DW_AT_name.0 as u64)?.as_string()?));
        }
        if self.contains(DW_AT_specification.0 as u64) {
            return self
                .index(DW_AT_specification.0 as u64)?
                .as_reference()
                .name();
        }
        if self.contains(DW_AT_abstract_origin.0 as u64) {
            return self
                .index(DW_AT_abstract_origin.0 as u64)?
                .as_reference()
                .name();
        }
        Ok(None)
    }

    pub fn location(&self) -> Result<SourceLocation, SdbError> {
        Ok(SourceLocation {
            file: self.file()?,
            line: self.line()?,
        })
    }

    pub fn file(&self) -> Result<Rc<LineTableFile>, SdbError> {
        let idx = if self.abbrev_entry().tag as u16 == DW_TAG_inlined_subroutine.0 {
            self.index(DW_AT_call_file.0 as u64)?.as_int()?
        } else {
            self.index(DW_AT_decl_file.0 as u64)?.as_int()?
        };
        Ok(Rc::new(
            self.cu().lines().file_names()[idx as usize - 1].clone(),
        ))
    }

    pub fn line(&self) -> Result<u64, SdbError> {
        if self.abbrev_entry().tag as u16 == DW_TAG_inlined_subroutine.0 {
            return self.index(DW_AT_call_line.0 as u64)?.as_int();
        }
        self.index(DW_AT_decl_line.0 as u64)?.as_int()
    }
}

pub trait DieExt {
    fn children(&self) -> DieChildenIter;
}

impl DieExt for Rc<Die> {
    fn children(&self) -> DieChildenIter {
        DieChildenIter::new(self)
    }
}

pub struct DieAttr {
    cu: Weak<CompileUnit>,
    type_: u64,
    form: u64,
    location: Bytes,
}

impl DieAttr {
    pub fn new(cu: &Rc<CompileUnit>, type_: u64, form: u64, location: Bytes) -> Self {
        Self {
            cu: Rc::downgrade(cu),
            type_,
            form,
            location: location.clone(),
        }
    }

    pub fn name(&self) -> u64 {
        self.type_
    }

    pub fn form(&self) -> u64 {
        self.form
    }

    pub fn as_address(&self) -> Result<FileAddress, SdbError> {
        let mut cursor = Cursor::new(&self.location);
        if self.form as u16 != DW_FORM_addr.0 {
            return SdbError::err("Invalid address type");
        }
        let elf = self.cu.upgrade().unwrap().dwarf_info().elf_file();
        return Ok(FileAddress::new(&elf, cursor.u64()));
    }

    pub fn as_section_offset(&self) -> Result<u32, SdbError> {
        let mut cursor = Cursor::new(&self.location);
        if self.form as u16 != DW_FORM_sec_offset.0 {
            return SdbError::err("Invalid offset type");
        }
        return Ok(cursor.u32());
    }

    pub fn as_block(&self) -> Result<Bytes, SdbError> {
        let mut cursor = Cursor::new(&self.location);
        #[allow(non_upper_case_globals)]
        let size = match DwForm(self.form as u16) {
            DW_FORM_block1 => cursor.u8() as usize,
            DW_FORM_block2 => cursor.u16() as usize,
            DW_FORM_block4 => cursor.u32() as usize,
            DW_FORM_block => cursor.uleb128() as usize,
            _ => return SdbError::err("Invalid block type"),
        };
        Ok(cursor.position().slice(..size))
    }

    pub fn as_int(&self) -> Result<u64, SdbError> {
        let mut cursor = Cursor::new(&self.location);
        #[allow(non_upper_case_globals)]
        return match DwForm(self.form as u16) {
            DW_FORM_data1 => Ok(cursor.u8() as u64),
            DW_FORM_data2 => Ok(cursor.u16() as u64),
            DW_FORM_data4 => Ok(cursor.u32() as u64),
            DW_FORM_data8 => Ok(cursor.u64()),
            DW_FORM_udata => Ok(cursor.uleb128()),
            _ => SdbError::err("Invalid integer type"),
        };
    }

    pub fn as_string(&self) -> Result<String, SdbError> {
        let mut cursor = Cursor::new(&self.location);
        #[allow(non_upper_case_globals)]
        match DwForm(self.form as u16) {
            DW_FORM_string => Ok(cursor.string()),
            DW_FORM_strp => {
                let offset = cursor.u32() as usize;
                let stab = self
                    .cu
                    .upgrade()
                    .unwrap()
                    .dwarf_info()
                    .elf_file()
                    .get_section_contents(".debug_str");
                let mut stab_cur = Cursor::new(&stab.slice(offset..));
                Ok(stab_cur.string())
            }
            _ => SdbError::err("Invalid string type"),
        }
    }

    pub fn as_reference(&self) -> Rc<Die> {
        let mut cursor = Cursor::new(&self.location);
        #[allow(non_upper_case_globals)]
        let offset = match DwForm(self.form as u16) {
            DW_FORM_ref1 => cursor.u8() as usize,
            DW_FORM_ref2 => cursor.u16() as usize,
            DW_FORM_ref4 => cursor.u32() as usize,
            DW_FORM_ref8 => cursor.u64() as usize,
            DW_FORM_ref_udata => cursor.uleb128() as usize,
            DW_FORM_ref_addr => {
                let offset = cursor.u32() as usize;
                let cu = self.cu.upgrade().unwrap();
                let dwarf_info = cu.dwarf_info();
                let section = dwarf_info.elf_file().get_section_contents(".debug_info");
                let die_pos = section.slice(offset..);
                let die_ptr = die_pos.as_ptr() as usize;
                let cus = dwarf_info.compile_units();
                let cu_for_offset = cus
                    .iter()
                    .find(|cu| {
                        let cu_ptr = cu.data.as_ptr() as usize;
                        let cu_end = cu_ptr + cu.data.len();
                        cu_ptr <= die_ptr && cu_end > die_ptr
                    })
                    .unwrap();
                let offset_in_cu = die_ptr - (cu_for_offset.data().as_ptr() as usize);
                let ref_cursor = Cursor::new(&cu_for_offset.data.slice(offset_in_cu..));
                return parse_die(cu_for_offset, ref_cursor);
            }
            _ => panic!("Invalid reference type"),
        };
        let cu = self.cu.upgrade().unwrap();
        let ref_cursor = Cursor::new(&cu.data.slice(offset..));
        parse_die(&cu, ref_cursor)
    }

    pub fn as_range_list(&self) -> Result<CompileUnitRangeList, SdbError> {
        let cu = self.cu.upgrade().unwrap();
        let section = cu
            .dwarf_info()
            .elf_file()
            .get_section_contents(".debug_ranges");
        let offset = self.as_section_offset()? as usize;
        let data = section.slice(offset..);
        let root = cu.root();
        let base_address = if root.contains(DW_AT_low_pc.0 as u64) {
            root.index(DW_AT_low_pc.0 as u64)?.as_address()?
        } else {
            FileAddress::default()
        };
        Ok(CompileUnitRangeList::new(&cu, &data, base_address))
    }
}

pub struct DieChildenIter {
    die: Option<Rc<Die>>,
}

impl DieChildenIter {
    pub fn new(die: &Rc<Die>) -> Self {
        if let Some(abbrev) = &die.abbrev
            && abbrev.has_children
        {
            let next_cursor = Cursor::new(&die.next);
            return Self {
                die: Some(parse_die(&die.cu.upgrade().unwrap(), next_cursor)),
            };
        }
        Self { die: None }
    }
}

impl Iterator for DieChildenIter {
    type Item = Rc<Die>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_die) = self.die.take()
            && let Some(abbrev) = &current_die.abbrev
        {
            if !abbrev.has_children {
                let next_cursor = Cursor::new(&current_die.next);
                self.die = Some(parse_die(&current_die.cu.upgrade().unwrap(), next_cursor));
                return Some(current_die);
            } else if current_die.contains(DW_AT_sibling.0 as u64) {
                self.die = Some(
                    current_die
                        .index(DW_AT_sibling.0 as u64)
                        .unwrap()
                        .as_reference(),
                );
                return Some(current_die);
            } else {
                let sub_children = DieChildenIter::new(&current_die);
                for d in sub_children {
                    if d.abbrev.is_none() {
                        let next_cursor = Cursor::new(&d.next);
                        self.die = Some(parse_die(&current_die.cu.upgrade().unwrap(), next_cursor));
                        break;
                    }
                }
                return Some(current_die);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct CompileUnit {
    parent: Weak<Dwarf>,
    data: Bytes,
    abbrev_offset: usize,
    line_table: RefCell<Option<Rc<LineTable>>>,
}

fn parse_line_table_file<T: AsRef<Path>>(
    cur: &mut Cursor,
    compilation_dir: &T,
    include_directories: &[PathBuf],
) -> LineTableFile {
    let file = PathBuf::from(cur.string());
    let dir_index = cur.uleb128();
    let modification_time = cur.uleb128();
    let file_length = cur.uleb128();
    let mut path = file.clone();
    if !file.as_os_str().to_str().unwrap().starts_with('/') {
        if dir_index == 0 {
            path = compilation_dir.as_ref().join(file);
        } else {
            path = include_directories[dir_index as usize - 1].join(file);
        }
    }
    LineTableFile {
        path,
        modification_time,
        file_length,
    }
}

fn parse_line_table(cu: &Rc<CompileUnit>) -> Result<Option<Rc<LineTable>>, SdbError> {
    let section = cu
        .dwarf_info()
        .elf_file()
        .get_section_contents(".debug_line");
    if !cu.root().contains(DW_AT_stmt_list.0 as u64) {
        return Ok(None);
    }
    let offset = cu
        .root()
        .index(DW_AT_stmt_list.0 as u64)?
        .as_section_offset()? as usize;
    let mut cursor = Cursor::new(&section.slice(offset..));
    let size = cursor.u32();
    let end = cursor.position().as_ptr() as usize + size as usize;
    let version = cursor.u16();
    if version != 4 {
        return SdbError::err("Only DWARF 4 is supported");
    }
    let _header_length = cursor.u32();
    let minimum_instruction_length = cursor.u8();
    if minimum_instruction_length != 1 {
        return SdbError::err("Invalid minimum instruction length");
    }
    let maximum_operations_per_instruction = cursor.u8();
    if maximum_operations_per_instruction != 1 {
        return SdbError::err("Invalid maximum operations per instruction");
    }
    let default_is_stmt = cursor.u8();
    let line_base = cursor.s8();
    let line_range = cursor.u8();
    let opcode_base = cursor.u8();
    let expected_opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];
    for i in 0..opcode_base - 1 {
        if cursor.u8() != expected_opcode_lengths[i as usize] {
            return SdbError::err("Unexpected opcode length");
        }
    }
    let mut include_directories: Vec<PathBuf> = vec![];
    let compilation_dir = PathBuf::from(cu.root().index(DW_AT_comp_dir.0 as u64)?.as_string()?);
    let mut dir = cursor.string();
    while !dir.is_empty() {
        if dir.starts_with('/') {
            include_directories.push(PathBuf::from(dir));
        } else {
            include_directories.push(compilation_dir.clone().join(dir));
        }
        dir = cursor.string();
    }
    let mut file_names: Vec<LineTableFile> = vec![];
    while cursor.position()[0] != 0 {
        file_names.push(parse_line_table_file(
            &mut cursor,
            &compilation_dir,
            &include_directories,
        ));
    }
    cursor += 1;
    // Use ptr arithmetics
    let data = cursor
        .position()
        .slice(0..(end - cursor.position().as_ptr() as usize));
    Ok(Some(LineTable::new(
        data,
        cu,
        default_is_stmt != 0,
        line_base,
        line_range,
        opcode_base,
        include_directories,
        file_names,
    )))
}

impl CompileUnit {
    pub fn new(
        parent: &Rc<Dwarf>,
        data: Bytes,
        abbrev_offset: usize,
    ) -> Result<Rc<Self>, SdbError> {
        let ret = Rc::new(Self {
            parent: Rc::downgrade(parent),
            data,
            abbrev_offset,
            line_table: RefCell::new(None),
        });
        *ret.line_table.borrow_mut() = parse_line_table(&ret)?;
        Ok(ret)
    }

    pub fn dwarf_info(&self) -> Rc<Dwarf> {
        self.parent.upgrade().unwrap()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn abbrev_table(&self) -> Rc<AbbrevTable> {
        self.parent
            .upgrade()
            .unwrap()
            .get_abbrev_table(self.abbrev_offset)
    }

    pub fn lines(&self) -> Rc<LineTable> {
        self.line_table.borrow().clone().unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct CompileUnitRangeList {
    cu: Rc<CompileUnit>,
    data: Bytes,
    base_address: FileAddress,
}

impl CompileUnitRangeList {
    pub fn new(cu: &Rc<CompileUnit>, data: &Bytes, base_address: FileAddress) -> Self {
        Self {
            cu: cu.clone(),
            data: data.clone(),
            base_address,
        }
    }

    pub fn contains(&self, addr: &FileAddress) -> bool {
        let mut iter =
            CompileUnitRangeListIter::new(&self.cu, &self.data, self.base_address.clone());
        iter.any(|e| e.contains(addr))
    }
}

impl IntoIterator for CompileUnitRangeList {
    type Item = CompileUnitRangeEntry;
    type IntoIter = CompileUnitRangeListIter;

    fn into_iter(self) -> Self::IntoIter {
        CompileUnitRangeListIter::new(&self.cu, &self.data, self.base_address)
    }
}

pub struct CompileUnitRangeListIter {
    cu: Rc<CompileUnit>,
    pos: Bytes,
    base_address: FileAddress,
    current: CompileUnitRangeEntry,
}

impl CompileUnitRangeListIter {
    pub fn new(cu: &Rc<CompileUnit>, data: &Bytes, base_address: FileAddress) -> Self {
        let mut ret = Self {
            cu: cu.clone(),
            pos: data.clone(),
            base_address,
            current: CompileUnitRangeEntry::default(),
        };
        ret.next();
        ret
    }
}

impl Iterator for CompileUnitRangeListIter {
    type Item = CompileUnitRangeEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos.is_empty() {
            return None;
        }
        let elf = self.cu.dwarf_info().elf_file();
        let base_address_flag = !0u64;
        let mut cursor = Cursor::new(&self.pos);
        let prev_current = self.current.clone();
        loop {
            self.current.low = FileAddress::new(&elf, cursor.u64());
            self.current.high = FileAddress::new(&elf, cursor.u64());
            if self.current.low.addr() == base_address_flag {
                self.base_address = self.current.high.clone();
            } else if self.current.low.addr() == 0 && self.current.high.addr() == 0 {
                self.pos = Bytes::new();
                break;
            } else {
                self.pos = cursor.position();
                self.current.low += self.base_address.addr() as i64;
                self.current.high += self.base_address.addr() as i64;
                break;
            }
        }
        return Some(prev_current);
    }
}
#[derive(Debug, Clone, Default)]
pub struct CompileUnitRangeEntry {
    pub low: FileAddress,
    pub high: FileAddress,
}

impl CompileUnitRangeEntry {
    pub fn contains(&self, addr: &FileAddress) -> bool {
        &self.low <= addr && addr < &self.high
    }
}

pub trait CompileUnitExt {
    fn root(&self) -> Rc<Die>;
}

impl CompileUnitExt for Rc<CompileUnit> {
    fn root(&self) -> Rc<Die> {
        let header_size = 11usize;
        let cursor = Cursor::new(&self.data.slice(header_size..));
        parse_die(self, cursor)
    }
}

fn parse_die(cu: &Rc<CompileUnit>, mut cursor: Cursor) -> Rc<Die> {
    let pos = cursor.position();
    let abbrev_code = cursor.uleb128();
    if abbrev_code == 0 {
        let next = cursor.position();
        return Die::null(next);
    }
    let abbrev_table = cu.abbrev_table();
    let abbrev = &abbrev_table[&abbrev_code];
    let mut attr_locs = Vec::<Bytes>::with_capacity(abbrev.attr_specs.len());
    for attr in &abbrev.attr_specs {
        attr_locs.push(cursor.position());
        cursor.skip_form(attr.form).unwrap();
    }
    let next = cursor.position();
    Die::new(pos, cu, abbrev.clone(), attr_locs, next)
}

fn parse_call_frame_information(
    dwarf: &Rc<Dwarf>,
) -> Result<Rc<RefCell<CallFrameInformation>>, SdbError> {
    let eh_hdr = parse_eh_hdr(dwarf)?;
    Ok(CallFrameInformation::new(dwarf, eh_hdr))
}

#[derive(Debug)]
pub struct Dwarf {
    elf: Weak<Elf>,
    abbrev_tables: RefCell<HashMap<usize, Rc<AbbrevTable>>>,
    compile_units: OnceCell<Vec<Rc<CompileUnit>>>,
    function_index: RefCell<MultiMap<String, DwarfIndexEntry>>,
    cfi: OnceCell<Rc<RefCell<CallFrameInformation>>>,
}

impl Dwarf {
    pub fn cfi(&self) -> Rc<RefCell<CallFrameInformation>> {
        self.cfi.get().unwrap().clone()
    }

    pub fn new(parent: &Weak<Elf>) -> Result<Rc<Self>, SdbError> {
        let ret = Rc::new(Self {
            elf: parent.clone(),
            abbrev_tables: RefCell::new(HashMap::default()),
            compile_units: OnceCell::new(),
            function_index: RefCell::new(MultiMap::default()),
            cfi: OnceCell::new(),
        });
        let t = parse_compile_units(&ret, &ret.elf_file())?;
        ret.compile_units
            .set(t)
            .map_err(|_| SdbError::new_err("Failed to set compile units"))?;
        ret.cfi
            .set(parse_call_frame_information(&ret)?)
            .map_err(|_| SdbError::new_err("Failed to set call frame information"))?;
        Ok(ret)
    }

    pub fn elf_file(&self) -> Rc<Elf> {
        self.elf.upgrade().unwrap()
    }

    pub fn get_abbrev_table(&self, offset: usize) -> Rc<AbbrevTable> {
        if !self.abbrev_tables.borrow().contains_key(&offset) {
            self.abbrev_tables.borrow_mut().insert(
                offset,
                Rc::new(parse_abbrev_table(&self.elf_file(), offset)),
            );
        }
        self.abbrev_tables.borrow()[&offset].clone()
    }

    pub fn compile_units(&self) -> &Vec<Rc<CompileUnit>> {
        self.compile_units.get().unwrap()
    }

    pub fn compile_unit_containing_address(
        &self,
        address: &FileAddress,
    ) -> Result<Option<Rc<CompileUnit>>, SdbError> {
        for cu in self.compile_units().iter() {
            if cu.root().contains_address(address)? {
                return Ok(Some(cu.clone()));
            }
        }
        Ok(None)
    }

    pub fn function_containing_address(
        &self,
        address: &FileAddress,
    ) -> Result<Option<Rc<Die>>, SdbError> {
        self.index()?;
        for (_name, entry) in self.function_index.borrow().iter() {
            let cursor = Cursor::new(&entry.pos);
            let die = parse_die(&entry.cu, cursor);
            if die.contains_address(address)?
                && die.abbrev_entry().tag == DW_TAG_subprogram.0 as u64
            {
                return Ok(Some(die));
            }
        }
        Ok(None)
    }

    pub fn find_functions(&self, name: &str) -> Result<Vec<Rc<Die>>, SdbError> {
        self.index()?;
        let mut found: Vec<Rc<Die>> = Vec::new();
        let function_index = self.function_index.borrow();
        let entrys = function_index.get_vec(name);
        if let Some(entrys) = entrys {
            for entry in entrys {
                let cursor = Cursor::new(&entry.pos);
                let die = parse_die(&entry.cu, cursor);
                found.push(die);
            }
        }
        Ok(found)
    }

    fn index(&self) -> Result<(), SdbError> {
        if !self.function_index.borrow().is_empty() {
            return Ok(());
        }
        for cu in self.compile_units().iter() {
            self.index_die(&cu.root())?;
        }
        Ok(())
    }

    fn index_die(&self, die: &Rc<Die>) -> Result<(), SdbError> {
        let has_range = die.contains(DW_AT_low_pc.0 as u64) || die.contains(DW_AT_ranges.0 as u64);
        let is_function = die.abbrev_entry().tag == DW_TAG_subprogram.0 as u64
            || die.abbrev_entry().tag == DW_TAG_inlined_subroutine.0 as u64;
        if has_range
            && is_function
            && let Some(name) = die.name()?
        {
            let entry = DwarfIndexEntry {
                cu: die.cu.upgrade().unwrap(),
                pos: die.pos.clone(),
            };
            self.function_index.borrow_mut().insert(name, entry);
        }
        for child in die.children() {
            self.index_die(&child)?;
        }
        Ok(())
    }

    pub fn line_entry_at_address(&self, address: &FileAddress) -> Result<LineTableIter, SdbError> {
        let cu = self.compile_unit_containing_address(address)?;
        if let Some(cu) = cu {
            return cu.lines().get_entry_by_address(address);
        }
        Ok(LineTableIter::default())
    }

    pub fn inline_stack_at_address(&self, address: &FileAddress) -> Result<Vec<Rc<Die>>, SdbError> {
        let func = self.function_containing_address(address)?;
        let mut stack: Vec<Rc<Die>> = Vec::new();
        if let Some(func) = func {
            stack.push(func);
            loop {
                let mut children = stack.last().unwrap().children();
                let found = children.find(|child| {
                    child.abbrev_entry().tag == DW_TAG_inlined_subroutine.0 as u64
                        && child.contains_address(address).unwrap_or(false)
                });
                if let Some(found) = found {
                    stack.push(found);
                } else {
                    break;
                }
            }
        }
        Ok(stack)
    }
}

#[derive(Debug)]
pub struct DwarfIndexEntry {
    cu: Rc<CompileUnit>,
    pos: Bytes,
}

fn parse_compile_units(dwarf: &Rc<Dwarf>, obj: &Elf) -> Result<Vec<Rc<CompileUnit>>, SdbError> {
    let debug_info = obj.get_section_contents(".debug_info");
    let mut cursor = Cursor::new(&debug_info);
    let mut units: Vec<Rc<CompileUnit>> = Vec::new();
    while !cursor.finished() {
        if let Ok(unit) = parse_compile_unit(dwarf, obj, cursor.clone()) {
            cursor += unit.data.len();
            units.push(unit);
        } else {
            break;
        }
    }
    Ok(units)
}

fn parse_compile_unit(
    dwarf: &Rc<Dwarf>,
    _obj: &Elf,
    mut cursor: Cursor,
) -> Result<Rc<CompileUnit>, SdbError> {
    let start = cursor.position();
    let mut size = cursor.u32();
    let version = cursor.u16();
    let abbrev = cursor.u32();
    let address_size = cursor.u8();
    if size == 0xffffffff {
        return SdbError::err("Only DWARF32 is supported");
    }
    if version != 4 {
        return SdbError::err(&format!(
            "Only DWARF version 4 is supported, found version {version}"
        ));
    }
    if address_size != 8 {
        return SdbError::err("Invalid address size for DWARF");
    }
    size += size_of::<u32>() as u32;
    let data = start.slice(..size as usize);
    CompileUnit::new(dwarf, data, abbrev as usize)
}

fn parse_abbrev_table(obj: &Elf, offset: usize) -> AbbrevTable {
    let mut cursor = Cursor::new(&obj.get_section_contents(".debug_abbrev"));
    cursor += offset;
    let mut table: AbbrevTable = HashMap::new();
    let mut code: u64;
    loop {
        code = cursor.uleb128();
        // Bug fixed: should break early
        if code == 0 {
            break;
        }
        let tag = cursor.uleb128();
        let has_children = cursor.u8() != 0;
        let mut attr_specs = Vec::<AttrSpec>::new();
        let mut attr: u64;
        loop {
            attr = cursor.uleb128();
            let form = cursor.uleb128();
            if attr != 0 {
                attr_specs.push(AttrSpec { attr, form });
            }
            if attr == 0 {
                break;
            }
        }
        table.insert(
            code,
            Rc::new(Abbrev {
                code,
                tag,
                has_children,
                attr_specs,
            }),
        );
    }

    table
}

#[derive(Debug, Clone, Copy)]
pub struct AttrSpec {
    attr: u64,
    form: u64,
}

#[derive(Debug)]
pub struct Abbrev {
    pub code: u64,
    pub tag: u64,
    pub has_children: bool,
    pub attr_specs: Vec<AttrSpec>,
}

#[derive(Debug, Clone, Default)]
pub struct Cursor {
    data: Bytes,
}

macro_rules! gen_fixed_int {
    ($( $name:ident : $ty:ty ),* $(,)?) => {
       $(
            pub fn $name(&mut self) -> $ty {
                self.fixed_int::<$ty>()
            }
        )*
    };
}

impl Cursor {
    pub fn new(data: &Bytes) -> Self {
        Self { data: data.clone() }
    }

    pub fn finished(&self) -> bool {
        self.data.is_empty()
    }

    pub fn position(&self) -> Bytes {
        self.data.clone()
    }

    pub fn fixed_int<T: Pod>(&mut self) -> T {
        let t = from_bytes::<T>(&self.data);
        self.data = self.data.slice(size_of::<T>()..);
        t
    }

    pub fn string(&mut self) -> String {
        if let Some(pos) = self.data.iter().position(|&b| b == 0) {
            let next = pos + 1;
            let s = self.data.slice(..next);
            let s = CStr::from_bytes_with_nul(&s).unwrap().to_str().unwrap();
            if next < self.data.len() {
                self.data = self.data.slice(next..);
            } else {
                self.data = Bytes::new();
            }
            return s.to_owned();
        }

        panic!("Cannot find cstr")
    }

    pub fn uleb128(&mut self) -> u64 {
        let mut res = 0u64;
        let mut shift = 0i32;
        let mut byte: u8;
        loop {
            byte = self.u8();
            let masked = (byte & 0x7f) as u64;
            res |= masked << shift;
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
        }
        return res;
    }

    pub fn sleb128(&mut self) -> i64 {
        let mut res = 0u64;
        let mut shift = 0i32;
        let mut byte: u8;
        loop {
            byte = self.u8();
            let masked = (byte & 0x7f) as u64;
            res |= masked << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if ((shift as usize) < u64::BITS as usize) && ((byte & 0x40) != 0) {
            res |= !0u64 << shift;
        }
        res as i64
    }
    #[allow(non_upper_case_globals)]
    pub fn skip_form(&mut self, form: u64) -> Result<(), SdbError> {
        return match DwForm(form.try_into().unwrap()) {
            /* 0-byte forms -------------------------------------------------- */
            DW_FORM_flag_present => Ok(()),

            /* fixed-size scalar/reference forms ----------------------------- */
            DW_FORM_data1 | DW_FORM_ref1 | DW_FORM_flag => {
                self.data = self.data.slice(1..);
                Ok(())
            }
            DW_FORM_data2 | DW_FORM_ref2 => {
                self.data = self.data.slice(2..);
                Ok(())
            }
            DW_FORM_data4 | DW_FORM_ref4 | DW_FORM_ref_addr | DW_FORM_sec_offset | DW_FORM_strp => {
                self.data = self.data.slice(4..);
                Ok(())
            }
            DW_FORM_data8 | DW_FORM_addr => {
                self.data = self.data.slice(8..);
                Ok(())
            }

            /* variable-length scalars --------------------------------------- */
            DW_FORM_sdata => {
                self.sleb128();
                Ok(())
            }
            DW_FORM_udata | DW_FORM_ref_udata => {
                self.uleb128();
                Ok(())
            }

            /* blocks whose length precedes the data ------------------------- */
            DW_FORM_block1 => {
                let s = self.u8() as usize;
                self.data = self.data.slice(s..);
                Ok(())
            }
            DW_FORM_block2 => {
                let s = self.u16() as usize;
                self.data = self.data.slice(s..);
                Ok(())
            }
            DW_FORM_block4 => {
                let s = self.u32() as usize;
                self.data = self.data.slice(s..);
                Ok(())
            }
            DW_FORM_block | DW_FORM_exprloc => {
                let s = self.uleb128() as usize;
                self.data = self.data.slice(s..);
                Ok(())
            }

            /* in-line, NUL-terminated string ------------------------------- */
            DW_FORM_string => {
                while !self.finished() && self.data[0] != 0 {
                    self.data = self.data.slice(1..);
                }
                self.data = self.data.slice(1..); // consume trailing NUL
                Ok(())
            }
            /* indirection: the *next* ULEB128 is another form code ---------- */
            DW_FORM_indirect => {
                let s = self.uleb128();
                self.skip_form(s)?;
                Ok(())
            }
            _ => SdbError::err("Unrecognized DWARF form"),
        };
    }

    gen_fixed_int! {
        u8  : u8,
        u16 : u16,
        u32 : u32,
        u64 : u64,
        s8  : i8,
        s16 : i16,
        s32 : i32,
        s64 : i64,
    }
}

impl AddAssign<usize> for Cursor {
    fn add_assign(&mut self, rhs: usize) {
        self.data = self.data.slice(rhs..);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UndefinedRule {}
#[derive(Debug, Clone, Copy)]
pub struct SameRule {}
#[derive(Debug, Clone, Copy)]
pub struct OffsetRule {
    pub offset: i64,
}
#[derive(Debug, Clone, Copy)]
pub struct ValOffsetRule {
    pub offset: i64,
}
#[derive(Debug, Clone, Copy)]
pub struct RegisterRule {
    pub reg: u32,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct CfaRegisterRule {
    pub reg: u32,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub enum Rule {
    Undefined(UndefinedRule),
    Same(SameRule),
    Offset(OffsetRule),
    ValOffset(ValOffsetRule),
    Register(RegisterRule),
    CfaRegister(CfaRegisterRule),
}

pub type RuleSet = HashMap<u32, Rule>;

#[derive(Default)]
pub struct UnwindContext {
    pub cursor: Cursor,
    pub location: FileAddress,
    pub cfa_rule: CfaRegisterRule,
    pub cie_register_rules: RuleSet,
    pub register_rules: RuleSet,
    pub rule_stack: Vec<(RuleSet, CfaRegisterRule)>,
}


pub enum DwarfExpressionSimpleLocation {
    Address { address: FileAddress },
    Register { reg_num: u64 },
    Data { data: Bytes },
    Literal { value: u64 },
    Empty {},
}

pub struct DwarfExpressionPiece {
    pub location: DwarfExpressionSimpleLocation,
    pub bit_size: u64,
    pub offset: u64,
}

pub struct DwarfExpressionPiecesResult {
    pub pieces: Vec<DwarfExpressionPiece>,
}

pub enum DwarfExpressionResult {
    SimpleLocation(DwarfExpressionSimpleLocation),
    Pieces(DwarfExpressionPiecesResult),
}


#[derive(TypedBuilder)]
pub struct DwarfExpression {
    parent: Weak<Dwarf>,
    expr_data: Bytes,
    in_frame_info: bool,
}

/*
#include <functional>

sdb::dwarf_expression::result
sdb::dwarf_expression::eval(
      const sdb::process& proc, const registers& regs, bool push_cfa) const {
    cursor cur({ expr_data_.begin(), expr_data_.end() });

    std::vector<std::uint64_t> stack;
    if (push_cfa) stack.push_back(regs.cfa().addr());

    std::optional<simple_location> most_recent_location;
    std::vector<pieces_result::piece> pieces;

    bool result_is_address = true;
    --snip--
    auto binop = [&](auto op) {
        auto rhs = stack.back();
        stack.pop_back();
        auto lhs = stack.back();
        stack.pop_back();
        stack.push_back(op(lhs, rhs));
    };

    auto relop = [&](auto op) {
        auto rhs = static_cast<std::int64_t>(stack.back());
        stack.pop_back();
        auto lhs = static_cast<std::int64_t>(stack.back());
        stack.pop_back();
        stack.push_back(op(lhs, rhs) ? 1 : 0);
    };
    --snip--
    auto virt_pc = virt_addr{
        regs.read_by_id_as<std::uint64_t>(register_id::rip)
    };
    auto pc = virt_pc.to_file_addr(*parent_->elf_file());
    auto func = parent_->function_containing_address(pc);
    --snip--
    auto get_current_location = [&]() {
        simple_location loc;
        if (stack.empty()) {
            loc = most_recent_location.value_or(empty_result{});
            most_recent_location.reset();
        }
        else if (result_is_address) {
            loc = address_result{ virt_addr{stack.back()} };
            stack.pop_back();
        }
        else {
            loc = literal_result{ stack.back() };
            stack.pop_back();
            result_is_address = true;
        }
        return loc;
    };
    --snip--
    while (!cur.finished()) {
        auto opcode = cur.u8();

        if (opcode >= DW_OP_lit0 and opcode <= DW_OP_lit31) {
            stack.push_back(opcode - DW_OP_lit0);
        }
        else if (opcode >= DW_OP_breg0 and opcode <= DW_OP_breg31) {
            auto reg = opcode - DW_OP_breg0;
            auto reg_val = regs.read(sdb::register_info_by_dwarf(reg));
            auto offset = cur.sleb128();
            stack.push_back(std::get<std::uint64_t>(reg_val) + offset);
        }
        else if (opcode >= DW_OP_reg0 and opcode <= DW_OP_reg31) {
            auto reg = opcode - DW_OP_reg0;
            if (in_frame_info_) {
                auto reg_val = regs.read(sdb::register_info_by_dwarf(reg));
                stack.push_back(std::get<std::uint64_t>(reg_val));
            }
            else {
                most_recent_location = register_result{
                    static_cast<std::uint64_t>(reg)
                };
            }
        }
        --snip--
        switch (opcode) {
        case DW_OP_addr: {
            auto addr = file_addr{
                *parent_->elf_file(), cur.u64()
            };
            stack.push_back(addr.to_virt_addr().addr());
            break;
        }
        case DW_OP_const1u:
            stack.push_back(cur.u8());
            break;
        case DW_OP_const1s:
            stack.push_back(cur.s8());
            break;
        case DW_OP_const2u:
            stack.push_back(cur.u16());
            break;
        case DW_OP_const2s:
            stack.push_back(cur.s16());
            break;
        case DW_OP_const4u:
            stack.push_back(cur.u32());
            break;
        case DW_OP_const4s:
            stack.push_back(cur.s32());
            break;
        case DW_OP_const8u:
            stack.push_back(cur.u64());
            break;
        case DW_OP_const8s:
            stack.push_back(cur.s64());
            break;
        case DW_OP_constu:
            stack.push_back(cur.uleb128());
            break;
        case DW_OP_consts:
            stack.push_back(cur.sleb128());
            break;
        --snip--
        case DW_OP_bregx: {
            auto reg_val = regs.read(
                sdb::register_info_by_dwarf(cur.uleb128()));
            stack.push_back(
                std::get<std::uint64_t>(reg_val) + cur.sleb128());
            break;
        }
        case DW_OP_fbreg: {
            auto offset = cur.sleb128();
            auto fb_loc = func.value()[DW_AT_frame_base]
                .as_evaluated_location(proc, regs, /*in_frame_info=*/true);
            auto fb_addr = read_frame_base_result(fb_loc, regs);
            stack.push_back(fb_addr.addr() + offset);
            break;
        }
        --snip--
        case DW_OP_dup:
            stack.push_back(stack.back());
            break;
        case DW_OP_drop:
            stack.pop_back();
            break;
        case DW_OP_pick:
            stack.push_back(stack.rbegin()[cur.u8()]);
            break;
        case DW_OP_over:
            stack.push_back(stack.rbegin()[1]);
            break;
        case DW_OP_swap:
            std::swap(stack.rbegin()[0], stack.rbegin()[1]);
            break;
        case DW_OP_rot:
            std::rotate(
                stack.rbegin(), stack.rbegin() + 1, stack.rbegin() + 3);
            break;
        --snip--
        case DW_OP_deref: {
            auto addr = virt_addr{ stack.back() };
            stack.back() = proc.read_memory_as<std::uint64_t>(addr);
            break;
        }
        case DW_OP_deref_size: {
            auto addr = virt_addr{ stack.back() };
            auto size_to_read = cur.u8();
            auto mem = proc.read_memory(addr, size_to_read);
            std::uint64_t res = 0;
            std::copy(mem.data(), mem.data() + mem.size(),
                reinterpret_cast<std::byte*>(&res));
            stack.back() = res;
            break;
        }
        case DW_OP_xderef:
            sdb::error::send("DW_OP_xderef not supported");
        case DW_OP_xderef_size:
            sdb::error::send("DW_OP_xderef_size not supported");
        --snip--
        case DW_OP_push_object_address:
            sdb::error::send("Unsupported opcode DW_OP_push_object_address");
        case DW_OP_form_tls_address:
            sdb::error::send("Unsupported opcode DW_OP_form_tls_address");
        case DW_OP_call_frame_cfa:
            stack.push_back(regs.cfa().addr());
            break;
        --snip--
        case DW_OP_minus:
            binop(std::minus{});
            break;
        case DW_OP_mod:
            binop(std::modulus{});
            break;
        case DW_OP_mul:
            binop(std::multiplies{});
            break;
        case DW_OP_and:
            binop(std::bit_and{});
            break;
        case DW_OP_or:
            binop(std::bit_or{});
            break;
        case DW_OP_plus:
            binop(std::plus{});
            break;
        case DW_OP_shl:
            binop([](auto lhs, auto rhs) { return lhs << rhs; });
            break;
     ➊ case DW_OP_shr:
            binop([](auto lhs, auto rhs) { return lhs >> rhs; });
            break;
     ➋ case DW_OP_shra:
            binop([](auto lhs, auto rhs) {
                return static_cast<std::int64_t>(lhs) >> rhs; });
            break;
        case DW_OP_xor:
            binop(std::bit_xor{});
            break;
        case DW_OP_div: {
            auto rhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            auto lhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            stack.push_back(static_cast<std::uint64_t>(lhs / rhs));
            break;
        }
        --snip--
        case DW_OP_abs: {
            auto sval = static_cast<std::int64_t>(stack.back());
            sval = std::abs(sval);
            stack.back() = static_cast<std::uint64_t>(sval);
            break;
        }
        case DW_OP_neg: {
            auto neg = -static_cast<std::int64_t>(stack.back());
            stack.back() = static_cast<std::uint64_t>(neg);
            break;
        }
        case DW_OP_plus_uconst:
            stack.back() += cur.uleb128();
            break;
        case DW_OP_not:
            stack.back() = ~stack.back();
            break;
        --snip--
        case DW_OP_le:
            relop(std::less_equal{});
            break;
        case DW_OP_ge:
            relop(std::greater_equal{});
            break;
        case DW_OP_eq:
            relop(std::equal_to{});
            break;
        case DW_OP_lt:
            relop(std::less{});
            break;
        case DW_OP_gt:
            relop(std::greater{});
            break;
        case DW_OP_ne:
            relop(std::not_equal_to{});
            break;
        --snip--
        case DW_OP_skip:
            cur += cur.s16();
            break;
        case DW_OP_bra:
            if (stack.back() != 0) {
                cur += cur.s16();
            }
            stack.pop_back();
            break;
        case DW_OP_call2:
            sdb::error::send("Unsupported opcode DW_OP_call2");
        case DW_OP_call4:
            sdb::error::send("Unsupported opcode DW_OP_call4");
        case DW_OP_call_ref:
            sdb::error::send("Unsupported opcode DW_OP_call_ref");
        --snip--
        case DW_OP_regx:
            if (in_frame_info_) {
                auto reg_val = regs.read(
                    sdb::register_info_by_dwarf(cur.uleb128()));
                stack.push_back(
                    std::get<std::uint64_t>(reg_val));
            }
            else {
                most_recent_location = register_result{
                    cur.uleb128() };
            }
            break;

        case DW_OP_implicit_value: {
            auto length = cur.uleb128();
            most_recent_location = data_result{
                span<const std::byte>{cur.position(), length} };
            break;
        }
        case DW_OP_stack_value:
            result_is_address = false;
            break;
        --snip--
        case DW_OP_nop:
            break;
        --snip--
        case DW_OP_piece: {
            auto byte_size = cur.uleb128();
            simple_location loc = get_current_location();
            pieces.push_back(pieces_result::piece{ loc, byte_size*8 });
            break;
        }
        case DW_OP_bit_piece: {
            auto bit_size = cur.uleb128();
            auto offset = cur.uleb128();
            simple_location loc = get_current_location();
            pieces.push_back(pieces_result::piece{ loc, bit_size, offset });
            break;
        }
        }
    }
    --snip--
    if (!pieces.empty()) {
        return pieces_result{ pieces };
    }

    return get_current_location();
}
*/
impl DwarfExpression {
    pub fn eval(&self, proc: &Process, regs: &Registers, push_cfa: bool /* false */) -> Result<DwarfExpressionResult, SdbError> {
        todo!()
    }
}

/*
namespace {
    sdb::virt_addr read_frame_base_result(
          const sdb::dwarf_expression::result& loc,
          const sdb::registers& regs) {
        auto simple_loc = std::get_if<sdb::dwarf_expression::simple_location>(&loc);
        if (!simple_loc) sdb::error::send("Unsupported frame base location");
        if (auto addr_res = std::get_if<sdb::dwarf_expression::address_result>(simple_loc)) {
            return addr_res->address;
        }
        sdb::error::send("Unsupported frame base location");
    }
}
*/