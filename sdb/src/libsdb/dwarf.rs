use std::cell::{Ref, RefCell};
use std::ffi::CStr;
use std::rc::Weak;
use std::{collections::HashMap, ops::AddAssign, rc::Rc};

use bytemuck::Pod;
use bytes::Bytes;
use gimli::{
    DW_AT_abstract_origin, DW_AT_high_pc, DW_AT_low_pc, DW_AT_name, DW_AT_ranges, DW_AT_sibling,
    DW_AT_specification, DW_FORM_addr, DW_FORM_block, DW_FORM_block1, DW_FORM_block2,
    DW_FORM_block4, DW_FORM_data1, DW_FORM_data2, DW_FORM_data4, DW_FORM_data8, DW_FORM_exprloc,
    DW_FORM_flag, DW_FORM_flag_present, DW_FORM_indirect, DW_FORM_ref_addr, DW_FORM_ref_udata,
    DW_FORM_ref1, DW_FORM_ref2, DW_FORM_ref4, DW_FORM_ref8, DW_FORM_sdata, DW_FORM_sec_offset,
    DW_FORM_string, DW_FORM_strp, DW_FORM_udata, DW_TAG_inlined_subroutine, DW_TAG_subprogram,
    DwForm,
};
use multimap::MultiMap;

use super::bit::from_bytes;
use super::elf::Elf;
use super::sdb_error::SdbError;
use super::types::FileAddress;

type AbbrevTable = HashMap<u64, Rc<Abbrev>>;

#[derive(Debug)]
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
        if let Some(abbrev) = &self.abbrev {
            if let Some((i, spec)) = abbrev
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
            &addr.elf_file(),
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
        if let Some(abbrev) = &die.abbrev {
            if abbrev.has_children {
                let next_cursor = Cursor::new(&die.next);
                return Self {
                    die: Some(parse_die(&die.cu.upgrade().unwrap(), next_cursor)),
                };
            }
        }
        Self { die: None }
    }
}

impl Iterator for DieChildenIter {
    type Item = Rc<Die>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_die) = self.die.take() {
            if let Some(abbrev) = &current_die.abbrev {
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
                    let mut sub_children = DieChildenIter::new(&current_die);
                    while let Some(d) = sub_children.next() {
                        if d.abbrev.is_none() {
                            let next_cursor = Cursor::new(&d.next);
                            self.die =
                                Some(parse_die(&current_die.cu.upgrade().unwrap(), next_cursor));
                            break;
                        }
                    }
                    return Some(current_die);
                }
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
}

impl CompileUnit {
    pub fn new(parent: &Rc<Dwarf>, data: Bytes, abbrev_offset: usize) -> Rc<Self> {
        Rc::new(Self {
            parent: Rc::downgrade(parent),
            data,
            abbrev_offset,
        })
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
}

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
    low: FileAddress,
    high: FileAddress,
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

#[derive(Debug)]
pub struct Dwarf {
    elf: Rc<Elf>,
    abbrev_tables: RefCell<HashMap<usize, Rc<AbbrevTable>>>,
    compile_units: RefCell<Vec<Rc<CompileUnit>>>,
    function_index: RefCell<MultiMap<String, DwarfIndexEntry>>,
}

impl Dwarf {
    pub fn new(parent: &Rc<Elf>) -> Result<Rc<Self>, SdbError> {
        let ret = Self {
            elf: parent.clone(),
            abbrev_tables: RefCell::new(HashMap::default()),
            compile_units: RefCell::new(Vec::default()),
            function_index: RefCell::new(MultiMap::default()),
        };
        let ret = Rc::new(ret);
        *ret.compile_units.borrow_mut() = parse_compile_units(&ret, parent)?;
        Ok(ret)
    }

    pub fn elf_file(&self) -> Rc<Elf> {
        self.elf.clone()
    }

    pub fn get_abbrev_table(&self, offset: usize) -> Rc<AbbrevTable> {
        if !self.abbrev_tables.borrow().contains_key(&offset) {
            self.abbrev_tables
                .borrow_mut()
                .insert(offset, Rc::new(parse_abbrev_table(&self.elf, offset)));
        }
        self.abbrev_tables.borrow()[&offset].clone()
    }

    pub fn compile_units(&self) -> Ref<'_, Vec<Rc<CompileUnit>>> {
        self.compile_units.borrow()
    }

    pub fn compile_unit_containing_address(
        &self,
        address: &FileAddress,
    ) -> Result<Option<Rc<CompileUnit>>, SdbError> {
        for cu in self.compile_units.borrow().iter() {
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
        for cu in self.compile_units.borrow().iter() {
            self.index_die(&cu.root())?;
        }
        Ok(())
    }

    fn index_die(&self, die: &Rc<Die>) -> Result<(), SdbError> {
        let has_range = die.contains(DW_AT_low_pc.0 as u64) || die.contains(DW_AT_ranges.0 as u64);
        let is_function = die.abbrev_entry().tag == DW_TAG_subprogram.0 as u64
            || die.abbrev_entry().tag == DW_TAG_inlined_subroutine.0 as u64;
        if has_range && is_function {
            if let Some(name) = die.name()? {
                let entry = DwarfIndexEntry {
                    cu: die.cu.upgrade().unwrap(),
                    pos: die.pos.clone(),
                };
                self.function_index.borrow_mut().insert(name, entry);
            }
        }
        for child in die.children() {
            self.index_die(&child)?;
        }
        Ok(())
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
    Ok(CompileUnit::new(dwarf, data, abbrev as usize))
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

#[derive(Debug, Clone)]
struct Cursor {
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
        if ((shift as usize) < u64::BITS as usize) && (byte & 0x40) != 0 {
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
