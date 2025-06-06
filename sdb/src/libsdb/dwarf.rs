use std::cell::{Ref, RefCell};
use std::ffi::CStr;
use std::rc::Weak;
use std::{collections::HashMap, ops::AddAssign, rc::Rc};

use bytemuck::Pod;
use bytes::Bytes;
use gimli::{
    DW_FORM_addr, DW_FORM_block, DW_FORM_block1, DW_FORM_block2, DW_FORM_block4, DW_FORM_data1,
    DW_FORM_data2, DW_FORM_data4, DW_FORM_data8, DW_FORM_exprloc, DW_FORM_flag,
    DW_FORM_flag_present, DW_FORM_indirect, DW_FORM_ref_addr, DW_FORM_ref_udata, DW_FORM_ref1,
    DW_FORM_ref2, DW_FORM_ref4, DW_FORM_sdata, DW_FORM_sec_offset, DW_FORM_string, DW_FORM_strp,
    DW_FORM_udata, DwForm,
};

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

    fn index(&self, attribute: u64) -> Result<DieAttr, SdbError> {
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
        if self.form as u16 != DW_FORM_addr.0{
            return SdbError::err("Invalid address type");
        }
        let elf = self.cu.upgrade().unwrap().dwarf_info().elf_file();
        return Ok(FileAddress::new(&elf, cursor.u64()));
    }

    pub fn as_section_offset(&self) -> u32 {
        todo!()
    }

    pub fn as_block(&self) -> Bytes {
        todo!()
    }

    pub fn as_int(&self) -> u64 {
        todo!()
    }

    pub fn as_string(&self) -> String {
        todo!()
    }

    pub fn as_reference(&self) -> Die {
        todo!()
    }
}

pub struct DieChildenIter {
    die: Option<Result<Rc<Die>, SdbError>>,
}

impl DieChildenIter {
    pub fn new(die: &Rc<Die>) -> Self {
        if let Some(abbrev) = &die.abbrev {
            if abbrev.has_children {
                let mut next_cursor = Cursor::new(&die.next);
                let next_die = parse_die(&die.cu.upgrade().unwrap(), &mut next_cursor);
                return Self {
                    die: Some(next_die),
                };
            }
        }
        Self { die: None }
    }
}

impl Iterator for DieChildenIter {
    type Item = Result<Rc<Die>, SdbError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(Ok(current_die)) = &self.die {
            if let Some(abbrev) = &current_die.abbrev {
                if !abbrev.has_children {
                    let mut next_cursor = Cursor::new(&current_die.next);
                    let next_die = parse_die(&current_die.cu.upgrade().unwrap(), &mut next_cursor);
                    self.die = Some(next_die.clone());
                    return Some(next_die);
                } else {
                    let mut sub_children = DieChildenIter::new(current_die);
                    let mut child: Option<Result<Rc<Die>, SdbError>>;
                    loop {
                        child = sub_children.next();
                        if let Some(Ok(die)) = &child {
                            if die.abbrev.is_some() {
                                continue;
                            }
                        }
                        break;
                    }
                    let child = child.expect("Has null die");
                    if let Ok(child) = child {
                        let mut next_cursor = Cursor::new(&child.next);
                        let next_die =
                            parse_die(&current_die.cu.upgrade().unwrap(), &mut next_cursor);
                        self.die = Some(next_die.clone());
                        return Some(next_die);
                    } else {
                        return Some(Err(child.unwrap_err()));
                    }
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

pub trait CompileUnitExt {
    fn root(&self) -> Result<Rc<Die>, SdbError>;
}

impl CompileUnitExt for Rc<CompileUnit> {
    fn root(&self) -> Result<Rc<Die>, SdbError> {
        let header_size = 11usize;
        let mut cursor = Cursor::new(&self.data.slice(header_size..));
        return parse_die(self, &mut cursor);
    }
}

fn parse_die(cu: &Rc<CompileUnit>, cursor: &mut Cursor) -> Result<Rc<Die>, SdbError> {
    let pos = cursor.position();
    let abbrev_code = cursor.uleb128();
    if abbrev_code == 0 {
        let next = cursor.position();
        return Ok(Die::null(next));
    }
    let abbrev_table = cu.abbrev_table();
    let abbrev = &abbrev_table[&abbrev_code];
    let mut attr_locs = Vec::<Bytes>::with_capacity(abbrev.attr_specs.len());
    for attr in &abbrev.attr_specs {
        attr_locs.push(cursor.position());
        cursor.skip_form(attr.form)?;
    }
    let next = cursor.position();
    return Ok(Die::new(pos, cu, abbrev.clone(), attr_locs, next));
}

#[derive(Debug)]
pub struct Dwarf {
    elf: Rc<Elf>,
    abbrev_tables: RefCell<HashMap<usize, Rc<AbbrevTable>>>,
    compile_units: RefCell<Vec<Rc<CompileUnit>>>,
}

impl Dwarf {
    pub fn new(parent: &Rc<Elf>) -> Result<Rc<Self>, SdbError> {
        let ret = Self {
            elf: parent.clone(),
            abbrev_tables: RefCell::new(HashMap::default()),
            compile_units: RefCell::new(Vec::default()),
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
}
fn parse_compile_units(dwarf: &Rc<Dwarf>, obj: &Elf) -> Result<Vec<Rc<CompileUnit>>, SdbError> {
    let debug_info = obj.get_section_contents(".debug_info");
    let mut cursor = Cursor::new(&debug_info);
    let mut units: Vec<Rc<CompileUnit>> = Vec::new();
    while !cursor.finished() {
        let unit = parse_compile_unit(dwarf, obj, &mut cursor)?;
        cursor += unit.data.len();
        units.push(unit);
    }
    Ok(units)
}

fn parse_compile_unit(
    dwarf: &Rc<Dwarf>,
    _obj: &Elf,
    cursor: &mut Cursor,
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
        return SdbError::err("Only DWARF version 4 is supported");
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
        if code != 0 {
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
        if code == 0 {
            break;
        }
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
    code: u64,
    tag: u64,
    has_children: bool,
    attr_specs: Vec<AttrSpec>,
}

#[derive(Debug)]
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
        !self.data.is_empty()
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

    pub fn sleb128(&mut self) -> u64 {
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
        res
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
        self.data = self.data.slice(rhs..)
    }
}
