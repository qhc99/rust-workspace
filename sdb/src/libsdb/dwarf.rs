use std::cell::RefCell;
use std::ffi::CStr;
use std::rc::Weak;
use std::{collections::HashMap, ops::AddAssign, rc::Rc};

use bytemuck::Pod;
use bytes::Bytes;

use super::bit::from_bytes;
use super::elf::Elf;

#[derive(Debug)]
pub struct CompileUnit {
    parent: Weak<Dwarf>,
    data: Bytes,
    abbrev_offset: usize,
}

impl CompileUnit {
    pub fn new(parent: &Rc<Dwarf>, data: &Bytes, abbrev_offset: usize) -> Rc<Self> {
        Rc::new(Self {
            parent: Rc::downgrade(parent),
            data: data.clone(),
            abbrev_offset,
        })
    }

    pub fn dwarf_info(&self) -> Rc<Dwarf> {
        self.parent.upgrade().unwrap()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn abbrev_table(&self) -> Rc<HashMap<u64, Abbrev>> {
        self.parent
            .upgrade()
            .unwrap()
            .get_abbrev_table(self.abbrev_offset)
    }
}

#[derive(Debug)]
pub struct Dwarf {
    elf: Rc<Elf>,
    abbrev_tables: RefCell<HashMap<usize, Rc<HashMap<u64, Abbrev>>>>,
    compile_units: Vec<Rc<CompileUnit>>,
}

impl Dwarf {
    pub fn new(parent: &Rc<Elf>) -> Rc<Self> {
        let mut obj = Self {
            elf: parent.clone(),
            abbrev_tables: RefCell::new(HashMap::default()),
            compile_units: Vec::default(),
        };
        let t = parse_compile_units(&mut obj, parent);
        obj.compile_units = t;
        Rc::new(obj)
    }

    pub fn elf_file(&self) -> Rc<Elf> {
        self.elf.clone()
    }

    pub fn get_abbrev_table(&self, offset: usize) -> Rc<HashMap<u64, Abbrev>> {
        if !self.abbrev_tables.borrow().contains_key(&offset) {
            self.abbrev_tables
                .borrow_mut()
                .insert(offset, Rc::new(parse_abbrev_table(&self.elf, offset)));
        }
        self.abbrev_tables.borrow()[&offset].clone()
    }

    pub fn compile_units(&self) -> &Vec<Rc<CompileUnit>> {
        &self.compile_units
    }
}
fn parse_compile_units(dwarf: &mut Dwarf, obj: &Elf) -> Vec<Rc<CompileUnit>> {
    let debug_info = obj.get_section_contents(".debug_info");
    let mut cursor = Cursor::new(debug_info, 0);
    let mut units: Vec<Rc<CompileUnit>> = Vec::new();
    while !cursor.finished() {
        let unit = parse_compile_unit(dwarf, obj, &mut cursor);
        cursor += unit.data.len();
        units.push(unit);
    }
    units
}

fn parse_compile_unit(dwarf: &Dwarf, obj: &Elf, cursor: &mut Cursor) -> Rc<CompileUnit> {
    todo!()
}
/**
std::unique_ptr<sdb::compile_unit> parse_compile_unit(
    sdb::dwarf& dwarf, const sdb::elf& obj, cursor cur) {
    auto start = cur.position();
    auto size = cur.u32();
    auto version = cur.u16();
    auto abbrev = cur.u32();
    auto address_size = cur.u8();
    if (size == 0xffffffff) {
        sdb::error::send("Only DWARF32 is supported");
    }
    if (version != 4) {
        sdb::error::send("Only DWARF version 4 is supported");
    }
    if (address_size != 8) {
        sdb::error::send("Invalid address size for DWARF");
    }
    size += sizeof(std::uint32_t);
    sdb::span<const std::byte> data = { start, size };
    return std::make_unique<sdb::compile_unit>(dwarf, data, abbrev);
}
 *
 */

fn parse_abbrev_table(obj: &Elf, offset: usize) -> HashMap<u64, Abbrev> {
    let mut cursor = Cursor::new(obj.get_section_contents(".debug_abbrev"), 0);
    cursor += offset;
    let mut table: HashMap<u64, Abbrev> = HashMap::new();
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
                Abbrev {
                    code,
                    tag,
                    has_children,
                    attr_specs,
                },
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
struct Cursor<'this> {
    data: &'this [u8],
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

impl<'this> Cursor<'this> {
    pub fn new(data: &'this [u8], pos: usize) -> Self {
        Self { data: &data[pos..] }
    }

    pub fn finished(&self) -> bool {
        self.data.len() > 0
    }

    pub fn fixed_int<T: Pod>(&mut self) -> T {
        let t = from_bytes::<T>(self.data);
        self.data = &self.data[size_of::<T>()..];
        t
    }

    pub fn string(&mut self) -> &str {
        if let Some(pos) = self.data.iter().position(|&b| b == 0) {
            let next = pos + 1;
            let s = CStr::from_bytes_with_nul(&self.data[..next])
                .unwrap()
                .to_str()
                .unwrap();
            if next < self.data.len() {
                self.data = &self.data[next..];
            } else {
                self.data = &[];
            }
            return s;
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
        if ((shift as usize) < size_of::<u64>() * 8) && (byte & 0x40) != 0 {
            res |= !0u64 << shift;
        }
        res
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

impl<'this> AddAssign<usize> for Cursor<'this> {
    fn add_assign(&mut self, rhs: usize) {
        self.data = &self.data[rhs..]
    }
}
