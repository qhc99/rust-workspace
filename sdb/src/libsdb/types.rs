use std::{
    cell::RefCell,
    fmt::{Display, LowerHex},
    ops::{Add, AddAssign, Sub, SubAssign},
    rc::{Rc, Weak},
};

use gimli::{
    DW_AT_byte_size, DW_AT_type, DW_AT_upper_bound, DW_TAG_array_type, DW_TAG_pointer_type,
    DW_TAG_ptr_to_member_type, DW_TAG_subrange_type, DW_TAG_subroutine_type,
};

use super::{dwarf::DieExt, sdb_error::SdbError};

use super::dwarf::Die;

use super::elf::ElfCollection;

use super::elf::Elf;

pub type Byte64 = [u8; 8];
pub type Byte128 = [u8; 16];

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct VirtualAddress {
    addr: u64,
}

#[derive(Default, Debug)]
pub struct FileOffset {
    addr: u64,
    elf: Weak<Elf>,
}

impl FileOffset {
    pub fn new(elf: &Rc<Elf>, addr: u64) -> Self {
        Self {
            addr,
            elf: Rc::downgrade(elf),
        }
    }

    pub fn off(&self) -> u64 {
        self.addr
    }

    pub fn elf_file(&self) -> Rc<Elf> {
        self.elf.upgrade().unwrap()
    }
}

#[derive(Default, Debug, Clone)]
pub struct FileAddress {
    addr: u64,
    elf: Weak<Elf>,
}

impl FileAddress {
    pub fn new(elf: &Rc<Elf>, addr: u64) -> Self {
        Self {
            addr,
            elf: Rc::downgrade(elf),
        }
    }

    pub fn null() -> Self {
        FileAddress::default()
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn rc_elf_file(&self) -> Rc<Elf> {
        self.elf.upgrade().unwrap()
    }

    pub fn weak_elf_file(&self) -> Weak<Elf> {
        self.elf.clone()
    }

    pub fn has_elf(&self) -> bool {
        self.elf.upgrade().is_some()
    }

    pub fn to_virt_addr(&self) -> VirtualAddress {
        let elf = self.elf.upgrade();
        assert!(elf.is_some());
        let elf = elf.unwrap();
        let section = elf.get_section_containing_file_addr(self);

        return match section {
            Some(_) => VirtualAddress {
                addr: self.addr + elf.load_bias().addr,
            },
            None => VirtualAddress::default(),
        };
    }
}

impl PartialEq for FileAddress {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.elf.ptr_eq(&other.elf)
    }
}

impl Eq for FileAddress {}

impl PartialOrd for FileAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        assert!(self.elf.ptr_eq(&other.elf));
        self.addr.cmp(&other.addr)
    }
}

impl Add<i64> for FileAddress {
    type Output = FileAddress;

    fn add(self, rhs: i64) -> Self::Output {
        Self {
            addr: (self.addr as i128 + rhs as i128) as u64,
            elf: self.elf,
        }
    }
}

impl AddAssign<i64> for FileAddress {
    fn add_assign(&mut self, rhs: i64) {
        self.addr = (self.addr as i128 + rhs as i128) as u64;
    }
}

impl Sub<i64> for FileAddress {
    type Output = FileAddress;

    fn sub(self, rhs: i64) -> Self::Output {
        Self {
            addr: (self.addr as i128 - rhs as i128) as u64,
            elf: self.elf,
        }
    }
}

impl SubAssign<i64> for FileAddress {
    fn sub_assign(&mut self, rhs: i64) {
        self.addr = (self.addr as i128 - rhs as i128) as u64;
    }
}

impl VirtualAddress {
    pub fn new(addr: u64) -> Self {
        Self { addr }
    }

    pub fn to_file_addr_elf(self, elf: &Rc<Elf>) -> FileAddress {
        let obj = elf;
        let section = obj.get_section_containing_virt_addr(self);
        return match section {
            Some(_) => FileAddress {
                addr: self.addr - obj.load_bias().addr,
                elf: Rc::downgrade(elf),
            },
            None => FileAddress::default(),
        };
    }

    pub fn to_file_addr_elves(self, elves: &ElfCollection) -> FileAddress {
        let obj = elves.get_elf_containing_address(self);
        if obj.upgrade().is_none() {
            return FileAddress::default();
        }
        return self.to_file_addr_elf(&obj.upgrade().unwrap());
    }
}

impl LowerHex for VirtualAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(&self.addr, f)
    }
}

impl From<u64> for VirtualAddress {
    fn from(value: u64) -> Self {
        Self { addr: value }
    }
}

impl VirtualAddress {
    pub fn addr(&self) -> u64 {
        self.addr
    }
}

impl Add<i64> for VirtualAddress {
    type Output = VirtualAddress;

    fn add(self, rhs: i64) -> Self::Output {
        Self {
            addr: (self.addr as i128 + rhs as i128) as u64,
        }
    }
}

impl AddAssign<i64> for VirtualAddress {
    fn add_assign(&mut self, rhs: i64) {
        self.addr = (self.addr as i128 + rhs as i128) as u64;
    }
}

impl Sub<i64> for VirtualAddress {
    type Output = VirtualAddress;

    fn sub(self, rhs: i64) -> Self::Output {
        Self {
            addr: (self.addr as i128 - rhs as i128) as u64,
        }
    }
}

impl SubAssign<i64> for VirtualAddress {
    fn sub_assign(&mut self, rhs: i64) {
        self.addr = (self.addr as i128 - rhs as i128) as u64;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum StoppointMode {
    Write,
    ReadWrite,
    Execute,
}

impl Display for StoppointMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            StoppointMode::Write => write!(f, "write"),
            StoppointMode::ReadWrite => write!(f, "read_write"),
            StoppointMode::Execute => write!(f, "execute"),
        }
    }
}

pub struct SdbType {
    die: Rc<Die>,
    byte_size: RefCell<Option<usize>>,
}

impl SdbType {
    pub fn new(die: Rc<Die>) -> Self {
        Self {
            die,
            byte_size: RefCell::new(None),
        }
    }

    pub fn get_die(&self) -> Rc<Die> {
        self.die.clone()
    }

    pub fn byte_size(&self) -> Result<usize, SdbError> {
        if self.byte_size.borrow().is_none() {
            self.byte_size
                .borrow_mut()
                .replace(self.compute_byte_size()?);
        }
        return Ok(self.byte_size.borrow().unwrap());
    }

    pub fn is_char_type(&self) -> bool {
        todo!()
    }

    fn compute_byte_size(&self) -> Result<usize, SdbError> {
        let tag = self.die.abbrev_entry().tag;

        if tag as u16 == DW_TAG_pointer_type.0 {
            return Ok(8);
        }
        if tag as u16 == DW_TAG_ptr_to_member_type.0 {
            let member_type = self.die.index(DW_AT_type.0 as u64)?.as_type();
            if member_type.get_die().abbrev_entry().tag as u16 == DW_TAG_subroutine_type.0 {
                return Ok(16);
            }
            return Ok(8);
        }
        if tag as u16 == DW_TAG_array_type.0 {
            let mut value_size = self.die.index(DW_AT_type.0 as u64)?.as_type().byte_size()?;
            for child in self.die.children() {
                if child.abbrev_entry().tag as u16 == DW_TAG_subrange_type.0 {
                    value_size *= (child.index(DW_AT_upper_bound.0 as u64)?.as_int()? + 1) as usize;
                }
            }
            return Ok(value_size);
        }
        if self.die.contains(DW_AT_byte_size.0 as u64) {
            return Ok(self.die.index(DW_AT_byte_size.0 as u64)?.as_int()? as usize);
        }
        if self.die.contains(DW_AT_type.0 as u64) {
            return self.die.index(DW_AT_type.0 as u64)?.as_type().byte_size();
        }

        return Ok(0);
    }
}
