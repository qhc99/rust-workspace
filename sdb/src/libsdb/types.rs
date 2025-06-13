use std::{
    cell::RefCell,
    fmt::{Display, LowerHex},
    ops::{Add, AddAssign, Sub, SubAssign},
    rc::{Rc, Weak},
};

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
    elf: Weak<RefCell<Elf>>,
}

impl FileOffset {
    pub fn new(elf: &Rc<RefCell<Elf>>, addr: u64) -> Self {
        Self {
            addr,
            elf: Rc::downgrade(elf),
        }
    }

    pub fn offset(&self) -> u64 {
        self.addr
    }

    pub fn elf_file(&self) -> Rc<RefCell<Elf>> {
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

    pub fn elf_file(&self) -> Rc<Elf> {
        self.elf.upgrade().unwrap()
    }

    pub fn to_virtual_address(&self) -> VirtualAddress {
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

    pub fn to_file_addr(self, elf: &Rc<Elf>) -> FileAddress {
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
    pub fn get_addr(&self) -> u64 {
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
