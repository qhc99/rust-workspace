use std::{
    cell::RefCell,
    fmt::{Display, LowerHex},
    ops::{Add, AddAssign, Sub, SubAssign},
    rc::{Rc, Weak},
};

use gimli::{
    DW_AT_byte_size, DW_AT_data_bit_offset, DW_AT_data_member_location, DW_AT_encoding, DW_AT_type,
    DW_AT_upper_bound, DW_ATE_signed_char, DW_ATE_unsigned_char, DW_TAG_array_type,
    DW_TAG_base_type, DW_TAG_class_type, DW_TAG_const_type, DW_TAG_enumeration_type, DW_TAG_member,
    DW_TAG_pointer_type, DW_TAG_ptr_to_member_type, DW_TAG_reference_type,
    DW_TAG_rvalue_reference_type, DW_TAG_structure_type, DW_TAG_subrange_type,
    DW_TAG_subroutine_type, DW_TAG_typedef, DW_TAG_union_type, DW_TAG_volatile_type, DwTag,
};
use typed_builder::TypedBuilder;

use super::bit::memcpy_bits;

use super::dwarf::BitfieldInformation;

use super::process::Process;

use super::{dwarf::DieExt, sdb_error::SdbError};

use super::dwarf::Die;

use super::elf::ElfCollection;

use super::elf::Elf;

pub type Byte64 = [u8; 8];
pub type Byte128 = [u8; 16];

#[macro_export]
macro_rules! strip {
    ($value:expr, $( $tag:expr ),+ $(,)?) => {{
        use gimli::DW_AT_type;
        let mut ret = $value.clone();
        let mut tag = ret.get_die().abbrev_entry().tag as u16;
        while false $(|| tag == $tag.0)+ {
            ret = SdbType::new(ret.get_die().index(DW_AT_type.0 as u64)?.as_type().get_die());
            tag = ret.get_die().abbrev_entry().tag as u16;
        }
        Ok(ret)
    }};
}

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

#[derive(Debug, Clone)]
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

    pub fn is_char_type(&self) -> Result<bool, SdbError> {
        let stripped = self.strip_cv_typedef()?.get_die();
        if !stripped.contains(DW_AT_encoding.0 as u64) {
            return Ok(false);
        }
        let encoding = stripped.index(DW_AT_encoding.0 as u64)?.as_int()? as u8;
        return Ok(stripped.abbrev_entry().tag as u16 == DW_TAG_base_type.0
            && encoding == DW_ATE_signed_char.0
            || encoding == DW_ATE_unsigned_char.0);
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

    pub fn strip_cv_typedef(&self) -> Result<Self, SdbError> {
        strip!(
            self,
            DW_TAG_const_type,
            DW_TAG_volatile_type,
            DW_TAG_typedef
        )
    }

    pub fn strip_cvref_typedef(&self) -> Result<Self, SdbError> {
        strip!(
            self,
            DW_TAG_const_type,
            DW_TAG_volatile_type,
            DW_TAG_typedef,
            DW_TAG_reference_type,
            DW_TAG_rvalue_reference_type
        )
    }

    pub fn strip_all(&self) -> Result<Self, SdbError> {
        strip!(
            self,
            DW_TAG_const_type,
            DW_TAG_volatile_type,
            DW_TAG_typedef,
            DW_TAG_reference_type,
            DW_TAG_rvalue_reference_type,
            DW_TAG_pointer_type
        )
    }
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct TypedData {
    data: Vec<u8>,
    type_: SdbType,
    #[builder(default)]
    address: Option<VirtualAddress>,
}

impl TypedData {
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn data_ptr(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn value_type(&self) -> &SdbType {
        &self.type_
    }

    pub fn address(&self) -> Option<VirtualAddress> {
        self.address.clone()
    }

    pub fn fixup_bitfield(&self, proc: &Process, member_die: &Die) -> Result<Self, SdbError> {
        let stripped = self.type_.strip_cv_typedef()?;
        let bitfield_info = member_die.get_bitfield_information(stripped.byte_size()? as u64)?;
        if let Some(bitfield_info) = bitfield_info {
            let BitfieldInformation {
                bit_size,
                storage_byte_size,
                bit_offset,
            } = bitfield_info;
            let mut fixed_data = vec![0u8; storage_byte_size as usize];
            let dest = fixed_data.as_mut_slice();
            let src = self.data().as_slice();
            memcpy_bits(dest, 0, src, bit_offset as u32, bit_size as u32);
            return Ok(TypedData::builder()
                .data(fixed_data)
                .type_(self.type_.clone())
                .build());
        }
        Ok(self.clone())
    }

    pub fn visualize(&self, proc: &Process, depth: i32 /* 0 */) -> Result<String, SdbError> {
        let die = self.type_.get_die();
        #[allow(non_upper_case_globals)]
        match DwTag(die.abbrev_entry().tag as u16) {
            DW_TAG_base_type => Ok(visualize_base_type(self)?),
            DW_TAG_pointer_type => Ok(visualize_pointer_type(proc, self)?),
            DW_TAG_ptr_to_member_type => Ok(visualize_member_pointer_type(self)?),
            DW_TAG_array_type => Ok(visualize_array_type(proc, self)?),
            DW_TAG_class_type | DW_TAG_structure_type | DW_TAG_union_type => {
                Ok(visualize_class_type(proc, self, depth)?)
            }
            DW_TAG_enumeration_type | DW_TAG_typedef | DW_TAG_const_type | DW_TAG_volatile_type => {
                Ok(TypedData::builder()
                    .data(self.data.clone())
                    .type_(die.index(DW_AT_type.0 as u64)?.as_type())
                    .build()
                    .visualize(proc, 0)?)
            }
            _ => SdbError::err("Unsupported type"),
        }
    }
}

fn visualize_base_type(data: &TypedData) -> Result<String, SdbError> {
    todo!()
}

fn visualize_pointer_type(proc: &Process, data: &TypedData) -> Result<String, SdbError> {
    let ptr = data.data_ptr().as_ptr() as u64;
    if ptr == 0 {
        return Ok("0x0".to_string());
    }
    if data
        .value_type()
        .get_die()
        .index(DW_AT_type.0 as u64)?
        .as_type()
        .is_char_type()?
    {
        return Ok(format!(
            "\"{}\"",
            proc.read_string(VirtualAddress::new(ptr))?
        ));
    }
    Ok(format!("0x{:x}", ptr))
}

fn visualize_member_pointer_type(data: &TypedData) -> Result<String, SdbError> {
    Ok(format!("0x{:x}", data.data_ptr().as_ptr() as usize))
}

fn visualize_array_type(proc: &Process, data: &TypedData) -> Result<String, SdbError> {
    todo!()
}

fn visualize_class_type(proc: &Process, data: &TypedData, depth: i32) -> Result<String, SdbError> {
    let mut ret = "{\n".to_string();
    for child in data.value_type().get_die().children() {
        if child.abbrev_entry().tag as u16 == DW_TAG_member.0
            && child.contains(DW_AT_data_member_location.0 as u64)
            || child.contains(DW_AT_data_bit_offset.0 as u64)
        {
            let indent = "\t".repeat(depth as usize + 1);
            let byte_offset = if child.contains(DW_AT_data_member_location.0 as u64) {
                child.index(DW_AT_data_member_location.0 as u64)?.as_int()? as usize
            } else {
                child.index(DW_AT_data_bit_offset.0 as u64)?.as_int()? as usize / 8
            };
            let pos = &data.data_ptr()[byte_offset..];
            let subtype = child.index(DW_AT_type.0 as u64)?.as_type();
            let member_data = &pos[..subtype.byte_size()?];
            let data = TypedData::builder()
                .data(member_data.to_vec())
                .type_(subtype)
                .build()
                .fixup_bitfield(proc, &child)?;
            let member_str = data.visualize(proc, depth + 1)?;
            let name = child.name()?.unwrap_or("<unnamed>".to_string());
            ret.push_str(&format!("{indent}{name}: {member_str}\n"));
        }
    }
    let indent = "\t".repeat(depth as usize);
    ret.push_str(&format!("{indent}}}"));
    Ok(ret)
}
