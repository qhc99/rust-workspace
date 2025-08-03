use std::{
    cell::RefCell,
    fmt::{Display, LowerHex},
    ops::{Add, AddAssign, Sub, SubAssign},
    rc::{Rc, Weak},
};

use gimli::{
    DW_AT_byte_size, DW_AT_data_bit_offset, DW_AT_data_member_location, DW_AT_encoding, DW_AT_type,
    DW_AT_upper_bound, DW_ATE_UTF, DW_ATE_boolean, DW_ATE_float, DW_ATE_signed, DW_ATE_signed_char,
    DW_ATE_unsigned, DW_ATE_unsigned_char, DW_TAG_array_type, DW_TAG_base_type, DW_TAG_class_type,
    DW_TAG_const_type, DW_TAG_enumeration_type, DW_TAG_member, DW_TAG_pointer_type,
    DW_TAG_ptr_to_member_type, DW_TAG_reference_type, DW_TAG_rvalue_reference_type,
    DW_TAG_structure_type, DW_TAG_subrange_type, DW_TAG_subroutine_type, DW_TAG_typedef,
    DW_TAG_union_type, DW_TAG_volatile_type, DwAte, DwTag,
};
use typed_builder::TypedBuilder;

use super::{bit::from_bytes, registers::F80};

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
        let mut tag = ret.get_die()?.abbrev_entry().tag as u16;
        while false $(|| tag == $tag.0)+ {
            ret = SdbType::new(ret.get_die()?.index(DW_AT_type.0 as u64)?.as_type().get_die()?);
            tag = ret.get_die()?.abbrev_entry().tag as u16;
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
    byte_size: RefCell<Option<usize>>,
    info: SdbTypeInfo,
}

#[derive(Debug, Clone)]
pub enum SdbTypeInfo {
    Die(Rc<Die>),
    BuiltinType(BuiltinType),
}

impl SdbType {
    pub fn new(die: Rc<Die>) -> Self {
        Self {
            byte_size: RefCell::new(None),
            info: SdbTypeInfo::Die(die),
        }
    }

    pub fn new_from_info(info: SdbTypeInfo) -> Self {
        Self {
            byte_size: RefCell::new(None),
            info,
        }
    }

    pub fn get_die(&self) -> Result<Rc<Die>, SdbError> {
        match &self.info {
            SdbTypeInfo::Die(die) => Ok(die.clone()),
            _ => SdbError::err("Type is not from DWARF info"),
        }
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
        let stripped = self.strip_cv_typedef()?.get_die()?;
        if !stripped.contains(DW_AT_encoding.0 as u64) {
            return Ok(false);
        }
        let encoding = stripped.index(DW_AT_encoding.0 as u64)?.as_int()? as u8;
        return Ok(stripped.abbrev_entry().tag as u16 == DW_TAG_base_type.0
            && encoding == DW_ATE_signed_char.0
            || encoding == DW_ATE_unsigned_char.0);
    }

    fn compute_byte_size(&self) -> Result<usize, SdbError> {
        let die = self.get_die()?;
        let tag = die.abbrev_entry().tag;

        if tag as u16 == DW_TAG_pointer_type.0 {
            return Ok(8);
        }
        if tag as u16 == DW_TAG_ptr_to_member_type.0 {
            let member_type = die.index(DW_AT_type.0 as u64)?.as_type();
            if member_type.get_die()?.abbrev_entry().tag as u16 == DW_TAG_subroutine_type.0 {
                return Ok(16);
            }
            return Ok(8);
        }
        if tag as u16 == DW_TAG_array_type.0 {
            let mut value_size = die.index(DW_AT_type.0 as u64)?.as_type().byte_size()?;
            for child in die.children() {
                if child.abbrev_entry().tag as u16 == DW_TAG_subrange_type.0 {
                    value_size *= (child.index(DW_AT_upper_bound.0 as u64)?.as_int()? + 1) as usize;
                }
            }
            return Ok(value_size);
        }
        if die.contains(DW_AT_byte_size.0 as u64) {
            return Ok(die.index(DW_AT_byte_size.0 as u64)?.as_int()? as usize);
        }
        if die.contains(DW_AT_type.0 as u64) {
            return die.index(DW_AT_type.0 as u64)?.as_type().byte_size();
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

    pub fn get_builtin_type(&self) -> Result<BuiltinType, SdbError> {
        match &self.info {
            SdbTypeInfo::BuiltinType(builtin_type) => Ok(*builtin_type),
            _ => SdbError::err("Type is not a builtin type"),
        }
    }

    pub fn is_from_dwarf(&self) -> bool {
        match &self.info {
            SdbTypeInfo::Die(_) => true,
            _ => false,
        }
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
        self.address
    }

    pub fn fixup_bitfield(&self, _proc: &Process, member_die: &Die) -> Result<Self, SdbError> {
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

    pub fn deref_pointer(&self, proc: &Process) -> Result<TypedData, SdbError> {
        let stripped_type_die = self.type_.strip_cv_typedef()?.get_die()?;
        let tag = stripped_type_die.abbrev_entry().tag;
        if tag as u16 != DW_TAG_pointer_type.0 {
            return SdbError::err("Not a pointer type");
        }
        let address = VirtualAddress::new(from_bytes::<u64>(&self.data));
        let value_type = stripped_type_die.index(DW_AT_type.0 as u64)?.as_type();
        let data_vec = proc.read_memory(address, value_type.byte_size()?)?;
        Ok(TypedData::builder()
            .data(data_vec)
            .type_(value_type)
            .address(Some(address))
            .build())
    }

    pub fn read_member(&self, proc: &Process, member_name: &str) -> Result<TypedData, SdbError> {
        let die = self.type_.get_die()?;
        let mut children = die.children();
        let it = children.find(|child| {
            child
                .name()
                .map(|v| v.unwrap_or_default())
                .unwrap_or_default()
                == member_name
        });
        if it.is_none() {
            return SdbError::err("No such member");
        }
        let var = it.unwrap();
        let value_type = var.index(DW_AT_type.0 as u64)?.as_type();
        let byte_offset = if var.contains(DW_AT_data_member_location.0 as u64) {
            var.index(DW_AT_data_member_location.0 as u64)?.as_int()? as usize
        } else {
            var.index(DW_AT_data_bit_offset.0 as u64)?.as_int()? as usize / 8
        };
        let data_start = &self.data.as_slice()[byte_offset..];
        let member_data = &data_start[..value_type.byte_size()?];
        let data = if self.address.is_some() {
            TypedData::builder()
                .data(member_data.to_vec())
                .type_(value_type.clone())
                .address(Some(self.address.unwrap() + byte_offset as i64))
                .build()
        } else {
            TypedData::builder()
                .data(member_data.to_vec())
                .type_(value_type)
                .build()
        };
        return data.fixup_bitfield(proc, &var);
    }

    pub fn index(&self, _proc: &Process, index: usize) -> Result<TypedData, SdbError> {
        let parent_type = self.type_.strip_cv_typedef()?.get_die()?;
        let tag = parent_type.abbrev_entry().tag;
        if tag as u16 != DW_TAG_array_type.0 && tag as u16 != DW_TAG_pointer_type.0 {
            return SdbError::err("Not an array or pointer type");
        }
        let value_type = parent_type.index(DW_AT_type.0 as u64)?.as_type();
        let element_size = value_type.byte_size()?;
        let offset = index * element_size;
        if tag as u16 == DW_TAG_pointer_type.0 {
            let address = VirtualAddress::new(from_bytes::<u64>(&self.data)) + offset as i64;
            let data_vec = _proc.read_memory(address, element_size)?;
            return Ok(TypedData::builder()
                .data(data_vec)
                .type_(value_type)
                .address(Some(address))
                .build());
        } else {
            let data_vec = self.data[offset..offset + element_size].to_vec();
            if let Some(address) = self.address {
                return Ok(TypedData::builder()
                    .data(data_vec)
                    .type_(value_type)
                    .address(Some(address + offset as i64))
                    .build());
            }
            return Ok(TypedData::builder()
                .data(data_vec)
                .type_(value_type)
                .build());
        }
    }

    pub fn visualize(&self, proc: &Process, depth: i32 /* 0 */) -> Result<String, SdbError> {
        let die = self.type_.get_die()?;
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
    let type_ = data.value_type();
    let die = type_.get_die()?;
    let ptr = data.data_ptr();
    #[allow(non_upper_case_globals)]
    match DwAte(die.index(DW_AT_encoding.0 as u64)?.as_int()? as u8) {
        DW_ATE_boolean => Ok((ptr[0] != 0).to_string()),
        DW_ATE_float => {
            if die.name()?.unwrap() == "float" {
                Ok((from_bytes::<f32>(ptr)).to_string())
            } else if die.name()?.unwrap() == "double" {
                Ok((from_bytes::<f64>(ptr)).to_string())
            } else if die.name()?.unwrap() == "long double" {
                Ok((from_bytes::<F80>(ptr)).to_string())
            } else {
                SdbError::err("Unsupported floating point type")
            }
        }
        DW_ATE_signed => match type_.byte_size()? {
            1 => Ok(from_bytes::<i8>(ptr).to_string()),
            2 => Ok(from_bytes::<i16>(ptr).to_string()),
            4 => Ok(from_bytes::<i32>(ptr).to_string()),
            8 => Ok(from_bytes::<i64>(ptr).to_string()),
            _ => SdbError::err("Unsupported signed integer size"),
        },
        DW_ATE_unsigned => match type_.byte_size()? {
            1 => Ok(from_bytes::<u8>(ptr).to_string()),
            2 => Ok(from_bytes::<u16>(ptr).to_string()),
            4 => Ok(from_bytes::<u32>(ptr).to_string()),
            8 => Ok(from_bytes::<u64>(ptr).to_string()),
            _ => SdbError::err("Unsupported unsigned integer size"),
        },
        DW_ATE_signed_char => Ok(from_bytes::<i8>(ptr).to_string()),
        DW_ATE_unsigned_char => Ok(from_bytes::<u8>(ptr).to_string()),
        DW_ATE_UTF => SdbError::err("DW_ATE_UTF is not implemented"),
        _ => SdbError::err("Unsupported encoding"),
    }
}

fn visualize_pointer_type(proc: &Process, data: &TypedData) -> Result<String, SdbError> {
    let ptr = from_bytes::<u64>(data.data_ptr());
    if ptr == 0 {
        return Ok("0x0".to_string());
    }
    if data
        .value_type()
        .get_die()?
        .index(DW_AT_type.0 as u64)?
        .as_type()
        .is_char_type()?
    {
        return Ok(format!(
            "\"{}\"",
            proc.read_string(VirtualAddress::new(ptr))?
        ));
    }
    Ok(format!("0x{ptr:x}"))
}

fn visualize_member_pointer_type(data: &TypedData) -> Result<String, SdbError> {
    Ok(format!("0x{:x}", from_bytes::<usize>(data.data_ptr())))
}

fn visualize_array_type(proc: &Process, data: &TypedData) -> Result<String, SdbError> {
    let mut dimensions = Vec::new();
    for child in data.value_type().get_die()?.children() {
        if child.abbrev_entry().tag as u16 == DW_TAG_subrange_type.0 {
            dimensions.push(child.index(DW_AT_upper_bound.0 as u64)?.as_int()? as usize + 1);
        }
    }
    dimensions.reverse();
    let value_type = data
        .value_type()
        .get_die()?
        .index(DW_AT_type.0 as u64)?
        .as_type();
    visualize_subrange(proc, &value_type, data.data(), dimensions)
}

fn visualize_subrange(
    proc: &Process,
    value_type: &SdbType,
    data: &[u8],
    mut dimensions: Vec<usize>,
) -> Result<String, SdbError> {
    if dimensions.is_empty() {
        let data_vec = data.to_vec();
        return TypedData::builder()
            .data(data_vec)
            .type_(value_type.clone())
            .build()
            .visualize(proc, 0);
    }
    let mut ret = "[".to_string();
    let size = dimensions.pop().unwrap();
    let sub_size = dimensions
        .iter()
        .fold(value_type.byte_size()?, |acc, dim| acc * dim);
    for i in 0..size {
        let subdata = &data[i * sub_size..];
        ret.push_str(&visualize_subrange(
            proc,
            value_type,
            subdata,
            dimensions.clone(),
        )?);
        if i != size - 1 {
            ret.push_str(", ");
        }
    }
    Ok(ret + "]")
}

fn visualize_class_type(proc: &Process, data: &TypedData, depth: i32) -> Result<String, SdbError> {
    let mut ret = "{\n".to_string();
    for child in data.value_type().get_die()?.children() {
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

#[derive(Debug, Clone, Copy)]
pub enum BuiltinType {
    String,
    Character,
    Integer,
    Boolean,
    FloatingPoint,
}
