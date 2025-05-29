use bytemuck::checked::pod_read_unaligned;
use bytemuck::{Pod, Zeroable};
use multimap::MultiMap;
use nix::libc::{Elf64_Ehdr, Elf64_Shdr, Elf64_Sym};
use nix::{
    fcntl::{OFlag, open},
    sys::{
        mman::{MapFlags, ProtFlags, mmap, munmap},
        stat::{Mode, fstat},
    },
};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::{
    num::NonZeroUsize,
    os::{
        fd::{FromRawFd, OwnedFd},
        raw::c_void,
    },
    path::{Path, PathBuf},
    ptr::NonNull,
};

use super::bit::cstr_view;
use super::bit::from_array_bytes;
use super::sdb_error::SdbError;
use super::types::FileAddress;
use super::types::VirtualAddress;
use std::{mem, ptr};

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SdbElf64Ehdr(Elf64_Ehdr);

unsafe impl Pod for SdbElf64Ehdr {}

unsafe impl Zeroable for SdbElf64Ehdr {}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SdbElf64Shdr(Elf64_Shdr);

unsafe impl Pod for SdbElf64Shdr {}

unsafe impl Zeroable for SdbElf64Shdr {}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SdbElf64Sym(Elf64_Sym);

unsafe impl Pod for SdbElf64Sym {}

unsafe impl Zeroable for SdbElf64Sym {}

// TODO add wrapper
pub struct Elf {
    fd: OwnedFd,
    path: PathBuf,
    file_size: usize,
    data: Vec<u8>,
    header: SdbElf64Ehdr,
    section_headers: Vec<Rc<SdbElf64Shdr>>,
    section_map: HashMap<String, Rc<SdbElf64Shdr>>,
    load_bias: VirtualAddress,
    symbol_table: Vec<Rc<SdbElf64Sym>>,
    symbol_name_map: MultiMap<String, Rc<SdbElf64Sym>>,
    symbol_addr_map: BTreeMap<FileAddressRange, Rc<RefCell<SdbElf64Sym>>>,
    _map: NonNull<c_void>,
}

impl Elf {
    pub fn new(path: &Path) -> Result<Self, SdbError> {
        let raw_fd = open(path, OFlag::O_RDONLY, Mode::empty())
            .map_err(|_| SdbError::new_err("Could not open ELF file"))?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let stat =
            fstat(raw_fd).map_err(|_| SdbError::new_err("Could not retrieve ELF file stats"))?;
        let file_size = stat.st_size as usize;

        let map = unsafe {
            mmap(
                None,
                NonZeroUsize::new(file_size).ok_or(SdbError::new_err("ELF file is empty"))?,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                fd.try_clone()
                    .map_err(|_| SdbError::new_err("ELF file is closed"))?,
                0,
            )
            .map_err(|_| SdbError::new_err("Could not mmap ELF file"))?
        };

        let bytes = unsafe { std::slice::from_raw_parts(map.as_ptr() as *const u8, file_size) };
        let mut data = Vec::<u8>::with_capacity(file_size);
        data.extend_from_slice(bytes);

        let header = pod_read_unaligned(&bytes[..mem::size_of::<SdbElf64Ehdr>()]);

        let mut ret = Self {
            fd,
            path: path.to_path_buf(),
            file_size,
            data,
            header,
            section_headers: Vec::default(),
            section_map: HashMap::default(),
            load_bias: 0.into(),
            symbol_table: Vec::default(),
            symbol_name_map: MultiMap::default(),
            symbol_addr_map: BTreeMap::default(),
            _map: map,
        };
        ret.parse_section_headers();
        ret.build_section_map();
        ret.parse_symbol_table();
        ret.build_symbol_maps();
        Ok(ret)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get_header(&self) -> &SdbElf64Ehdr {
        &self.header
    }

    fn parse_section_headers(&mut self) {
        let mut n_headers = self.header.0.e_shnum as usize;

        if n_headers == 0 && self.header.0.e_shentsize as usize != 0 {
            let sh0: SdbElf64Shdr = pod_read_unaligned(
                &self.data[self.header.0.e_shoff as usize..mem::size_of::<SdbElf64Shdr>()],
            );
            n_headers = sh0.0.sh_size as usize;
        }

        let section_headers: Vec<SdbElf64Shdr> = from_array_bytes(
            &self.data[self.header.0.e_shoff as usize
                ..self.header.0.e_shoff as usize + n_headers * mem::size_of::<SdbElf64Shdr>()],
        );
        self.section_headers = section_headers.into_iter().map(Rc::new).collect();
    }

    pub fn get_section_name(&self, index: usize) -> &str {
        let section = &self.section_headers[self.header.0.e_shstrndx as usize];
        let offset = section.0.sh_offset as usize + index;
        cstr_view(&self.data[offset..])
    }

    pub fn get_section(&self, name: &str) -> Option<Rc<SdbElf64Shdr>> {
        self.section_map.get(name).cloned()
    }

    pub fn get_section_contents(&self, name: &str) -> Vec<u8> {
        if let Some(section) = self.get_section(name) {
            let mut ret = Vec::with_capacity(section.0.sh_size as usize);
            ret.extend_from_slice(
                &self.data[section.0.sh_offset as usize
                    ..(section.0.sh_offset + section.0.sh_size) as usize],
            );
            return ret;
        }
        return vec![];
    }

    fn build_section_map(&mut self) {
        for section in &self.section_headers {
            self.section_map.insert(
                self.get_section_name(section.0.sh_name as usize)
                    .to_string(),
                section.clone(),
            );
        }
    }

    pub fn get_string(&self, index: usize) -> &str {
        let mut opt_strtab = self.get_section(".strtab");
        if opt_strtab.is_none() {
            opt_strtab = self.get_section(".dynstr");
            if opt_strtab.is_none() {
                return "";
            }
        }
        cstr_view(&self.data[opt_strtab.unwrap().0.sh_offset as usize + index..])
    }

    pub fn load_bias(&self) -> VirtualAddress {
        self.load_bias
    }

    pub fn notify_loaded(&mut self, address: VirtualAddress) {
        self.load_bias = address
    }

    pub fn get_section_containing_file_addr(
        &self,
        address: &FileAddress,
    ) -> Option<Rc<SdbElf64Shdr>> {
        if ptr::eq(self, &*address.elf_file().borrow()) {
            for section in &self.section_headers {
                if section.0.sh_addr <= address.addr()
                    && (section.0.sh_addr + section.0.sh_size) > address.addr()
                {
                    return Some(section.clone());
                }
            }
        }

        return None;
    }
    pub fn get_section_containing_virt_addr(
        &self,
        address: VirtualAddress,
    ) -> Option<Rc<SdbElf64Shdr>> {
        for section in &self.section_headers {
            if (self.load_bias + section.0.sh_addr as i64) <= address
                && (self.load_bias + section.0.sh_addr as i64 + section.0.sh_size as i64) > address
            {
                return Some(section.clone());
            }
        }
        return None;
    }

    fn parse_symbol_table(&mut self) {
        let mut opt_symtab = self.get_section(".symtab");
        if opt_symtab.is_none() {
            opt_symtab = self.get_section(".dynsym");
            if opt_symtab.is_none() {
                return;
            }
        }
        let symtab = opt_symtab.unwrap();
        let symtab: Vec<SdbElf64Sym> = from_array_bytes(
            &self.data[symtab.0.sh_offset as usize
                ..symtab.0.sh_offset as usize + symtab.0.sh_size as usize],
        );
        self.symbol_table = symtab.into_iter().map(Rc::new).collect()
    }

    pub fn get_symbols_by_name(name: &str) -> Vec<Rc<SdbElf64Sym>> {
        todo!()
    }

    pub fn get_symbol_at_file_address(address: FileAddress) -> Option<Rc<SdbElf64Sym>> {
        todo!()
    }

    pub fn get_symbol_at_virt_address(address: VirtualAddress) -> Option<Rc<SdbElf64Sym>> {
        todo!()
    }

    pub fn get_symbol_containing_file_address(address: FileAddress) -> Option<Rc<SdbElf64Sym>> {
        todo!()
    }

    pub fn get_symbol_containin_virt_address(address: VirtualAddress) -> Option<Rc<SdbElf64Sym>> {
        todo!()
    }

    fn build_symbol_maps(&mut self) {
        todo!()
    }
}

#[derive(Debug)]
struct FileAddressRange(FileAddress, FileAddress);

impl PartialEq for FileAddressRange {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl Eq for FileAddressRange {}

impl PartialOrd for FileAddressRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileAddressRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

pub trait ElfExt {
    fn get_section_start_address(&self, name: &str) -> Option<FileAddress>;
}

impl ElfExt for Rc<RefCell<Elf>> {
    fn get_section_start_address(&self, name: &str) -> Option<FileAddress> {
        return self
            .borrow()
            .get_section(name)
            .map(|section| FileAddress::new(self, section.0.sh_addr));
    }
}

impl Drop for Elf {
    fn drop(&mut self) {
        unsafe { munmap(self._map, self.file_size).expect("mmap uniquely managed by Elf object") };
    }
}
