use bytemuck::{Pod, Zeroable, bytes_of_mut};
use nix::libc::{Elf64_Ehdr, Elf64_Shdr, Elf64_Sym};
use nix::{
    fcntl::{OFlag, open},
    sys::{
        mman::{MapFlags, ProtFlags, mmap, munmap},
        stat::{Mode, fstat},
    },
};
use std::cell::RefCell;
use std::collections::HashMap;
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
    _map: NonNull<c_void>,
}

impl Elf {
    pub fn new(path: &Path) -> Result<Self, SdbError> {
        let raw_fd = open(path, OFlag::O_RDONLY, Mode::empty())
            .map_err(|_| SdbError::new_err("Could not open ELF file"))?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) }; // Owned

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

        let bytes = unsafe { std::slice::from_raw_parts(map.as_ptr() as *const u8, file_size) }; // length
        let mut data = Vec::<u8>::with_capacity(file_size);
        data.extend_from_slice(bytes);

        let header = {
            let mut ret = SdbElf64Ehdr::zeroed();
            bytes_of_mut(&mut ret).copy_from_slice(&bytes[..mem::size_of::<SdbElf64Ehdr>()]);
            ret
        };

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
            _map: map,
        };
        ret.parse_section_headers();
        ret.build_section_map();
        ret.parse_symbol_table();
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
            let sh0: SdbElf64Shdr = {
                let mut ret = SdbElf64Shdr::zeroed();
                bytes_of_mut(&mut ret).copy_from_slice(
                    &self.data[self.header.0.e_shoff as usize..mem::size_of::<SdbElf64Shdr>()],
                );
                ret
            };
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
