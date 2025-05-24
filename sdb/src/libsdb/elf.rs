use nix::libc::{Elf64_Ehdr, Elf64_Shdr};
use nix::{
    fcntl::{OFlag, open},
    sys::{
        mman::{MapFlags, ProtFlags, mmap, munmap},
        stat::{Mode, fstat},
    },
};
use std::collections::HashMap;
use std::ffi::{CStr, c_char};
use std::mem;
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

use super::bit::init_from_bytes;
use super::sdb_error::SdbError;

pub struct Elf {
    fd: OwnedFd,
    path: PathBuf,
    file_size: usize,
    data: Vec<u8>,
    header: Elf64_Ehdr,
    section_headers: Vec<Rc<Elf64_Shdr>>,
    section_map: HashMap<String, Rc<Elf64_Shdr>>,
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

        let header: Elf64_Ehdr = unsafe { init_from_bytes(bytes) };
        let mut ret = Self {
            fd,
            path: path.to_path_buf(),
            file_size,
            data,
            header,
            section_headers: Vec::new(),
            section_map: HashMap::new(),
            _map: map,
        };
        ret.parse_section_headers();
        Ok(ret)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get_header(&self) -> &Elf64_Ehdr {
        &self.header
    }

    fn parse_section_headers(&mut self) {
        let mut n_headers = self.header.e_shnum as usize;

        if n_headers == 0 && self.header.e_shentsize as usize != 0 {
            let sh0: Elf64_Shdr =
                unsafe { init_from_bytes(&self.data[..self.header.e_shoff as usize]) };
            n_headers = sh0.sh_size as usize;
        }

        self.section_headers = Vec::with_capacity(n_headers);
        for i in 0..n_headers {
            let offset = self.header.e_shoff as usize + i * mem::size_of::<Elf64_Ehdr>();
            let sh: Elf64_Shdr = unsafe { init_from_bytes(&self.data[..offset]) };
            self.section_headers.push(Rc::new(sh));
        }
    }

    pub fn get_section_name(&self, index: usize) -> &str {
        let section = &self.section_headers[self.header.e_shstrndx as usize];
        let offset = section.sh_offset as usize + index;
        assert!(
            self.data[offset..].iter().any(|d| { *d == 0 }),
            "Cannot find c-string"
        );
        let ptr = unsafe { self.data.as_ptr().add(offset) } as *const c_char;
        unsafe { CStr::from_ptr(ptr).to_str().unwrap() }
    }

    pub fn get_section(&self, name: &str) -> Option<&Elf64_Shdr> {
        todo!()
    }

    pub fn get_section_contents(&self, name: &str) -> &[u8] {
        todo!()
    }

    fn build_section_map(&mut self) {}
}

impl Drop for Elf {
    fn drop(&mut self) {
        unsafe { munmap(self._map, self.file_size).expect("mmap uniquely managed by Elf object") };
    }
}
