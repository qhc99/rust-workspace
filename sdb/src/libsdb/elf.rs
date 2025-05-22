use std::{
    num::NonZeroUsize,
    os::{
        fd::{FromRawFd, OwnedFd},
        raw::c_void,
    },
    path::{Path, PathBuf},
    ptr::NonNull,
};

use nix::libc::Elf64_Ehdr;
use std::{mem, ptr};

use nix::{
    fcntl::{OFlag, open},
    sys::{
        mman::{MapFlags, ProtFlags, mmap, munmap},
        stat::{Mode, fstat},
    },
};

use super::sdb_error::SdbError;

pub struct Elf {
    fd: OwnedFd,
    path: PathBuf,
    file_size: usize,
    data: Vec<u8>,
    header: Elf64_Ehdr,
    map: NonNull<c_void>,
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

        let header: Elf64_Ehdr = {
            let mut hdr: Elf64_Ehdr = unsafe { mem::zeroed() };
            let hdr_bytes = &bytes[..mem::size_of::<Elf64_Ehdr>()];
            unsafe {
                ptr::copy_nonoverlapping(
                    hdr_bytes.as_ptr(),
                    &mut hdr as *mut _ as *mut u8,
                    mem::size_of::<Elf64_Ehdr>(),
                );
            }
            hdr
        };

        Ok(Self {
            fd,
            path: path.to_path_buf(),
            file_size,
            data,
            header,
            map,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get_header(&self) -> &Elf64_Ehdr {
        &self.header
    }
}

impl Drop for Elf {
    fn drop(&mut self) {
        unsafe { munmap(self.map, self.file_size).expect("mmap uniquely managed by Elf object") };
    }
}
