use std::{os::fd::RawFd, path::PathBuf};

use nix::libc::Elf64_Ehdr;

struct Elf{
    fd: RawFd,
    path: PathBuf,
    file_size: usize,
    data: Vec<u8>,
    header: Elf64_Ehdr
}