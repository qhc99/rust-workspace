use super::bit::from_bytes;
use super::breakpoint_site::BreakpointSite;
use super::breakpoint_site::IdType;
use super::pipe::Pipe;
use super::register_info::RegisterId;
use super::register_info::register_info_by_id;
use super::registers::Registers;
use super::sdb_error::SdbError;
use super::stoppoint_collection::StoppointCollection;
use super::target::Target;
use super::traits::StoppointTrait;
use super::types::StoppointMode;
use super::types::VirtualAddress;
use super::utils::ResultLogExt;
use super::watchpoint::WatchPoint;
use bytemuck::Pod;
use bytemuck::bytes_of_mut;
use byteorder::NativeEndian;
use byteorder::ReadBytesExt;
use nix::libc::AT_NULL;
use nix::libc::PTRACE_GETFPREGS;
use nix::libc::ptrace;
use nix::sys::personality::Persona;
use nix::sys::personality::set as set_personality;
use nix::sys::ptrace::AddressType;
use nix::sys::ptrace::Options;
use nix::sys::ptrace::cont;
use nix::sys::ptrace::getsiginfo;
use nix::sys::ptrace::setoptions;
use nix::sys::ptrace::step;
use nix::sys::ptrace::syscall;
use nix::sys::ptrace::write;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::signal::kill;
use nix::sys::uio::RemoteIoVec;
use nix::sys::uio::process_vm_readv;
use nix::unistd::dup2;
use nix::{
    errno::Errno,
    libc::{
        PTRACE_SETFPREGS, PTRACE_SETREGS, SI_KERNEL, TRAP_HWBKPT, TRAP_TRACE, setpgid,
        user_fpregs_struct, user_regs_struct,
    },
    sys::{
        ptrace::{attach as nix_attach, detach, getregs, read_user, write_user},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
};
use nix::{
    sys::ptrace::traceme,
    unistd::{ForkResult, Pid, execvp, fork},
};
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::c_long;
use std::fs::File;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;
use std::rc::Weak;
use std::{cell::RefCell, ffi::CString, os::raw::c_void, path::Path, process::exit, rc::Rc};
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated,
}

#[derive(Debug, Clone, Copy)]
pub struct StopReason {
    pub reason: ProcessState,
    pub info: i32,
    pub trap_reason: Option<TrapType>,
    pub syscall_info: Option<SyscallInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapType {
    SingleStep,
    SoftwareBreak,
    HardwareBreak,
    Syscall,
    Unknown,
}

impl StopReason {
    fn new(status: WaitStatus) -> Result<Self, SdbError> {
        if let WaitStatus::Exited(_, info) = status {
            return Ok(StopReason {
                reason: ProcessState::Exited,
                info,
                trap_reason: None,
                syscall_info: None,
            });
        } else if let WaitStatus::Signaled(_, info, _) = status {
            return Ok(StopReason {
                reason: ProcessState::Terminated,
                info: info as i32,
                trap_reason: None,
                syscall_info: None,
            });
        } else if let WaitStatus::Stopped(_, info) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: info as i32,
                trap_reason: None,
                syscall_info: None,
            });
        } else if let WaitStatus::PtraceEvent(_, info, _) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: info as i32,
                trap_reason: None,
                syscall_info: None,
            });
        } else if let WaitStatus::PtraceSyscall(_) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: SIGTRAP as i32,
                trap_reason: Some(TrapType::Syscall),
                syscall_info: None,
            });
        }

        SdbError::err(&format!("Unhandled wait status {status:?}"))
    }
}

fn set_ptrace_options(pid: Pid) -> Result<(), SdbError> {
    setoptions(pid, Options::PTRACE_O_TRACESYSGOOD)
        .map_err(|errno| SdbError::new_errno("Failed to set TRACESYSGOOD option", errno))
}

#[derive(Debug, PartialEq, Eq, Default)]
pub enum SyscallCatchPolicy {
    #[default]
    None,
    Some(Vec<i32>),
    All,
}

#[derive(Debug, Clone, Copy)]
pub struct SyscallInfo {
    pub id: u16,
    pub data: SyscallData,
}

#[derive(Debug, Clone, Copy)]
pub enum SyscallData {
    Args([u64; 6]),
    Ret(i64),
}

#[derive(Debug)]
pub struct Process {
    pid: Pid,
    terminate_on_end: bool, // Default true
    // Use RefCell to avoid self mut borrow runtime error
    state: RefCell<ProcessState>, // Default Stopped
    is_attached: bool,            // Default true
    registers: Rc<RefCell<Option<Registers>>>,
    breakpoint_sites: Rc<RefCell<StoppointCollection<BreakpointSite>>>,
    watchpoints: Rc<RefCell<StoppointCollection<WatchPoint>>>,
    syscall_catch_policy: RefCell<SyscallCatchPolicy>,
    expecting_syscall_exit: RefCell<bool>,
    target: RefCell<Option<Weak<Target>>>,
}

impl Process {
    pub fn set_syscall_catch_policy(&self, info: SyscallCatchPolicy) {
        *self.syscall_catch_policy.borrow_mut() = info;
    }

    fn new(pid: Pid, terminate_on_end: bool, is_attached: bool) -> Rc<Self> {
        let res = Self {
            pid,
            terminate_on_end,
            state: RefCell::new(ProcessState::Stopped),
            is_attached,
            registers: Rc::new(RefCell::new(None)),
            breakpoint_sites: Rc::new(RefCell::new(StoppointCollection::default())),
            watchpoints: Rc::new(RefCell::new(StoppointCollection::default())),
            syscall_catch_policy: RefCell::new(SyscallCatchPolicy::default()),
            expecting_syscall_exit: RefCell::new(false),
            target: RefCell::new(None),
        };

        let res = Rc::new(res);
        *res.registers.borrow_mut() = Some(Registers::new(&res));
        res
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn resume(&self) -> Result<(), SdbError> {
        let pc = self.get_pc();
        let breakpoint_sites = &self.breakpoint_sites.borrow();
        if breakpoint_sites.enabled_breakpoint_at_address(pc) {
            let bp = breakpoint_sites.get_by_address(pc)?;
            bp.borrow_mut().disable()?;
            step(self.pid, None)
                .map_err(|errno| SdbError::new_errno("Failed to single step", errno))?;
            waitpid(self.pid, None)
                .map_err(|errno| SdbError::new_errno("Waitpid failed", errno))?;
            bp.borrow_mut().enable()?;
        }
        let request: fn(Pid, Option<Signal>) -> Result<(), Errno> =
            if *self.syscall_catch_policy.borrow() == SyscallCatchPolicy::None {
                cont::<Option<Signal>>
            } else {
                syscall::<Option<Signal>>
            };
        if let Err(errno) = request(self.pid, None) {
            return SdbError::errno("Could not resume", errno);
        }
        *self.state.borrow_mut() = ProcessState::Running;
        Ok(())
    }

    pub fn state(&self) -> ProcessState {
        *self.state.borrow()
    }

    pub fn wait_on_signal(&self) -> Result<StopReason, SdbError> {
        let wait_status = waitpid(self.pid, WaitPidFlag::from_bits(0));
        return match wait_status {
            Err(errno) => SdbError::errno("waitpid failed", errno),
            Ok(status) => {
                let mut reason = StopReason::new(status)?;
                *self.state.borrow_mut() = reason.reason;

                if self.is_attached && *self.state.borrow() == ProcessState::Stopped {
                    self.read_all_registers()?;
                    self.augment_stop_reason(&mut reason)?;
                    let instr_begin = self.get_pc() - 1;
                    if reason.info == Signal::SIGTRAP as i32 {
                        let breakpoint_sites = self.breakpoint_sites.borrow();
                        if reason.trap_reason == Some(TrapType::SoftwareBreak)
                            && breakpoint_sites.contain_address(instr_begin)
                            && breakpoint_sites
                                .get_by_address(instr_begin)?
                                .borrow()
                                .is_enabled()
                        {
                            self.set_pc(instr_begin)?;
                        } else if reason.trap_reason == Some(TrapType::HardwareBreak) {
                            let id = self.get_current_hardware_stoppoint()?;
                            if let StoppointId::Watchpoint(id) = id {
                                self.watchpoints
                                    .borrow()
                                    .get_by_id(id)?
                                    .borrow_mut()
                                    .update_data()?;
                            }
                        } else if reason.trap_reason == Some(TrapType::Syscall) {
                            reason = self.maybe_resume_from_syscall(&reason)?;
                        }
                    }
                    if let Some(target) = self.target.borrow().as_ref() {
                        if let Some(target) = target.upgrade() {
                            target.notify_stop(&reason);
                        }
                    }
                }
                Ok(reason)
            }
        };
    }

    fn exit_with_error(channel: &Pipe, msg: &str, errno: Errno) -> ! {
        let err_str = errno.desc();
        channel
            .write(format!("{msg}: {err_str}").as_bytes())
            .unwrap();
        exit(-1)
    }

    pub fn launch(
        path: &Path,
        debug: bool, /*true*/
        stdout_replacement: Option<i32>,
    ) -> Result<Rc<Process>, SdbError> {
        let fork_res;
        let mut channel = Pipe::new(true)?;
        let mut pid = Pid::from_raw(0);
        unsafe {
            // unsafe in signal handler context
            fork_res = fork();
        }
        let path_str = CString::new(path.to_str().unwrap()).unwrap();
        if let Ok(ForkResult::Child) = fork_res {
            unsafe {
                if setpgid(0, 0) < 0 {
                    Process::exit_with_error(&channel, "Could not set pgid", Errno::last());
                }
            }
            let res = set_personality(Persona::ADDR_NO_RANDOMIZE);
            if let Err(errno) = res {
                Process::exit_with_error(&channel, "Subprocess set peronality failed", errno);
            }
            channel.close_read();
            if let Some(fd) = stdout_replacement {
                if let Err(errno) = dup2(fd, std::io::stdout().as_raw_fd()) {
                    Process::exit_with_error(&channel, "Stdout replacement failed", errno);
                }
            }
            if debug {
                if let Err(errno) = traceme() {
                    Process::exit_with_error(&channel, "Tracing failed", errno);
                }
            }
            if execvp(&path_str, &[&path_str]).is_err() {
                Process::exit_with_error(&channel, "Exec failed", Errno::from_raw(0));
            }
        } else if let Ok(ForkResult::Parent { child }) = fork_res {
            pid = child;
            channel.close_write();
            let data = channel.read();
            channel.close_read();
            if let Ok(msg) = data {
                if !msg.is_empty() {
                    waitpid(pid, WaitPidFlag::from_bits(0)).map_err(|errno| {
                        SdbError::new_err(&format!("Waitpid child failed, errno: {errno}"))
                    })?;
                    return SdbError::err(std::str::from_utf8(&msg).unwrap());
                }
            }
        } else {
            return SdbError::err("Fork failed");
        }

        let proc = Process::new(pid, true, debug);
        if debug {
            proc.wait_on_signal()?;
            set_ptrace_options(pid)?;
        }
        return Ok(proc);
    }

    pub fn attach(pid: Pid) -> Result<Rc<Process>, SdbError> {
        if pid.as_raw() <= 0 {
            return SdbError::err("Invalid pid");
        }
        if let Err(errno) = nix_attach(pid) {
            return SdbError::errno("Could not attach", errno);
        }
        let proc = Process::new(pid, false, true);
        proc.wait_on_signal()?;
        set_ptrace_options(pid)?;
        return Ok(proc);
    }

    pub fn write_user_area(&self, offset: usize, data: u64) -> Result<(), SdbError> {
        match write_user(self.pid, offset as AddressType, data.try_into().unwrap()) {
            Ok(_) => Ok(()),
            Err(errno) => SdbError::errno("Could not write user area", errno),
        }
    }

    pub fn get_registers(&self) -> Rc<RefCell<Option<Registers>>> {
        self.registers.clone()
    }

    pub fn read_all_registers(&self) -> Result<(), SdbError> {
        let regs = getregs(self.pid);
        match regs {
            Ok(data) => {
                self.registers.borrow_mut().as_mut().unwrap().data.0.regs = data;
                Ok(())
            }
            Err(errno) => SdbError::errno("Could not read GPR registers", errno),
        }?;

        unsafe {
            if ptrace(
                PTRACE_GETFPREGS,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                &mut self.registers.borrow_mut().as_mut().unwrap().data.0.i387 as *mut _
                    as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not read FPR registers", Errno::last());
            }
        }
        for i in 0..8 {
            let id = RegisterId::dr0 as i32 + i;
            let info = register_info_by_id(RegisterId::try_from(id).unwrap())?;

            match read_user(self.pid, info.offset as *mut c_void) {
                Ok(data) => {
                    self.registers
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .data
                        .0
                        .u_debugreg[i as usize] = data as u64;
                }
                Err(errno) => SdbError::errno("Could not read debug register", errno)?,
            };
        }

        Ok(())
    }

    pub fn write_gprs(&self, gprs: &mut user_regs_struct) -> Result<(), SdbError> {
        unsafe {
            if ptrace(
                PTRACE_SETREGS,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                gprs as *mut _ as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not write GPR registers", Errno::last());
            }
            Ok(())
        }
    }

    pub fn write_fprs(&self, fprs: &mut user_fpregs_struct) -> Result<(), SdbError> {
        unsafe {
            if ptrace(
                PTRACE_SETFPREGS,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                fprs as *mut _ as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not write FPR registers", Errno::last());
            }
            Ok(())
        }
    }

    pub fn get_pc(&self) -> VirtualAddress {
        self.get_registers()
            .borrow()
            .as_ref()
            .unwrap()
            .read_by_id_as::<u64>(RegisterId::rip)
            .unwrap()
            .into()
    }

    pub fn breakpoint_sites(&self) -> Rc<RefCell<StoppointCollection<BreakpointSite>>> {
        self.breakpoint_sites.clone()
    }

    pub fn set_pc(&self, address: VirtualAddress) -> Result<(), SdbError> {
        self.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::rip, address.get_addr())?;
        Ok(())
    }

    pub fn step_instruction(&self) -> Result<StopReason, SdbError> {
        let mut to_reenable: Option<_> = None;
        let pc = self.get_pc();
        let breakpoint_sites = &self.breakpoint_sites.borrow();
        if breakpoint_sites.enabled_breakpoint_at_address(pc) {
            let bp = breakpoint_sites.get_by_address(pc).unwrap();
            bp.borrow_mut().disable()?;
            to_reenable = Some(bp);
        }
        step(self.pid, None)
            .map_err(|errno| SdbError::new_errno("Could not single step", errno))?;
        let reason = self.wait_on_signal()?;
        if let Some(to_reenable) = to_reenable {
            to_reenable.borrow_mut().enable()?;
        }
        Ok(reason)
    }

    pub fn read_memory(
        &self,
        mut address: VirtualAddress,
        mut amount: usize,
    ) -> Result<Vec<u8>, SdbError> {
        let mut ret = vec![0u8; amount];
        let local_desc = IoSliceMut::new(&mut ret);
        let mut remote_descs = Vec::<RemoteIoVec>::new();
        while amount > 0 {
            let up_to_next_stage = 0x1000 - (address.get_addr() & 0xfff) as usize;
            let chunk_size = min(amount, up_to_next_stage);
            remote_descs.push(RemoteIoVec {
                base: address.get_addr() as usize,
                len: chunk_size,
            });
            amount -= chunk_size;
            address += chunk_size as i64;
        }
        process_vm_readv(self.pid, &mut [local_desc], &remote_descs)
            .map_err(|errno| SdbError::new_errno("Could not read process memory", errno))?;
        Ok(ret)
    }

    pub fn write_memory(&self, address: VirtualAddress, data: &[u8]) -> Result<(), SdbError> {
        let mut written = 0usize;
        while written < data.len() {
            let remaing = data.len() - written;
            let mut word = 0u64;
            if remaing >= 8 {
                word = from_bytes(&data[written..]);
            } else {
                let read = self.read_memory(address + written as i64, 8)?;
                let word_data = bytes_of_mut(&mut word);
                word_data[..remaing].copy_from_slice(&data[written..written + remaing]);
                word_data[remaing..].copy_from_slice(&read[remaing..8]);
            }
            write(
                self.pid,
                (address + written as i64).get_addr() as AddressType,
                word as c_long,
            )
            .map_err(|errno| SdbError::new_errno("Failed to write memory", errno))?;
            written += 8;
        }
        Ok(())
    }

    pub fn read_memory_as<T: Pod>(&self, address: VirtualAddress) -> Result<T, SdbError> {
        let data = self.read_memory(address, size_of::<T>())?;
        Ok(from_bytes(&data))
    }

    pub fn read_memory_without_trap(
        &self,
        address: VirtualAddress,
        amount: usize,
    ) -> Result<Vec<u8>, SdbError> {
        let mut memory = self.read_memory(address, amount)?;
        let sites = self
            .breakpoint_sites
            .borrow()
            .get_in_region(address, address + amount as i64);
        for site in sites.iter() {
            let site = site.borrow();
            if !site.is_enabled() || site.is_hardware() {
                continue;
            }
            let offset = site.address() - address.get_addr() as i64;
            memory[offset.get_addr() as usize] = site.saved_data();
        }
        Ok(memory)
    }

    pub fn set_hardware_breakpoint(
        &self,
        _id: i32,
        address: VirtualAddress,
    ) -> Result<i32, SdbError> {
        self._set_hardware_breakpoint(address, StoppointMode::Execute, 1)
    }

    fn _set_hardware_breakpoint(
        &self,
        address: VirtualAddress,
        mode: StoppointMode,
        size: usize,
    ) -> Result<i32, SdbError> {
        let owned_regs = self.get_registers();
        let mut regs = owned_regs.borrow_mut();
        let regs = regs.as_mut().unwrap();
        let control: u64 = regs.read_by_id_as(RegisterId::dr7)?;

        let free_space = Process::find_free_stoppoint_register(control)?;
        let id = RegisterId::dr0 as i32 + free_space as i32;
        regs.write_by_id(RegisterId::try_from(id).unwrap(), address.get_addr())?;

        let mode_flag = Process::encode_hardware_stoppoint_mode(mode);
        let size_flag = Process::encode_hardware_stoppoint_size(size)?;

        let enable_bit = 1 << (free_space * 2);
        let mode_bits = mode_flag << (free_space * 4 + 16);
        let size_bits = size_flag << (free_space * 4 + 18);
        let clear_mask = (0b11 << (free_space * 2)) | (0b1111 << (free_space * 4 + 16));
        let mut masked = control & !clear_mask;
        masked |= enable_bit | mode_bits | size_bits;
        regs.write_by_id(RegisterId::dr7, masked)?;
        return Ok(free_space as i32);
    }

    pub fn clear_hardware_stoppoint(&self, index: i32) -> Result<(), SdbError> {
        let id = RegisterId::try_from(RegisterId::dr0 as i32 + index).unwrap();
        let owned_registers = self.get_registers();
        {
            let mut regs = owned_registers.borrow_mut();
            let regs = regs.as_mut().unwrap();
            regs.write_by_id(id, 0)?;
        }
        let masked: u64;
        {
            let regs = owned_registers.borrow();
            let regs = regs.as_ref().unwrap();
            let control: u64 = regs.read_by_id_as(RegisterId::dr7)?;
            let clear_mask = (0b11 << (index * 2)) | (0b1111 << (index * 4 + 16));
            masked = control & !clear_mask;
        }
        let mut regs = owned_registers.borrow_mut();
        let regs = regs.as_mut().unwrap();
        regs.write_by_id(RegisterId::dr7, masked)?;
        Ok(())
    }

    fn find_free_stoppoint_register(control_register: u64) -> Result<u64, SdbError> {
        for i in 0..4 {
            if (control_register & (0b11 << (i * 2))) == 0 {
                return Ok(i);
            }
        }
        return SdbError::err("No remaining hardware debug registers");
    }

    fn encode_hardware_stoppoint_mode(mode: StoppointMode) -> u64 {
        match mode {
            StoppointMode::Write => 0b01,
            StoppointMode::ReadWrite => 0b11,
            StoppointMode::Execute => 0b00,
        }
    }

    fn encode_hardware_stoppoint_size(size: usize) -> Result<u64, SdbError> {
        match size {
            1 => Ok(0b00),
            2 => Ok(0b01),
            4 => Ok(0b11),
            8 => Ok(0b10),
            _ => SdbError::err("Invalid stoppoint size"),
        }
    }

    pub fn set_watchpoint(
        &self,
        _id: IdType,
        address: VirtualAddress,
        mode: StoppointMode,
        size: usize,
    ) -> Result<i32, SdbError> {
        return self._set_hardware_breakpoint(address, mode, size);
    }

    pub fn watchpoints(&self) -> Rc<RefCell<StoppointCollection<WatchPoint>>> {
        self.watchpoints.clone()
    }

    fn augment_stop_reason(&self, reason: &mut StopReason) -> Result<(), SdbError> {
        let info = getsiginfo(self.pid)
            .map_err(|errno| SdbError::new_errno("Failed to get signal info", errno))?;

        // Implementation is different
        if reason.trap_reason == Some(TrapType::Syscall) {
            let regs = self.get_registers();
            let regs = regs.borrow();
            let regs = regs.as_ref().unwrap();
            let expecting_syscall_exit = *self.expecting_syscall_exit.borrow();
            if expecting_syscall_exit {
                reason.syscall_info = Some(SyscallInfo {
                    id: regs.read_by_id_as::<u64>(RegisterId::orig_rax)? as u16,
                    data: SyscallData::Ret(regs.read_by_id_as::<u64>(RegisterId::rax)? as i64),
                });
                *self.expecting_syscall_exit.borrow_mut() = false;
            } else {
                let register_ids = [
                    RegisterId::rdi,
                    RegisterId::rsi,
                    RegisterId::rdx,
                    RegisterId::r10,
                    RegisterId::r8,
                    RegisterId::r9,
                ];
                let mut data = [0u64; 6];
                for (idx, id) in register_ids.iter().enumerate() {
                    data[idx] = regs.read_by_id_as::<u64>(*id)?;
                }
                reason.syscall_info = Some(SyscallInfo {
                    id: regs.read_by_id_as::<u64>(RegisterId::orig_rax)? as u16,
                    data: SyscallData::Args(data),
                });

                *self.expecting_syscall_exit.borrow_mut() = true;
            }

            reason.info = SIGTRAP as i32;
            return Ok(());
        }

        *self.expecting_syscall_exit.borrow_mut() = false;
        reason.trap_reason = Some(TrapType::Unknown);
        if reason.info == SIGTRAP as i32 {
            match info.si_code {
                TRAP_TRACE => reason.trap_reason = Some(TrapType::SingleStep),
                SI_KERNEL => reason.trap_reason = Some(TrapType::SoftwareBreak),
                TRAP_HWBKPT => reason.trap_reason = Some(TrapType::HardwareBreak),
                _ => {}
            }
        }
        Ok(())
    }

    fn maybe_resume_from_syscall(&self, reason: &StopReason) -> Result<StopReason, SdbError> {
        if let SyscallCatchPolicy::Some(to_catch) = &*self.syscall_catch_policy.borrow() {
            if !to_catch.iter().any(|id| {
                if let Some(info) = reason.syscall_info {
                    return *id == info.id as i32;
                }
                return false;
            }) {
                self.resume()?;
                return self.wait_on_signal();
            }
        }
        Ok(*reason)
    }

    pub fn get_current_hardware_stoppoint(&self) -> Result<StoppointId, SdbError> {
        let regs = self.get_registers();
        let regs = regs.borrow();
        let regs = regs.as_ref().unwrap();
        let status: u64 = regs.read_by_id_as(RegisterId::dr6)?;
        let index = status.trailing_zeros();

        let id = RegisterId::try_from(RegisterId::dr0 as i32 + index as i32).unwrap();
        let addr = VirtualAddress::from(regs.read_by_id_as::<u64>(id)?);
        let breapoint_sites = self.breakpoint_sites.borrow();
        if breapoint_sites.contain_address(addr) {
            let site_id = breapoint_sites.get_by_address(addr)?.borrow().id();
            Ok(StoppointId::BreakpointSite(site_id))
        } else {
            let watch_id = self
                .watchpoints
                .borrow()
                .get_by_address(addr)?
                .borrow()
                .id();
            Ok(StoppointId::Watchpoint(watch_id))
        }
    }

    pub fn get_auxv(&self) -> HashMap<i32, u64> {
        let path = format!("/proc/{}/auxv", self.pid);
        let mut file = File::open(path).unwrap();
        let mut auxv = HashMap::new();
        loop {
            let id = file.read_u64::<NativeEndian>().unwrap();
            if id == AT_NULL {
                break;
            }
            let value = file.read_u64::<NativeEndian>().unwrap();
            auxv.insert(id as i32, value);
        }
        auxv
    }

    pub fn set_target(&self, target: &Rc<Target>) {
        *self.target.borrow_mut() = Some(Rc::downgrade(target));
    }
}

pub enum StoppointId {
    BreakpointSite(IdType),
    Watchpoint(IdType),
}

pub trait ProcessExt {
    fn create_breakpoint_site(
        &self,
        address: VirtualAddress,
        hardware: bool,
        internal: bool,
    ) -> Result<Rc<RefCell<BreakpointSite>>, SdbError>;

    fn create_watchpoint(
        &self,
        address: VirtualAddress,
        mode: StoppointMode,
        size: usize,
    ) -> Result<Rc<RefCell<WatchPoint>>, SdbError>;
}

impl ProcessExt for Rc<Process> {
    fn create_breakpoint_site(
        &self,
        address: VirtualAddress,
        hardware: bool, // false
        internal: bool, // false
    ) -> Result<Rc<RefCell<BreakpointSite>>, SdbError> {
        if self.breakpoint_sites.borrow().contain_address(address) {
            return SdbError::err(&format!(
                "Breakpoint site already created at address {}",
                address.get_addr()
            ));
        }
        Ok(self
            .breakpoint_sites
            .borrow_mut()
            .push(BreakpointSite::new(self, address, hardware, internal)))
    }

    fn create_watchpoint(
        &self,
        address: VirtualAddress,
        mode: StoppointMode,
        size: usize,
    ) -> Result<Rc<RefCell<WatchPoint>>, SdbError> {
        if self.watchpoints.borrow().contain_address(address) {
            return SdbError::err(&format!(
                "Watchpoint already created at address {}",
                address.get_addr()
            ));
        }
        Ok(self
            .watchpoints
            .borrow_mut()
            .push(WatchPoint::new(self, address, mode, size)?))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.as_raw() != 0 {
            if self.is_attached {
                if *self.state.borrow() == ProcessState::Running {
                    kill(self.pid, Signal::SIGSTOP).log_error();
                    waitpid(self.pid, WaitPidFlag::from_bits(0)).log_error();
                }
                detach(self.pid, None).log_error();
                kill(self.pid, Signal::SIGCONT).log_error();
            }
            if self.terminate_on_end {
                kill(self.pid, Signal::SIGKILL).log_error();
                waitpid(self.pid, WaitPidFlag::from_bits(0)).log_error();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    use std::path::Path;

    fn process_exists(pid: Pid) -> bool {
        return kill(pid, None).is_ok();
    }

    #[test]
    fn process_launch_success() {
        let proc = super::Process::launch(Path::new("yes"), true, None);
        assert!(process_exists(proc.unwrap().pid()));
    }

    #[test]
    fn process_launch_no_such_program() {
        let proc = super::Process::launch(Path::new("you_do_not_have_to_be_good"), true, None);
        assert!(proc.is_err());
    }
}
