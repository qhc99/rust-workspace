use super::bit::to_byte_span;

use super::breakpoint::Breakpoint;

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
use nix::libc::PTRACE_EVENT_CLONE;
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
use nix::sys::signal::Signal::SIGSTOP;
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
use std::any::Any;
use std::cell::Ref;
use std::cell::RefMut;
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::c_long;
use std::fs::File;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;
use std::rc::Weak;
use std::{cell::RefCell, ffi::CString, os::raw::c_void, path::Path, process::exit, rc::Rc};
use typed_builder::TypedBuilder;
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ProcessState {
    #[default]
    Stopped,
    Running,
    Exited,
    Terminated,
}

#[derive(Debug, Clone, Copy, TypedBuilder)]
pub struct StopReason {
    #[builder(default)]
    pub reason: ProcessState,
    #[builder(default)]
    pub info: i32,
    #[builder(default)]
    pub trap_reason: Option<TrapType>,
    #[builder(default)]
    pub syscall_info: Option<SyscallInfo>,
    #[builder(default = Pid::from_raw(0))]
    pub tid: Pid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapType {
    SingleStep,
    SoftwareBreak,
    HardwareBreak,
    Syscall,
    Clone,
    Unknown,
}

impl StopReason {
    pub fn new(tid: Pid, status: WaitStatus) -> Result<Self, SdbError> {
        if let WaitStatus::Exited(_, info) = status {
            return Ok(StopReason {
                reason: ProcessState::Exited,
                info,
                trap_reason: None,
                syscall_info: None,
                tid,
            });
        } else if let WaitStatus::Signaled(_, info, _) = status {
            return Ok(StopReason {
                reason: ProcessState::Terminated,
                info: info as i32,
                trap_reason: None,
                syscall_info: None,
                tid,
            });
        } else if let WaitStatus::Stopped(_, info) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: info as i32,
                trap_reason: None,
                syscall_info: None,
                tid,
            });
        } else if let WaitStatus::PtraceEvent(_, info, event) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: info as i32,
                // Implementation is different
                trap_reason: if event == PTRACE_EVENT_CLONE {
                    Some(TrapType::Clone)
                } else {
                    None
                },
                syscall_info: None,
                tid,
            });
        } else if let WaitStatus::PtraceSyscall(_) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: SIGTRAP as i32,
                trap_reason: Some(TrapType::Syscall),
                syscall_info: None,
                tid,
            });
        }

        SdbError::err(&format!("Unhandled wait status {status:?}"))
    }

    pub fn is_step(&self) -> bool {
        self.reason == ProcessState::Stopped
            && self.info == SIGTRAP as i32
            && self.trap_reason == Some(TrapType::SingleStep)
    }

    pub fn is_breakpoint(&self) -> bool {
        self.reason == ProcessState::Stopped
            && self.info == SIGTRAP as i32
            && (self.trap_reason == Some(TrapType::SoftwareBreak)
                || self.trap_reason == Some(TrapType::HardwareBreak))
    }
}

fn set_ptrace_options(pid: Pid) -> Result<(), SdbError> {
    setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACECLONE,
    )
    .map_err(|errno| {
        SdbError::new_errno("Failed to set TRACESYSGOOD and TRACECLONE options", errno)
    })
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

type HitHandler = Option<Box<dyn Fn(&StopReason)>>;

pub struct Process {
    pid: Pid,
    terminate_on_end: bool,       // true
    state: RefCell<ProcessState>, // Stopped
    is_attached: bool,            // true
    registers: Rc<RefCell<Registers>>,
    breakpoint_sites: Rc<RefCell<StoppointCollection>>,
    watchpoints: Rc<RefCell<StoppointCollection>>,
    syscall_catch_policy: RefCell<SyscallCatchPolicy>,
    expecting_syscall_exit: RefCell<bool>,
    target: RefCell<Option<Weak<Target>>>,
    threads: RefCell<HashMap<Pid, Rc<RefCell<ThreadState>>>>,
    current_thread: RefCell<Pid>,
    thread_lifecycle_callback: RefCell<HitHandler>,
}

impl Process {
    pub fn cleanup_exited_threads(self: &Rc<Self>, main_stop_tid: Pid) -> Option<StopReason> {
        let mut to_remove = Vec::new();
        let mut to_report = None;
        for (tid, thread) in self.threads.borrow().iter() {
            if *tid != main_stop_tid
                && (thread.borrow().state == ProcessState::Exited
                    || thread.borrow().state == ProcessState::Terminated)
            {
                self.report_thread_lifecycle_event(&thread.borrow().reason);
                to_remove.push(*tid);
                if *tid == self.pid {
                    to_report = Some(thread.borrow().reason);
                }
            }
        }
        for tid in to_remove {
            self.threads.borrow_mut().remove(&tid);
        }
        to_report
    }

    pub fn report_thread_lifecycle_event(self: &Rc<Self>, reason: &StopReason) {
        if let Some(callback) = self.thread_lifecycle_callback.borrow().as_ref() {
            callback(reason);
        }
        if let Some(target) = self.target.borrow().as_ref() {
            target
                .upgrade()
                .unwrap()
                .notify_thread_lifecycle_event(reason);
        }
    }

    pub fn stop_running_threads(self: &Rc<Self>) -> Result<(), SdbError> {
        let threads = self.threads.borrow().clone();
        for (tid, thread) in threads.iter() {
            if thread.borrow().state == ProcessState::Running {
                if !thread.borrow().pending_sigstop {
                    unsafe {
                        let ret = nix::libc::syscall(
                            nix::libc::SYS_tgkill,
                            self.pid.as_raw() as nix::libc::c_long,
                            tid.as_raw() as nix::libc::c_long,
                            SIGSTOP as nix::libc::c_long,
                        );
                        if ret == -1 {
                            return SdbError::errno("tgkill failed", Errno::last());
                        }
                    }
                }

                let wait_status =
                    waitpid(*tid, None).map_err(|e| SdbError::new_errno("Failed to waitpid", e))?;
                let mut thread_reason = StopReason::new(*tid, wait_status)?;

                if thread_reason.reason == ProcessState::Stopped {
                    if thread_reason.info != SIGSTOP as i32 {
                        thread.borrow_mut().pending_sigstop = true;
                    } else if thread.borrow().pending_sigstop {
                        thread.borrow_mut().pending_sigstop = false;
                    }
                }

                thread_reason = self
                    .handle_signal(thread_reason, false)?
                    .unwrap_or(thread_reason);

                let mut temp_mut = self.threads.borrow_mut();
                let mut temp_mut = temp_mut.get_mut(tid).unwrap().borrow_mut();
                temp_mut.reason = thread_reason;
                temp_mut.state = thread_reason.reason;
            }
        }
        Ok(())
    }

    pub fn step_instruction(
        self: &Rc<Self>,
        otid: Option<Pid>, /* None */
    ) -> Result<StopReason, SdbError> {
        let tid = otid.unwrap_or(self.current_thread());
        let mut to_reenable: Option<_> = None;
        let pc = self.get_pc(Some(tid));
        let breakpoint_sites = &self.breakpoint_sites.borrow();
        if breakpoint_sites.enabled_breakpoint_at_address(pc) {
            let bp = breakpoint_sites.get_by_address(pc).unwrap();
            bp.borrow_mut().disable()?;
            to_reenable = Some(bp);
        }
        self.swallow_pending_sigstop(tid)?;
        step(tid, None).map_err(|errno| SdbError::new_errno("Could not single step", errno))?;
        let reason = self.wait_on_signal(tid)?;
        if let Some(to_reenable) = to_reenable {
            to_reenable.borrow_mut().enable()?;
        }
        Ok(reason)
    }

    pub fn wait_on_signal(
        self: &Rc<Self>,
        to_await: Pid, /* -1 */
    ) -> Result<StopReason, SdbError> {
        let options = WaitPidFlag::__WALL;
        let wait_status = waitpid(to_await, Some(options));

        let (tid, status) = match wait_status {
            Err(errno) => return SdbError::errno("waitpid failed", errno),
            Ok(status) => {
                let tid = match status {
                    WaitStatus::Exited(pid, _) => pid,
                    WaitStatus::Signaled(pid, _, _) => pid,
                    WaitStatus::Stopped(pid, _) => pid,
                    WaitStatus::PtraceEvent(pid, _, _) => pid,
                    WaitStatus::PtraceSyscall(pid) => pid,
                    WaitStatus::Continued(pid) => pid,
                    WaitStatus::StillAlive => {
                        return SdbError::err("Unexpected WaitStatus::StillAlive");
                    }
                };
                (tid, status)
            }
        };

        let mut reason = StopReason::new(tid, status)?;
        let final_reason = self.handle_signal(reason, true)?;

        if final_reason.is_none() {
            self.resume(Some(tid))?;
            return self.wait_on_signal(to_await);
        }

        reason = final_reason.unwrap();
        // Implementation difference: add empty check
        if let Some(thread) = self.threads.borrow().get(&tid) {
            let thread = thread.clone();
            let mut thread_state = thread.borrow_mut();
            thread_state.reason = reason;
            thread_state.state = reason.reason;
        }

        if reason.reason == ProcessState::Exited || reason.reason == ProcessState::Terminated {
            self.report_thread_lifecycle_event(&reason);
            if tid == self.pid {
                *self.state.borrow_mut() = reason.reason;
                return Ok(reason);
            } else {
                return self.wait_on_signal(Pid::from_raw(-1));
            }
        }

        self.stop_running_threads()?;
        reason = self.cleanup_exited_threads(tid).unwrap_or(reason);

        *self.state.borrow_mut() = reason.reason;
        self.set_current_thread(tid);

        Ok(reason)
    }

    pub fn handle_signal(
        self: &Rc<Self>,
        mut reason: StopReason,
        is_main_stop: bool,
    ) -> Result<Option<StopReason>, SdbError> {
        let tid = reason.tid;

        if reason.trap_reason == Some(TrapType::Clone) && is_main_stop {
            return Ok(None);
        }

        if self.is_attached && reason.reason == ProcessState::Stopped {
            if !self.threads.borrow().contains_key(&tid) {
                let thread_state = Rc::new(RefCell::new(
                    ThreadState::builder()
                        .tid(tid)
                        .regs(Rc::new(RefCell::new(Registers::new(
                            &Rc::downgrade(self),
                            tid,
                        ))))
                        .build(),
                ));
                self.threads.borrow_mut().insert(tid, thread_state);
                self.report_thread_lifecycle_event(&reason);
                if is_main_stop {
                    return Ok(None);
                }
            }

            let thread = self.threads.borrow().get(&tid).unwrap().clone();
            if thread.borrow().pending_sigstop && reason.info == SIGSTOP as i32 {
                thread.borrow_mut().pending_sigstop = false;
                return Ok(None);
            }

            self.read_all_registers(tid)?;
            self.augment_stop_reason(&mut reason)?;

            if reason.info == SIGTRAP as i32 {
                let instr_begin = VirtualAddress::from(self.get_pc(Some(tid)).addr() - 1);

                if reason.trap_reason == Some(TrapType::SoftwareBreak)
                    && self.breakpoint_sites.borrow().contains_address(instr_begin)
                    && self
                        .breakpoint_sites
                        .borrow()
                        .get_by_address(instr_begin)?
                        .borrow()
                        .is_enabled()
                {
                    self.set_pc(instr_begin, Some(tid))?;

                    let bp = self.breakpoint_sites.borrow().get_by_address(instr_begin)?;
                    let bp = bp.borrow() as Ref<dyn Any>;
                    let bp = bp.downcast_ref::<BreakpointSite>().unwrap();
                    if let Some(parent) = &bp.parent.upgrade() {
                        let should_restart = parent.borrow().notify_hit()?;
                        if should_restart && is_main_stop {
                            return Ok(None);
                        }
                    }
                } else if reason.trap_reason == Some(TrapType::HardwareBreak) {
                    let id = self.get_current_hardware_stoppoint(Some(tid))?;
                    if let StoppointId::Watchpoint(watchpoint_id) = id {
                        if let Ok(wp) = self.watchpoints.borrow().get_by_id(watchpoint_id) {
                            let mut wp = wp.borrow_mut() as RefMut<dyn Any>;
                            let wp = wp.downcast_mut::<WatchPoint>().unwrap();
                            wp.update_data()?;
                        }
                    }
                } else if reason.trap_reason == Some(TrapType::Syscall)
                    && is_main_stop
                    && self.should_resume_from_syscall(&reason)
                {
                    return Ok(None);
                }
            }

            if let Some(target_weak) = self.target.borrow().as_ref() {
                target_weak.upgrade().unwrap().notify_stop(&reason)?;
            }
        }

        Ok(Some(reason))
    }

    pub fn populate_existing_threads(self: &Rc<Self>) {
        let path = format!("/proc/{}/task", self.pid);
        let entries = std::fs::read_dir(path).unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            let tid = Pid::from_raw(
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse::<i32>()
                    .unwrap(),
            );
            self.threads.borrow_mut().insert(
                tid,
                Rc::new(RefCell::new(
                    ThreadState::builder()
                        .tid(tid)
                        .regs(Rc::new(RefCell::new(Registers::new(
                            &Rc::downgrade(self),
                            tid,
                        ))))
                        .build(),
                )),
            );
        }
    }

    pub fn create_breakpoint_site(
        self: &Rc<Self>,
        address: VirtualAddress,
        hardware: bool, // false
        internal: bool, // false
    ) -> Result<Weak<RefCell<BreakpointSite>>, SdbError> {
        if self.breakpoint_sites.borrow().contains_address(address) {
            return SdbError::err(&format!(
                "Breakpoint site already created at address {}",
                address.addr()
            ));
        }
        let bs = Rc::new(RefCell::new(BreakpointSite::new(
            self, address, hardware, internal,
        )));
        self.breakpoint_sites.borrow_mut().push_strong(bs.clone());
        Ok(Rc::downgrade(&bs))
    }

    pub fn create_breakpoint_site_from_breakpoint(
        self: &Rc<Self>,
        parent: &Rc<RefCell<Breakpoint>>,
        id: IdType,
        address: VirtualAddress,
        hardware: bool,
        internal: bool,
    ) -> Result<Weak<RefCell<BreakpointSite>>, SdbError> {
        if self.breakpoint_sites.borrow().contains_address(address) {
            return SdbError::err(&format!(
                "Breakpoint site already created at address {}",
                address.addr()
            ));
        }
        let bs = Rc::new(RefCell::new(BreakpointSite::from_breakpoint(
            parent, id, self, address, hardware, internal,
        )));
        self.breakpoint_sites.borrow_mut().push_strong(bs.clone());
        Ok(Rc::downgrade(&bs))
    }

    pub fn create_watchpoint(
        self: &Rc<Self>,
        address: VirtualAddress,
        mode: StoppointMode,
        size: usize,
    ) -> Result<Weak<RefCell<WatchPoint>>, SdbError> {
        if self.watchpoints.borrow().contains_address(address) {
            return SdbError::err(&format!(
                "Watchpoint already created at address {}",
                address.addr()
            ));
        }
        let wp = Rc::new(RefCell::new(WatchPoint::new(self, address, mode, size)?));
        self.watchpoints.borrow_mut().push_strong(wp.clone());
        Ok(Rc::downgrade(&wp))
    }

    pub fn inferior_call(
        self: &Rc<Self>,
        func_addr: VirtualAddress,
        return_addr: VirtualAddress,
        regs_to_restore: Registers,
        otid: Option<Pid>, /* None */
    ) -> Result<Registers, SdbError> {
        let tid = otid.unwrap_or(self.current_thread());
        let regs = self.get_registers(Some(tid));

        regs.borrow_mut()
            .write_by_id(RegisterId::rip, func_addr.addr(), true)?;

        let mut rsp = regs.borrow().read_by_id_as::<u64>(RegisterId::rsp)?;

        rsp -= 8;
        self.write_memory(VirtualAddress::new(rsp), to_byte_span(&return_addr.addr()))?;
        regs.borrow_mut().write_by_id(RegisterId::rsp, rsp, true)?;

        self.resume(Some(tid))?;
        let reason = self.wait_on_signal(tid)?;
        if reason.reason != ProcessState::Stopped {
            return SdbError::err("Function call failed");
        }

        let new_regs = regs.borrow().clone();
        *regs.borrow_mut() = regs_to_restore.clone();
        regs.borrow_mut().flush()?;
        if let Some(target) = self.target.borrow().as_ref()
            && let Some(target) = target.upgrade()
        {
            target.notify_stop(&reason)?;
        }

        Ok(new_regs)
    }

    pub fn read_string(&self, address: VirtualAddress) -> Result<String, SdbError> {
        let mut ret = String::new();
        loop {
            let data = self.read_memory(address, 1024)?;
            for c in data {
                if c == 0 {
                    return Ok(ret);
                }
                ret.push(c as char);
            }
        }
    }

    pub fn install_thread_lifecycle_callback<T: Fn(&StopReason) + 'static>(&self, callback: T) {
        *self.thread_lifecycle_callback.borrow_mut() = Some(Box::new(callback));
    }

    pub fn resume_all_threads(&self) -> Result<(), SdbError> {
        let tids = self.threads.borrow().keys().copied().collect::<Vec<_>>();
        for tid in tids.iter() {
            self.step_over_breakpoint(*tid)?;
        }
        for tid in tids.iter() {
            self.send_continue(*tid)?;
        }
        Ok(())
    }

    fn send_continue(&self, tid: Pid) -> Result<(), SdbError> {
        let request: fn(Pid, Option<Signal>) -> Result<(), Errno> =
            if *self.syscall_catch_policy.borrow() == SyscallCatchPolicy::None {
                cont::<Option<Signal>>
            } else {
                syscall::<Option<Signal>>
            };
        if let Err(errno) = request(tid, None) {
            return SdbError::errno("Could not resume", errno);
        }
        self.threads
            .borrow_mut()
            .get_mut(&tid)
            .unwrap()
            .borrow_mut()
            .state = ProcessState::Running;
        *self.state.borrow_mut() = ProcessState::Running;
        Ok(())
    }

    fn swallow_pending_sigstop(&self, tid: Pid) -> Result<(), SdbError> {
        let thread = self.threads.borrow().get(&tid).unwrap().clone();
        if thread.borrow().pending_sigstop {
            cont(tid, None).map_err(|errno| SdbError::new_errno("Failed to continue", errno))?;
            waitpid(tid, None).map_err(|errno| SdbError::new_errno("Waitpid failed", errno))?;
            thread.borrow_mut().pending_sigstop = false;
        }
        Ok(())
    }

    fn step_over_breakpoint(&self, tid: Pid) -> Result<(), SdbError> {
        let pc = self.get_pc(Some(tid));
        if self
            .breakpoint_sites
            .borrow()
            .enabled_breakpoint_at_address(pc)
        {
            let bp = self.breakpoint_sites.borrow().get_by_address(pc)?;
            bp.borrow_mut().disable()?;
            self.swallow_pending_sigstop(tid)?;
            step(tid, None).map_err(|errno| SdbError::new_errno("Failed to single step", errno))?;
            waitpid(tid, None).map_err(|errno| SdbError::new_errno("Waitpid failed", errno))?;
            bp.borrow_mut().enable()?;
        }
        Ok(())
    }

    pub fn set_current_thread(&self, tid: Pid) {
        *self.current_thread.borrow_mut() = tid;
    }

    pub fn current_thread(&self) -> Pid {
        *self.current_thread.borrow()
    }

    pub fn thread_states(&self) -> &RefCell<HashMap<Pid, Rc<RefCell<ThreadState>>>> {
        &self.threads
    }

    pub fn set_syscall_catch_policy(&self, info: SyscallCatchPolicy) {
        *self.syscall_catch_policy.borrow_mut() = info;
    }

    fn new(pid: Pid, terminate_on_end: bool, is_attached: bool) -> Rc<Self> {
        let ret = Rc::new_cyclic(|weak_self| Self {
            pid,
            terminate_on_end,
            state: RefCell::new(ProcessState::Stopped),
            is_attached,
            registers: Rc::new(RefCell::new(Registers::new(weak_self, pid))),
            breakpoint_sites: Rc::new(RefCell::new(StoppointCollection::default())),
            watchpoints: Rc::new(RefCell::new(StoppointCollection::default())),
            syscall_catch_policy: RefCell::new(SyscallCatchPolicy::default()),
            expecting_syscall_exit: RefCell::new(false),
            target: RefCell::new(None),
            threads: RefCell::new(HashMap::new()),
            current_thread: RefCell::new(pid),
            thread_lifecycle_callback: RefCell::new(None),
        });
        ret.populate_existing_threads();
        ret
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn resume(&self, otid: Option<Pid> /* None */) -> Result<(), SdbError> {
        let tid = otid.unwrap_or(self.current_thread());
        self.step_over_breakpoint(tid)?;
        self.send_continue(tid)?;
        Ok(())
    }

    pub fn state(&self) -> ProcessState {
        *self.state.borrow()
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
            if let Some(fd) = stdout_replacement
                && let Err(errno) = dup2(fd, std::io::stdout().as_raw_fd())
            {
                Process::exit_with_error(&channel, "Stdout replacement failed", errno);
            }
            if debug && let Err(errno) = traceme() {
                Process::exit_with_error(&channel, "Tracing failed", errno);
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
            proc.wait_on_signal(Pid::from_raw(-1))?;
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
        proc.wait_on_signal(Pid::from_raw(-1))?;
        set_ptrace_options(pid)?;
        return Ok(proc);
    }

    pub fn write_user_area(
        &self,
        offset: usize,
        data: u64,
        otid: Option<Pid>, /* None */
    ) -> Result<(), SdbError> {
        let tid = otid.unwrap_or(self.current_thread());
        match write_user(tid, offset as AddressType, data.try_into().unwrap()) {
            Ok(_) => Ok(()),
            Err(errno) => SdbError::errno("Could not write user area", errno),
        }
    }

    pub fn get_registers(&self, otid: Option<Pid> /* None */) -> Rc<RefCell<Registers>> {
        let tid = otid.unwrap_or(self.current_thread());
        self.threads
            .borrow()
            .get(&tid)
            .unwrap()
            .borrow()
            .regs
            .clone()
    }

    pub fn read_all_registers(&self, tid: Pid) -> Result<(), SdbError> {
        let regs = getregs(tid);
        match regs {
            Ok(data) => {
                self.get_registers(Some(tid)).borrow_mut().data.0.regs = data;
                Ok(())
            }
            Err(errno) => SdbError::errno("Could not read GPR registers", errno),
        }?;

        unsafe {
            if ptrace(
                PTRACE_GETFPREGS,
                tid,
                std::ptr::null_mut::<c_void>(),
                &mut self.get_registers(Some(tid)).borrow_mut().data.0.i387 as *mut _
                    as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not read FPR registers", Errno::last());
            }
        }
        for i in 0..8 {
            let id = RegisterId::dr0 as i32 + i;
            let info = register_info_by_id(RegisterId::try_from(id).unwrap())?;

            match read_user(tid, info.offset as *mut c_void) {
                Ok(data) => {
                    self.get_registers(Some(tid)).borrow_mut().data.0.u_debugreg[i as usize] =
                        data as u64;
                }
                Err(errno) => SdbError::errno("Could not read debug register", errno)?,
            };
        }

        Ok(())
    }

    pub fn write_gprs(
        &self,
        gprs: &mut user_regs_struct,
        otid: Option<Pid>, /* None */
    ) -> Result<(), SdbError> {
        let tid = otid.unwrap_or(self.current_thread());
        unsafe {
            if ptrace(
                PTRACE_SETREGS,
                tid,
                std::ptr::null_mut::<c_void>(),
                gprs as *mut _ as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not write GPR registers", Errno::last());
            }
            Ok(())
        }
    }

    pub fn write_fprs(
        &self,
        fprs: &mut user_fpregs_struct,
        otid: Option<Pid>, /* None */
    ) -> Result<(), SdbError> {
        let tid = otid.unwrap_or(self.current_thread());
        unsafe {
            if ptrace(
                PTRACE_SETFPREGS,
                tid,
                std::ptr::null_mut::<c_void>(),
                fprs as *mut _ as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not write FPR registers", Errno::last());
            }
            Ok(())
        }
    }

    pub fn get_pc(&self, otid: Option<Pid> /* None */) -> VirtualAddress {
        self.get_registers(otid)
            .borrow()
            .read_by_id_as::<u64>(RegisterId::rip)
            .unwrap()
            .into()
    }

    pub fn breakpoint_sites(&self) -> Rc<RefCell<StoppointCollection>> {
        self.breakpoint_sites.clone()
    }

    pub fn set_pc(
        &self,
        address: VirtualAddress,
        otid: Option<Pid>, /* None */
    ) -> Result<(), SdbError> {
        self.get_registers(otid)
            .borrow_mut()
            .write_by_id(RegisterId::rip, address.addr(), true)?;
        Ok(())
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
            let up_to_next_stage = 0x1000 - (address.addr() & 0xfff) as usize;
            let chunk_size = min(amount, up_to_next_stage);
            remote_descs.push(RemoteIoVec {
                base: address.addr() as usize,
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
                (address + written as i64).addr() as AddressType,
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
            let site = site.borrow() as Ref<dyn Any>;
            let site = site.downcast_ref::<BreakpointSite>().unwrap();
            if !site.is_enabled() || site.is_hardware() {
                continue;
            }
            let offset = site.address() - address.addr() as i64;
            memory[offset.addr() as usize] = site.saved_data();
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
        let owned_regs = self.get_registers(None);
        let mut regs = owned_regs.borrow_mut();
        let control: u64 = regs.read_by_id_as(RegisterId::dr7)?;

        let free_space = Process::find_free_stoppoint_register(control)?;
        let id = RegisterId::dr0 as i32 + free_space as i32;
        regs.write_by_id(RegisterId::try_from(id).unwrap(), address.addr(), true)?;

        let mode_flag = Process::encode_hardware_stoppoint_mode(mode);
        let size_flag = Process::encode_hardware_stoppoint_size(size)?;

        let enable_bit = 1 << (free_space * 2);
        let mode_bits = mode_flag << (free_space * 4 + 16);
        let size_bits = size_flag << (free_space * 4 + 18);
        let clear_mask = (0b11 << (free_space * 2)) | (0b1111 << (free_space * 4 + 16));
        let mut masked = control & !clear_mask;
        masked |= enable_bit | mode_bits | size_bits;
        regs.write_by_id(RegisterId::dr7, masked, true)?;
        for (tid, _) in self.threads.borrow().iter() {
            if *tid == *self.current_thread.borrow() {
                continue;
            }
            let other_regs = self.get_registers(Some(*tid));
            let mut other_regs = other_regs.borrow_mut();
            other_regs.write_by_id(RegisterId::try_from(id).unwrap(), address.addr(), true)?;
            other_regs.write_by_id(RegisterId::dr7, masked, true)?;
        }
        return Ok(free_space as i32);
    }

    pub fn clear_hardware_stoppoint(&self, index: i32) -> Result<(), SdbError> {
        let id = RegisterId::try_from(RegisterId::dr0 as i32 + index).unwrap();
        let owned_registers = self.get_registers(None);
        {
            let mut regs = owned_registers.borrow_mut();
            regs.write_by_id(id, 0, true)?;
        }
        let masked: u64;
        {
            let regs = owned_registers.borrow();
            let control: u64 = regs.read_by_id_as(RegisterId::dr7)?;
            let clear_mask = (0b11 << (index * 2)) | (0b1111 << (index * 4 + 16));
            masked = control & !clear_mask;
        }
        let mut regs = owned_registers.borrow_mut();
        regs.write_by_id(RegisterId::dr7, masked, true)?;

        for (tid, _) in self.threads.borrow().iter() {
            if *tid == *self.current_thread.borrow() {
                continue;
            }
            let other_regs = self.get_registers(Some(*tid));
            let mut other_regs = other_regs.borrow_mut();
            other_regs.write_by_id(id, 0, true)?;
            other_regs.write_by_id(RegisterId::dr7, masked, true)?;
        }
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

    pub fn watchpoints(&self) -> Rc<RefCell<StoppointCollection>> {
        self.watchpoints.clone()
    }

    fn augment_stop_reason(&self, reason: &mut StopReason) -> Result<(), SdbError> {
        let tid = reason.tid;
        let info = getsiginfo(tid)
            .map_err(|errno| SdbError::new_errno("Failed to get signal info", errno))?;

        // Implementation is different
        if reason.trap_reason == Some(TrapType::Syscall) {
            let regs = self.get_registers(Some(tid));
            let regs = regs.borrow();
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

    fn should_resume_from_syscall(&self, reason: &StopReason) -> bool {
        if let SyscallCatchPolicy::Some(to_catch) = &*self.syscall_catch_policy.borrow() {
            if !to_catch.iter().any(|id| {
                if let Some(info) = reason.syscall_info {
                    return *id == info.id as i32;
                }
                return false;
            }) {
                return true;
            }
        }
        false
    }

    pub fn get_current_hardware_stoppoint(
        &self,
        otid: Option<Pid>, /* None */
    ) -> Result<StoppointId, SdbError> {
        let regs = self.get_registers(otid);
        let regs = regs.borrow();
        let status: u64 = regs.read_by_id_as(RegisterId::dr6)?;
        let index = status.trailing_zeros();

        let id = RegisterId::try_from(RegisterId::dr0 as i32 + index as i32).unwrap();
        let addr = VirtualAddress::from(regs.read_by_id_as::<u64>(id)?);
        let breapoint_sites = self.breakpoint_sites.borrow();
        if breapoint_sites.contains_address(addr) {
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

#[derive(TypedBuilder)]
pub struct ThreadState {
    tid: Pid,
    regs: Rc<RefCell<Registers>>,
    #[builder(default = StopReason::builder().build())]
    pub reason: StopReason,
    #[builder(default = ProcessState::Stopped)]
    state: ProcessState,
    #[builder(default = false)]
    pending_sigstop: bool,
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    use serial_test::serial;
    use std::path::Path;

    fn process_exists(pid: Pid) -> bool {
        return kill(pid, None).is_ok();
    }

    #[test]
    #[serial]
    fn process_launch_success() {
        let proc = super::Process::launch(Path::new("yes"), true, None);
        assert!(process_exists(proc.unwrap().pid()));
    }

    #[test]
    #[serial]
    fn process_launch_no_such_program() {
        let proc = super::Process::launch(Path::new("you_do_not_have_to_be_good"), true, None);
        assert!(proc.is_err());
    }
}
