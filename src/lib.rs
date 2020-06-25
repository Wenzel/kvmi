#![allow(clippy::mutex_atomic)] // prevent fp with idiomatic condvar code

#[macro_use]
extern crate log;
mod libkvmi;
use enum_primitive_derive::Primitive;
use kvmi_sys::{
    kvm_msr_entry, kvmi_event_cr_reply, kvmi_event_msr_reply, kvmi_event_pf_reply,
    kvmi_event_reply, kvmi_introspector2qemu, kvmi_qemu2introspector, kvmi_vcpu_hdr,
    KVMI_EVENT_BREAKPOINT, KVMI_EVENT_CR, KVMI_EVENT_MSR, KVMI_EVENT_PAUSE_VCPU, KVMI_EVENT_PF,
};
pub use kvmi_sys::{kvm_msrs, kvm_regs, kvm_segment, kvm_sregs, kvmi_dom_event};
use libc::free;
use nix::errno::Errno;
use num_traits::{FromPrimitive, ToPrimitive};
use std::cmp::PartialEq;
use std::convert::TryInto;
use std::ffi::CString;
use std::io::Error;
use std::mem;
use std::os::raw::{c_int, c_uchar, c_uint, c_ushort, c_void};
use std::ptr::null_mut;
use std::sync::{Condvar, Mutex};

use libkvmi::Libkvmi;

#[derive(Debug)]
struct KVMiCon {
    dom: *mut c_void,
    guard: Mutex<bool>,
    condvar: Condvar,
}

#[derive(Debug, Copy, Clone, Primitive)]
pub enum KVMiInterceptType {
    PauseVCPU = KVMI_EVENT_PAUSE_VCPU as isize,
    Cr = KVMI_EVENT_CR as isize,
    Msr = KVMI_EVENT_MSR as isize,
    Breakpoint = KVMI_EVENT_BREAKPOINT as isize,
    Pagefault = KVMI_EVENT_PF as isize,
}
pub enum KVMiPageAccess {
    PageAccessW = kvmi_sys::KVMI_PAGE_ACCESS_W as isize,
    PageAccessR = kvmi_sys::KVMI_PAGE_ACCESS_R as isize,
    PageAccessX = kvmi_sys::KVMI_PAGE_ACCESS_X as isize,
}

#[derive(Debug, Copy, Clone)]
pub enum KVMiEventType {
    PauseVCPU,
    Cr {
        cr_type: KVMiCr,
        new: u64,
        old: u64,
    },
    Msr {
        msr_type: u32,
        new: u64,
        old: u64,
    },
    Breakpoint {
        gpa: u64,
        insn_len: u8,
    },
    Pagefault {
        gva: u64,
        gpa: u64,
        access: u8,
        view: u16,
    },
}

#[derive(Primitive, Debug, Copy, Clone)]
pub enum KVMiEventReply {
    Continue = kvmi_sys::KVMI_EVENT_ACTION_CONTINUE as isize,
    Retry = kvmi_sys::KVMI_EVENT_ACTION_RETRY as isize,
    Crash = kvmi_sys::KVMI_EVENT_ACTION_CRASH as isize,
}

#[derive(Primitive, Debug, Copy, Clone, PartialEq)]
pub enum KVMiCr {
    Cr0 = 0,
    Cr3 = 3,
    Cr4 = 4,
}

#[derive(Primitive, Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum KVMiMsr {
    SysenterCs = 0x174 as u32,
    SysenterEsp = 0x175 as u32,
    SysenterEip = 0x176 as u32,
    MsrEfer = 0xc0000080 as u32,
    MsrStar = 0xc0000081 as u32,
    MsrLstar = 0xc0000082 as u32,
}

#[derive(Debug)]
pub struct KVMiEvent {
    pub vcpu: u16,
    pub ev_type: KVMiEventType,
    pub ffi_event: *mut kvmi_dom_event,
}

pub struct KvmMsr {
    pub msrs: kvm_msrs,
    pub entries: [kvm_msr_entry; 6],
}
unsafe extern "C" fn new_guest_cb(
    dom: *mut c_void,
    _uuid: *mut [c_uchar; 16usize],
    cb_ctx: *mut c_void,
) -> c_int {
    debug!("KVMi new guest");
    if cb_ctx.is_null() {
        panic!("Unexpected null context");
    }
    let kvmi_con = &mut *(cb_ctx as *mut KVMiCon);
    let mut connected = kvmi_con
        .guard
        .lock()
        .expect("Failed to acquire connexion mutex");
    kvmi_con.dom = dom;
    *connected = true;
    // wake up waiters
    kvmi_con.condvar.notify_one();
    0
}

unsafe extern "C" fn handshake_cb(
    _arg1: *const kvmi_qemu2introspector,
    _arg2: *mut kvmi_introspector2qemu,
    _cb_ctx: *mut c_void,
) -> c_int {
    debug!("KVMi handshake");
    0
}

pub trait KVMIntrospectable: std::fmt::Debug {
    fn init(&mut self, socket_path: &str) -> Result<(), Error>;
    fn control_events(
        &self,
        vcpu: u16,
        intercept_type: KVMiInterceptType,
        enabled: bool,
    ) -> Result<(), Error>;
    fn control_cr(&self, vcpu: u16, reg: KVMiCr, enabled: bool) -> Result<(), Error>;
    fn control_msr(&self, vcpu: u16, reg: u32, enabled: bool) -> Result<(), Error>;
    fn read_physical(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), Error>;
    fn write_physical(&self, gpa: u64, buffer: &[u8]) -> Result<(), Error>;
    fn get_page_access(&self, gpa: u64) -> Result<u8, Error>;
    fn set_page_access(&self, gpa: u64, access: u8) -> Result<(), Error>;
    fn pause(&self) -> Result<(), Error>;
    fn get_vcpu_count(&self) -> Result<u32, Error>;
    fn get_registers(&self, vcpu: u16) -> Result<(kvm_regs, kvm_sregs, KvmMsr), Error>;
    fn set_registers(&self, vcpu: u16, regs: &kvm_regs) -> Result<(), Error>;
    fn wait_and_pop_event(&self, ms: i32) -> Result<Option<KVMiEvent>, Error>;
    fn reply(&self, event: &KVMiEvent, reply_type: KVMiEventReply) -> Result<(), Error>;
    fn get_maximum_gfn(&self) -> Result<u64, Error>;
}

pub fn create_kvmi() -> KVMi {
    KVMi::new(unsafe { Libkvmi::new() })
}

#[derive(Debug)]
pub struct KVMi {
    ctx: *mut c_void,
    dom: *mut c_void,
    libkvmi: Libkvmi,
}

impl KVMi {
    fn new(libkvmi: Libkvmi) -> KVMi {
        KVMi {
            ctx: null_mut(),
            dom: null_mut(),
            libkvmi,
        }
    }
}

impl KVMIntrospectable for KVMi {
    fn init(&mut self, socket_path: &str) -> Result<(), Error> {
        let socket_path = CString::new(socket_path).unwrap();
        let accept_db = Some(
            new_guest_cb
                as unsafe extern "C" fn(*mut c_void, *mut [c_uchar; 16usize], *mut c_void) -> c_int,
        );
        let hsk_cb = Some(
            handshake_cb
                as unsafe extern "C" fn(
                    *const kvmi_qemu2introspector,
                    *mut kvmi_introspector2qemu,
                    *mut c_void,
                ) -> c_int,
        );
        let mut kvmi_con = KVMiCon {
            dom: null_mut(),
            guard: Mutex::new(false),
            condvar: Condvar::new(),
        };
        let cb_ctx: *mut c_void = &mut kvmi_con as *mut _ as *mut _;
        // kvmi_dom = NULL
        let mut connected = kvmi_con
            .guard
            .lock()
            .expect("Failed to acquire connection mutex");
        self.ctx = (self.libkvmi.init_unix_socket)(socket_path.as_ptr(), accept_db, hsk_cb, cb_ctx);
        if !self.ctx.is_null() {
            debug!("Waiting for connection...");
            while !*connected {
                connected = kvmi_con.condvar.wait(connected).unwrap();
            }
        }
        // TODO: error handling
        self.dom = kvmi_con.dom;
        Ok(())
    }

    fn control_events(
        &self,
        vcpu: u16,
        intercept_type: KVMiInterceptType,
        enabled: bool,
    ) -> Result<(), Error> {
        let res = (self.libkvmi.control_events)(
            self.dom,
            vcpu,
            intercept_type.to_i32().unwrap(),
            enabled,
        );
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn control_cr(&self, vcpu: u16, reg: KVMiCr, enabled: bool) -> Result<(), Error> {
        let res = (self.libkvmi.control_cr)(self.dom, vcpu, reg.to_u32().unwrap(), enabled);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn control_msr(&self, vcpu: u16, reg: u32, enabled: bool) -> Result<(), Error> {
        let res = (self.libkvmi.control_msr)(self.dom, vcpu, reg, enabled);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn read_physical(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let buf_ptr = buffer.as_mut_ptr() as *mut c_void;
        let res = (self.libkvmi.read_physical)(self.dom, gpa, buf_ptr, buffer.len());
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn write_physical(&self, gpa: u64, buffer: &[u8]) -> Result<(), Error> {
        let buf_ptr = buffer.as_ptr() as *mut c_void;
        let res = (self.libkvmi.write_physical)(self.dom, gpa, buf_ptr, buffer.len());
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn get_page_access(&self, gpa: u64) -> Result<u8, Error> {
        let mut access: c_uchar = 0;
        let res = (self.libkvmi.get_page_access)(self.dom, gpa, &mut access);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(access)
    }

    fn set_page_access(&self, mut gpa: u64, mut access: u8) -> Result<(), Error> {
        let count: c_ushort = 1;
        let res = (self.libkvmi.set_page_access)(self.dom, &mut gpa, &mut access, count);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn pause(&self) -> Result<(), Error> {
        let vcpu_count = self.get_vcpu_count()?;
        let res = (self.libkvmi.pause_all_vcpus)(self.dom, vcpu_count);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn get_vcpu_count(&self) -> Result<u32, Error> {
        let mut vcpu_count: c_uint = 0;
        let res = (self.libkvmi.get_vcpu_count)(self.dom, &mut vcpu_count);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(vcpu_count)
    }


    fn get_registers(&self, vcpu: u16) -> Result<(kvm_regs, kvm_sregs, KvmMsr), Error> {
        let mut regs: kvm_regs = unsafe { mem::MaybeUninit::<kvm_regs>::zeroed().assume_init() };
        let mut sregs: kvm_sregs = unsafe { mem::MaybeUninit::<kvm_sregs>::zeroed().assume_init() };
        let mut msrs: KvmMsr = unsafe { mem::MaybeUninit::<KvmMsr>::zeroed().assume_init() };
        let mut mode: c_uint = 0;
        msrs.msrs.nmsrs = 6;
        msrs.entries[0].index = KVMiMsr::SysenterCs as u32;
        msrs.entries[1].index = KVMiMsr::SysenterEsp as u32;
        msrs.entries[2].index = KVMiMsr::SysenterEip as u32;
        msrs.entries[3].index = KVMiMsr::MsrEfer as u32;
        msrs.entries[4].index = KVMiMsr::MsrStar as u32;
        msrs.entries[5].index = KVMiMsr::MsrLstar as u32;
        let res = (self.libkvmi.get_registers)(
            self.dom,
            vcpu,
            &mut regs,
            &mut sregs,
            &mut msrs.msrs,
            &mut mode,
        );
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok((regs, sregs, msrs))
    }

    fn set_registers(&self, vcpu: u16, regs: &kvm_regs) -> Result<(), Error> {
        let res = (self.libkvmi.set_registers)(self.dom, vcpu, regs);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn wait_and_pop_event(&self, ms: i32) -> Result<Option<KVMiEvent>, Error> {
        let res = (self.libkvmi.wait_event)(self.dom, ms);
        if res != 0 {
            // no events ?
            if Errno::last() == Errno::ETIMEDOUT {
                return Ok(None);
            }
            return Err(Error::last_os_error());
        }
        // a new event is available
        // kvmi_pop_event will allocate the struct and set this pointer
        let mut ev_ptr: *mut kvmi_dom_event = null_mut();
        let ev_ptr_ptr = &mut ev_ptr as *mut _;
        let res = (self.libkvmi.pop_event)(self.dom, ev_ptr_ptr);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        let ev_type = unsafe {
            let ev_u8 = (*ev_ptr).event.common.event.try_into().unwrap();
            match KVMiInterceptType::from_u32(ev_u8).unwrap() {
                KVMiInterceptType::PauseVCPU => KVMiEventType::PauseVCPU,
                KVMiInterceptType::Breakpoint => KVMiEventType::Breakpoint {
                    gpa: (*ev_ptr).event.__bindgen_anon_1.breakpoint.gpa,
                    insn_len: (*ev_ptr).event.__bindgen_anon_1.breakpoint.insn_len,
                },
                KVMiInterceptType::Pagefault => KVMiEventType::Pagefault {
                    gpa: (*ev_ptr).event.__bindgen_anon_1.page_fault.gpa,
                    gva: (*ev_ptr).event.__bindgen_anon_1.page_fault.gva,
                    access: (*ev_ptr).event.__bindgen_anon_1.page_fault.access,
                    view: (*ev_ptr).event.__bindgen_anon_1.page_fault.view,
                },

                KVMiInterceptType::Cr => KVMiEventType::Cr {
                    cr_type: KVMiCr::from_i32(
                        (*ev_ptr).event.__bindgen_anon_1.cr.cr.try_into().unwrap(),
                    )
                    .unwrap(),
                    new: (*ev_ptr).event.__bindgen_anon_1.cr.new_value,
                    old: (*ev_ptr).event.__bindgen_anon_1.cr.old_value,
                },
                KVMiInterceptType::Msr => KVMiEventType::Msr {
                    msr_type: (*ev_ptr).event.__bindgen_anon_1.msr.msr,
                    new: (*ev_ptr).event.__bindgen_anon_1.msr.new_value,
                    old: (*ev_ptr).event.__bindgen_anon_1.msr.old_value,
                },
            }
        };
        let kvmi_event = KVMiEvent {
            vcpu: unsafe { (*ev_ptr).event.common.vcpu },
            ev_type,
            ffi_event: ev_ptr,
        };
        Ok(Some(kvmi_event))
    }

    fn reply(&self, event: &KVMiEvent, reply_type: KVMiEventReply) -> Result<(), Error> {
        // reply should be like the following C struct
        /*
            struct {
                struct kvmi_vcpu_hdr hdr;
                struct kvmi_event_reply common;
                // event specific reply struct (ex: struct kvmi_event_cr_reply cr)
            } rpl = {0};
        */

        // declare and set EventReplyCommon to factorise some code
        #[repr(C)]
        struct EventReplyCommon {
            hdr: kvmi_vcpu_hdr,
            common: kvmi_event_reply,
        }
        let mut reply_common =
            unsafe { mem::MaybeUninit::<EventReplyCommon>::zeroed().assume_init() };
        unsafe {
            // set hdr
            reply_common.hdr.vcpu = (*event.ffi_event).event.common.vcpu;
            // set common
            reply_common.common.event = (*event.ffi_event).event.common.event;
        }
        reply_common.common.action = reply_type.to_i32().unwrap().try_into().unwrap();
        // we need the event sequence number for the reply
        let seq = unsafe { (*event.ffi_event).seq };

        let res = match event.ev_type {
            // PauseVCPU event doesn't have any event specific struct
            // reuse EventReplyCommon
            KVMiEventType::PauseVCPU => {
                let size = mem::size_of::<EventReplyCommon>();
                let rpl_ptr: *const c_void = &reply_common as *const _ as *const c_void;
                (self.libkvmi.reply_event)(self.dom, seq, rpl_ptr, size as usize)
            }
            KVMiEventType::Breakpoint {
                gpa: _,
                insn_len: _,
            } => {
                let size = mem::size_of::<EventReplyCommon>();
                let rpl_ptr: *const c_void = &reply_common as *const _ as *const c_void;
                (self.libkvmi.reply_event)(self.dom, seq, rpl_ptr, size as usize)
            }
            KVMiEventType::Pagefault {
                gpa: _,
                gva: _,
                access: _,
                view: _,
            } => {
                #[repr(C)]
                struct EventReplyPagefault {
                    common: EventReplyCommon,
                    pf: kvmi_event_pf_reply,
                }

                let mut reply =
                    unsafe { mem::MaybeUninit::<EventReplyPagefault>::zeroed().assume_init() };
                reply.common = reply_common;
                reply.pf.ctx_addr = 0;
                reply.pf.ctx_size = 0;
                reply.pf.singlestep = 0;
                reply.pf.rep_complete = 0;
                reply.pf.padding = 0;
                reply.pf.ctx_data = [0; 256];
                let size = mem::size_of::<EventReplyPagefault>();
                let rpl_ptr: *const c_void = &reply as *const _ as *const c_void;
                (self.libkvmi.reply_event)(self.dom, seq, rpl_ptr, size as usize)
            }
            KVMiEventType::Cr {
                cr_type: _,
                new,
                old: _,
            } => {
                #[repr(C)]
                struct EventReplyCr {
                    common: EventReplyCommon,
                    cr: kvmi_event_cr_reply,
                }

                let mut reply = unsafe { mem::MaybeUninit::<EventReplyCr>::zeroed().assume_init() };
                reply.common = reply_common;
                // set event specific attributes
                // reply.cr.xxx = ...
                reply.cr.new_val = new;
                let size = mem::size_of::<EventReplyCr>();
                let rpl_ptr: *const c_void = &reply as *const _ as *const c_void;
                (self.libkvmi.reply_event)(self.dom, seq, rpl_ptr, size as usize)
            }

            KVMiEventType::Msr {
                msr_type: _,
                new,
                old: _,
            } => {
                #[repr(C)]
                struct EventReplyMsr {
                    common: EventReplyCommon,
                    msr: kvmi_event_msr_reply,
                }

                let mut reply =
                    unsafe { mem::MaybeUninit::<EventReplyMsr>::zeroed().assume_init() };
                reply.common = reply_common;
                // set event specific attributes
                // reply.cr.xxx = ...
                reply.msr.new_val = new;
                let size = mem::size_of::<EventReplyMsr>();
                let rpl_ptr: *const c_void = &reply as *const _ as *const c_void;
                (self.libkvmi.reply_event)(self.dom, seq, rpl_ptr, size as usize)
            }
        };

        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn get_maximum_gfn(&self) -> Result<u64, Error> {
        let mut max_gfn: u64 = 0;
        let res = (self.libkvmi.get_maximum_gfn)(self.dom, &mut max_gfn);
        if res > 0 {
            return Err(Error::last_os_error());
        }
        Ok(max_gfn)
    }
}

impl Drop for KVMi {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            (self.libkvmi.uninit)(self.ctx);
            self.ctx = null_mut();
        }
        if !self.dom.is_null() {
            (self.libkvmi.domain_close)(self.dom, true);
            self.dom = null_mut();
        }
    }
}

impl Drop for KVMiEvent {
    fn drop(&mut self) {
        unsafe { free(self.ffi_event as *mut c_void) };
    }
}
