#[macro_use]
extern crate log;

mod libkvmi;

use std::convert::TryInto;
use std::ffi::CString;
use std::io::Error;
use std::mem;
use std::os::raw::{c_int, c_uchar, c_uint, c_void};
use std::ptr::null_mut;
use std::sync::{Condvar, Mutex};

use enum_primitive_derive::Primitive;
use kvmi_sys;
use kvmi_sys::{
    kvm_msrs, kvm_regs, kvm_sregs, kvmi_dom_event, kvmi_event_cr_reply, kvmi_event_reply,
    kvmi_introspector2qemu, kvmi_qemu2introspector, kvmi_vcpu_hdr, KVMI_EVENT_CR,
    KVMI_EVENT_PAUSE_VCPU,
};
use kvmi_sys::kvm_msr_entry;

use libc::free;
use nix::errno::Errno;
use num_traits::{FromPrimitive, ToPrimitive};

use libkvmi::Libkvmi;

#[derive(Debug)]
pub struct KVMi {
    ctx: *mut c_void,
    dom: *mut c_void,
    libkvmi: Libkvmi,
}

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
}

#[derive(Debug, Copy, Clone)]
pub enum KVMiEventType {
    PauseVCPU,
    Cr { cr_type: KVMiCr, new: u64, old: u64 },
}

#[derive(Primitive, Debug, Copy, Clone)]
pub enum KVMiEventReply {
    Continue = kvmi_sys::KVMI_EVENT_ACTION_CONTINUE as isize,
    Retry = kvmi_sys::KVMI_EVENT_ACTION_RETRY as isize,
    Crash = kvmi_sys::KVMI_EVENT_ACTION_CRASH as isize,
}

#[derive(Primitive, Debug, Copy, Clone)]
pub enum KVMiCr {
    Cr0 = 0,
    Cr2 = 2,
    Cr3 = 3,
    Cr4 = 4,
}

#[derive(Debug)]
pub struct KVMiEvent {
    pub vcpu: u16,
    pub ev_type: KVMiEventType,
    ffi_event: *mut kvmi_dom_event,
}

pub struct kvm_msr
{
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
    let mut started = kvmi_con
        .guard
        .lock()
        .expect("Failed to acquire connexion mutex");
    kvmi_con.dom = dom;
    *started = true;
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

impl KVMi {
    pub fn new(socket_path: &str) -> KVMi {
        let libkvmi = unsafe { Libkvmi::new() };
        let socket_path = CString::new(socket_path.clone()).unwrap();
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
        let mut kvmi = KVMi {
            ctx: null_mut(),
            dom: null_mut(),
            libkvmi,
        };
        let mut kvmi_con = KVMiCon {
            dom: null_mut(),
            guard: Mutex::new(false),
            condvar: Condvar::new(),
        };
        let cb_ctx: *mut c_void = &mut kvmi_con as *mut _ as *mut _;
        // kvmi_dom = NULL
        let lock = kvmi_con
            .guard
            .lock()
            .expect("Failed to acquire connexion mutex");
        kvmi.ctx = (kvmi.libkvmi.init_unix_socket)(socket_path.as_ptr(), accept_db, hsk_cb, cb_ctx);
        if !kvmi.ctx.is_null() {
            // wait for connexion
            debug!("Waiting for connexion...");
            kvmi_con.condvar.wait(lock).unwrap();
        }
        // TODO: error handling
        kvmi.dom = kvmi_con.dom;
        kvmi
    }

    pub fn control_events(
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

    pub fn control_cr(&self, vcpu: u16, reg: KVMiCr, enabled: bool) -> Result<(), Error> {
        let res = (self.libkvmi.control_cr)(self.dom, vcpu, reg.to_u32().unwrap(), enabled);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn read_physical(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let buf_ptr = buffer.as_mut_ptr() as *mut c_void;
        let res = (self.libkvmi.read_physical)(self.dom, gpa, buf_ptr, buffer.len());
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn write_physical(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let buf_ptr = buffer.as_mut_ptr() as *mut c_void;
        let res = (self.libkvmi.write_physical)(self.dom, gpa, buf_ptr, buffer.len());
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn pause(&self) -> Result<(), Error> {
        let vcpu_count = self.get_vcpu_count()?;
        let res = (self.libkvmi.pause_all_vcpus)(self.dom, vcpu_count);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn get_vcpu_count(&self) -> Result<u32, Error> {
        let mut vcpu_count: c_uint = 0;
        let res = (self.libkvmi.get_vcpu_count)(self.dom, &mut vcpu_count);
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(vcpu_count)
    }

    pub fn get_registers(&self, vcpu: u16,) -> Result<(kvm_regs, kvm_sregs,kvm_msr), Error> {
        let mut regs: kvm_regs = unsafe { mem::MaybeUninit::<kvm_regs>::zeroed().assume_init() };
        let mut sregs: kvm_sregs = unsafe { mem::MaybeUninit::<kvm_sregs>::zeroed().assume_init() };
        let mut msrs: kvm_msr = unsafe { mem::MaybeUninit::<kvm_msr>::zeroed().assume_init() };
        let mut mode: c_uint = 0;
        msrs.msrs.nmsrs=6;
        msrs.entries[0].index = 0x00000174;
        msrs.entries[1].index = 0x00000175;
        msrs.entries[2].index = 0x00000176;
        msrs.entries[3].index = 0xc0000080;
        msrs.entries[4].index = 0xc0000081;
        msrs.entries[5].index = 0xc0000082;
        let res = (self.libkvmi.get_registers)(
            self.dom, vcpu, &mut regs, &mut sregs, &mut msrs.msrs, &mut mode,
        );
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok((regs, sregs, msrs))
    }


     pub fn set_registers(&self, vcpu: u16, regs: &mut kvm_regs) -> Result<(), Error> {
       let res = (self.libkvmi.set_registers)(
            self.dom, vcpu, regs
        );
        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn wait_and_pop_event(&self, ms: i32) -> Result<Option<KVMiEvent>, Error> {
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
                KVMiInterceptType::Cr => KVMiEventType::Cr {
                    cr_type: KVMiCr::from_i32(
                        (*ev_ptr).event.__bindgen_anon_1.cr.cr.try_into().unwrap(),
                    )
                    .unwrap(),
                    new: (*ev_ptr).event.__bindgen_anon_1.cr.new_value,
                    old: (*ev_ptr).event.__bindgen_anon_1.cr.old_value,
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

    pub fn reply(&self, event: &KVMiEvent, reply_type: KVMiEventReply) -> Result<(), Error> {
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
        };

        if res != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn get_maximum_gfn(&self) -> Result<u64, Error> {
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
        if self.ctx != null_mut() {
            (self.libkvmi.uninit)(self.ctx);
            self.ctx = null_mut();
        }
        if self.dom != null_mut() {
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

