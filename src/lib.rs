use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;
use kvmi_sys;
use kvmi_sys::{kvmi_qemu2introspector, kvmi_introspector2qemu};
use std::ffi::{CString};
use std::ptr::{null_mut};
use std::os::raw::{c_void, c_uchar, c_int, c_uint};
use std::sync::{Mutex, Condvar};
use std::io::Error;
use std::mem;


#[derive(Debug)]
pub struct KVMi {
    ctx: *mut c_void,
    dom: *mut c_void,
}

#[derive(Debug)]
struct KVMiCon {
    dom: *mut c_void,
    guard: Mutex<bool>,
    condvar: Condvar,
}

#[derive(Primitive)]
pub enum KVMiEventType {
    Unhook = kvmi_sys::KVMI_EVENT_UNHOOK as isize,
    Cr = kvmi_sys::KVMI_EVENT_CR as isize,
    Msr = kvmi_sys::KVMI_EVENT_MSR as isize,
    XSetBv = kvmi_sys::KVMI_EVENT_XSETBV as isize,
    Breakoint = kvmi_sys::KVMI_EVENT_BREAKPOINT as isize,
    Hypercall = kvmi_sys::KVMI_EVENT_HYPERCALL as isize,
    Pf = kvmi_sys::KVMI_EVENT_PF as isize,
    Trap = kvmi_sys::KVMI_EVENT_TRAP as isize,
    Descriptor = kvmi_sys::KVMI_EVENT_DESCRIPTOR as isize,
    CreateVCPU = kvmi_sys::KVMI_EVENT_CREATE_VCPU as isize,
    PauseVCPU = kvmi_sys::KVMI_EVENT_PAUSE_VCPU as isize,
}

pub struct KVMiEvent {
    kind: KVMiEventType,
}

unsafe extern "C" fn new_guest_cb(dom: *mut c_void,
                           uuid: *mut [c_uchar; 16usize],
                           cb_ctx: *mut c_void) -> c_int {
    println!("new guest cb !");
    if cb_ctx.is_null() {
        panic!("Unexpected null context");
    }
    let kvmi_con = unsafe { &mut *(cb_ctx as *mut KVMiCon) };
    let mut started = kvmi_con.guard.lock().expect("Failed to acquire connexion mutex");
    kvmi_con.dom = dom;
    *started = true;
    // wake up waiters
    kvmi_con.condvar.notify_one();
    0
}

extern "C" fn handshake_cb(arg1: *const kvmi_qemu2introspector,
                           arg2: *mut kvmi_introspector2qemu,
                           cb_ctx: *mut c_void) -> c_int {
    println!("handshake cb !");
    0
}

impl KVMi {
    pub fn new(socket_path: &str) -> KVMi {
        let socket_path = CString::new(socket_path.as_bytes()).unwrap();
        let accept_db = Some(new_guest_cb as
                             unsafe extern "C" fn(*mut c_void,
                                              *mut [c_uchar; 16usize],
                                              *mut c_void) -> c_int);
        let hsk_cb = Some(handshake_cb as
                          unsafe extern "C" fn(*const kvmi_qemu2introspector,
                                           *mut kvmi_introspector2qemu,
                                           *mut c_void) -> c_int);
        let mut kvmi = KVMi {
            ctx: null_mut(),
            dom: null_mut(),
        };
        let mut kvmi_con = KVMiCon {
            dom: null_mut(),
            guard: Mutex::new(false),
            condvar: Condvar::new(),
        };
        let cb_ctx: *mut c_void = &mut kvmi_con as *mut _ as *mut _;
        // kvmi_dom = NULL
        let lock = kvmi_con.guard.lock().expect("Failed to acquire connexion mutex");
        kvmi.ctx = unsafe {
            kvmi_sys::kvmi_init_unix_socket(socket_path.as_ptr(), accept_db, hsk_cb, cb_ctx)
        };
        if !kvmi.ctx.is_null() {
            // wait for connexion
            println!("Waiting for connexion..");
            kvmi_con.condvar.wait(lock).unwrap();
        }
        // TODO: error handling
        kvmi.dom = kvmi_con.dom;
        println!("Connected {:?}", kvmi);
        kvmi
    }

    pub fn pause(&self) -> Result<u32,Error> {
        let mut expected_count: c_uint = 0;
        let mut expected_count_ptr = &mut expected_count;
        let res = unsafe {
            kvmi_sys::kvmi_pause_all_vcpus(self.dom, expected_count_ptr)
        };
        if res > 0 {
            return Err(Error::last_os_error())
        }
        Ok(expected_count)
    }

    pub fn wait_event(&self, ms: i32) -> Result<(),Error> {
        let res = unsafe {
            kvmi_sys::kvmi_wait_event(self.dom, ms)
        };
        if res > 0 {
            return Err(Error::last_os_error())
        }
        Ok(())
    }

    pub fn pop_event(&self) -> Result<KVMiEvent,Error> {
        let mut ev = unsafe {
            mem::MaybeUninit::<kvmi_sys::kvmi_dom_event>::zeroed().assume_init()
        };
        let mut ev_ptr = &mut ev as *mut _;
        let mut ev_ptr_ptr = &mut ev_ptr as *mut _;
        let res = unsafe {
            kvmi_sys::kvmi_pop_event(self.dom, ev_ptr_ptr)
        };
        if res > 0 {
            return Err(Error::last_os_error())
        }
        let kvmi_event = KVMiEvent {
            kind: KVMiEventType::from_u32(ev.event.common.event).unwrap(),
        };
        Ok(kvmi_event)
    }

    fn close(&mut self) {
        if self.ctx != null_mut() {
            unsafe {
                kvmi_sys::kvmi_uninit(self.ctx);
            };
            self.ctx = null_mut();
        }
        if self.dom != null_mut() {
            unsafe {
                kvmi_sys::kvmi_domain_close(self.dom, true);
            };
            self.dom = null_mut();
        }
    }
}

impl Drop for KVMi {
    fn drop(&mut self) {
        self.close();
    }
}
