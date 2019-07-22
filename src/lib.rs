use enum_primitive_derive::Primitive;
use num_traits::{FromPrimitive, ToPrimitive};
use kvmi_sys;
use kvmi_sys::{kvmi_qemu2introspector, kvmi_introspector2qemu, kvmi_dom_event,kvmi_event_reply,
               KVMI_EVENT_ACTION_CONTINUE};
use std::ffi::CString;
use std::ptr::null_mut;
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

#[derive(Primitive,Debug)]
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

#[derive(Debug)]
pub struct KVMiEvent {
    pub kind: KVMiEventType,
    pub seq: u32,
}

unsafe extern "C" fn new_guest_cb(dom: *mut c_void,
                           _uuid: *mut [c_uchar; 16usize],
                           cb_ctx: *mut c_void) -> c_int {
    println!("new guest cb !");
    if cb_ctx.is_null() {
        panic!("Unexpected null context");
    }
    let kvmi_con = &mut *(cb_ctx as *mut KVMiCon);
    let mut started = kvmi_con.guard.lock().expect("Failed to acquire connexion mutex");
    kvmi_con.dom = dom;
    *started = true;
    // wake up waiters
    kvmi_con.condvar.notify_one();
    0
}

extern "C" fn handshake_cb(_arg1: *const kvmi_qemu2introspector,
                           _arg2: *mut kvmi_introspector2qemu,
                           _cb_ctx: *mut c_void) -> c_int {
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

    pub fn read_physical(&self, gpa: u64, buffer: &mut [u8]) -> Result<(),Error> {
        let res = unsafe {
            let buf_ptr = buffer.as_mut_ptr() as *mut c_void;
            kvmi_sys::kvmi_read_physical(self.dom, gpa, buf_ptr, buffer.len())
        };
        if res > 0 {
            return Err(Error::last_os_error())
        }
        Ok(())
    }

    pub fn pause(&self) -> Result<u32,Error> {
        let mut expected_count: c_uint = 0;
        let expected_count_ptr = &mut expected_count;
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
        // kvmi_pop_event will allocate the struct and set this pointer
        let mut ev_ptr: *mut kvmi_dom_event = null_mut();
        let ev_ptr_ptr = &mut ev_ptr as *mut _;
        let res = unsafe {
            kvmi_sys::kvmi_pop_event(self.dom, ev_ptr_ptr)
        };
        if res > 0 {
            return Err(Error::last_os_error())
        }
        let kvmi_event = unsafe {
            KVMiEvent {
                kind: KVMiEventType::from_u32((*ev_ptr).event.common.event).unwrap(),
                seq: (*ev_ptr).seq,
            }
        };
        Ok(kvmi_event)
    }

    pub fn reply_continue(&self, event: &KVMiEvent) -> Result<(),Error>{
        let size = mem::size_of::<kvmi_event_reply>();
        let res = unsafe {
            let mut rpl = mem::MaybeUninit::<kvmi_event_reply>::zeroed().assume_init();
            rpl.action = KVMI_EVENT_ACTION_CONTINUE;
            rpl.event = event.kind.to_u32().unwrap();
            let rpl_ptr = &rpl as *const kvmi_event_reply as *const c_void;
            kvmi_sys::kvmi_reply_event(self.dom, event.seq, rpl_ptr, size as u32)
        };
        if res > 0 {
            return Err(Error::last_os_error())
        }
        Ok(())
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
