use kvmi_sys;
use kvmi_sys::{kvmi_qemu2introspector, kvmi_introspector2qemu};
use std::ffi::{CString};
use std::ptr::{null_mut};
use std::os::raw::{c_void, c_uchar, c_int, c_uint};
use std::sync::{Mutex, Condvar};
use std::io::Error;


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

    fn pause(&self) -> Result<u32,Error> {
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

    fn wait_event(&self, ms: i32) -> Result<(),Error>{
        let res = unsafe {
            kvmi_sys::kvmi_wait_event(self.dom, ms)
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
