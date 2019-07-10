use kvmi_sys;
use kvmi_sys::{kvmi_qemu2introspector, kvmi_introspector2qemu};
use std::ffi::{CString};
use std::ptr::{null_mut};
use std::os::raw::{c_void, c_uchar, c_int};
use std::sync::{Mutex, Condvar};


#[derive(Debug)]
pub struct KVMi {
    ctx: *mut c_void,
    connect_condvar: Condvar,
}

extern "C" fn new_guest_cb(dom: *mut c_void,
                           uuid: *mut [c_uchar; 16usize],
                           ctx: *mut c_void) -> c_int {
    println!("new guest cb !");
    0
}

extern "C" fn handshake_cb(arg1: *const kvmi_qemu2introspector,
                           arg2: *mut kvmi_introspector2qemu,
                           ctx: *mut c_void) -> c_int {
    println!("handshake cb !");
    0
}

impl KVMi {
    pub fn new(socket_path: String) -> KVMi {
        let socket_path = CString::new(socket_path.into_bytes()).unwrap();
        let accept_db = Some(new_guest_cb as
                             unsafe extern fn(*mut c_void,
                                              *mut [c_uchar; 16usize],
                                              *mut c_void) -> c_int);
        let hsk_cb = Some(handshake_cb as
                          unsafe extern fn(*const kvmi_qemu2introspector,
                                           *mut kvmi_introspector2qemu,
                                           *mut c_void) -> c_int);
        let mut kvmi = KVMi {
            ctx: null_mut(),
            connect_condvar: Condvar::new(),
        };
        let cb_ctx: *mut c_void = &kvmi;
        // kvmi_dom = NULL
        let guard = Mutex::new(false);
        let lock = guard.lock().unwrap();
        let res: *mut c_void = unsafe {
            kvmi_sys::kvmi_init_unix_socket(socket_path.as_ptr(), accept_db, hsk_cb, cb_ctx)
        };
        if res != null_mut() {
            // wait for connexion
            println!("Waiting for connexion..");
            kvmi.connect_condvar.wait(lock).unwrap();
        }
        kvmi
    }

    fn close(&mut self) {
        unsafe {
            kvmi_sys::kvmi_uninit(self.ctx);
        };
        self.ctx = null_mut();
    }
}

impl Drop for KVMi {
    fn drop(&mut self) {
        self.close();
    }
}
