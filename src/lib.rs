use kvmi_sys;
use kvmi_sys::{kvmi_qemu2introspector, kvmi_introspector2qemu};
use std::ffi::{CString};
use std::ptr::{null_mut};
use std::os::raw::{c_void, c_uchar, c_int};


#[derive(Debug)]
pub struct KVMi {
    ctx: *mut c_void,
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
    pub fn new() {
        let socket_path = CString::new("/tmp/introspector").unwrap();
        let accept_db = Some(new_guest_cb as
                             unsafe extern fn(*mut c_void,
                                              *mut [c_uchar; 16usize],
                                              *mut c_void) -> c_int);
        let hsk_cb = Some(handshake_cb as
                          unsafe extern fn(*const kvmi_qemu2introspector,
                                           *mut kvmi_introspector2qemu,
                                           *mut c_void) -> c_int);
        let ctx = null_mut();
        unsafe {
            kvmi_sys::kvmi_init_unix_socket(socket_path.as_ptr(), accept_db, hsk_cb, ctx);
        }
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
