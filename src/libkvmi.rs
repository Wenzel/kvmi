use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_ulonglong, c_ushort, c_void};

use kvmi_sys::{
    kvm_msrs, kvm_regs, kvm_sregs, kvmi_dom_event, kvmi_handshake_cb, kvmi_log_cb,
    kvmi_new_guest_cb, kvmi_timeout_t,
};
use libloading::os::unix::Symbol as RawSymbol;
use libloading::{Error, Library, Symbol};

const LIBKVMI_FILENAME: &str = "libkvmi.so";
// libkvmi function definitions type aliases
// kvmi_init_vsock
type FnInitVSock = extern "C" fn(
    port: c_uint,
    accept_cb: kvmi_new_guest_cb,
    hsk_cb: kvmi_handshake_cb,
    cb_ctx: *mut c_void,
) -> *mut c_void;
// kvmi_init_unix_socket
type FnInitUnixSocket = extern "C" fn(
    socket: *const c_char,
    accept_cb: kvmi_new_guest_cb,
    hsk_cb: kvmi_handshake_cb,
    cb_ctx: *mut c_void,
) -> *mut c_void;
// kvmi_uninit
type FnUninit = extern "C" fn(ctx: *mut c_void);
// kvmi_close
type FnClose = extern "C" fn(ctx: *mut c_void);
// kvmi_domain_close
type FnDomainClose = extern "C" fn(dom: *mut c_void, do_shutdown: bool);
// kvmi_domain_is_connected
type FnDomainIsConnected = extern "C" fn(dom: *const c_void) -> bool;
// kvmi_domain_name
type FnDomainName = extern "C" fn(dom: *const c_void, dest: *mut c_char, dest_size: usize);
// kvmi_connection_fd
type FnConnectionFd = extern "C" fn(dom: *const c_void) -> c_int;
// kvmi_get_version
type FnGetVersion = extern "C" fn(dom: *mut c_void, version: *mut c_uint) -> c_int;
// kvmi_control_events
type FnControlEvents =
    extern "C" fn(dom: *mut c_void, vcpu: c_ushort, events: c_int, enable: bool) -> c_int;
// kvmi_control_cr
type FnControlCr =
    extern "C" fn(dom: *mut c_void, vcpu: c_ushort, cr: c_uint, enable: bool) -> c_int;
// kvmi_control_msr
type FnControlMsr =
    extern "C" fn(dom: *mut c_void, vcpu: c_ushort, msr: c_uint, enable: bool) -> c_int;
// kvmi_pause_all_vcpus
type FnPauseAllVCPUs = extern "C" fn(dom: *mut c_void, count: c_uint) -> c_int;
// kvmi_get_vcpu_count
type FnGetVCPUCount = extern "C" fn(dom: *mut c_void, count: *mut c_uint) -> c_int;
// kvmi_read_physical
type FnReadPhysical =
    extern "C" fn(dom: *mut c_void, gpa: c_ulonglong, buffer: *mut c_void, size: usize) -> c_int;
// kvmi_write_physical
type FnWritePhysical =
    extern "C" fn(dom: *mut c_void, gpa: c_ulonglong, buffer: *const c_void, size: usize) -> c_int;
//kvmi_set_page_access
type FnSetPageAccess = extern "C" fn(
    dom: *mut c_void,
    gpa: *mut c_ulonglong,
    access: *mut c_uchar,
    count: c_ushort,
    view: c_ushort,
) -> c_int;

// kvmi_get_registers
type FnGetRegisters = extern "C" fn(
    dom: *mut c_void,
    vcpu: c_ushort,
    regs: *mut kvm_regs,
    sregs: *mut kvm_sregs,
    msrs: *mut kvm_msrs,
    mode: *mut c_uint,
) -> c_int;

//kvmi_set_registers
type FnSetRegisters =
    extern "C" fn(dom: *mut c_void, vcpu: c_ushort, regs: *const kvm_regs) -> c_int;

// kvmi_reply_event
type FnReplyEvent = extern "C" fn(
    dom: *mut c_void,
    msg_seq: c_uint,
    data: *const c_void,
    data_size: usize,
) -> c_int;
// kvmi_pop_event
type FnPopEvent = extern "C" fn(dom: *mut c_void, event: *mut *mut kvmi_dom_event) -> c_int;
// kvmi_wait_event
type FnWaitEvent = extern "C" fn(dom: *mut c_void, ms: kvmi_timeout_t) -> c_int;
// kvmi_set_log_cb
type FnSetLogCb = extern "C" fn(cb: kvmi_log_cb, ctx: *mut c_void);
// kvmi_get_maximum_gfn
type FnGetMaximumGFN = extern "C" fn(dom: *mut c_void, gfn: *mut c_ulonglong) -> c_int;

#[derive(Debug)]
pub struct Libkvmi {
    lib: Library,
    pub init_vsock: RawSymbol<FnInitVSock>,
    pub init_unix_socket: RawSymbol<FnInitUnixSocket>,
    pub uninit: RawSymbol<FnUninit>,
    pub close: RawSymbol<FnClose>,
    pub domain_close: RawSymbol<FnDomainClose>,
    pub domain_is_connected: RawSymbol<FnDomainIsConnected>,
    pub domain_name: RawSymbol<FnDomainName>,
    pub connection_fd: RawSymbol<FnConnectionFd>,
    pub get_version: RawSymbol<FnGetVersion>,
    pub control_events: RawSymbol<FnControlEvents>,
    pub control_cr: RawSymbol<FnControlCr>,
    pub control_msr: RawSymbol<FnControlMsr>,
    pub pause_all_vcpus: RawSymbol<FnPauseAllVCPUs>,
    pub get_vcpu_count: RawSymbol<FnGetVCPUCount>,
    pub read_physical: RawSymbol<FnReadPhysical>,
    pub write_physical: RawSymbol<FnWritePhysical>,
    pub set_page_access: RawSymbol<FnSetPageAccess>,
    pub get_registers: RawSymbol<FnGetRegisters>,
    pub set_registers: RawSymbol<FnSetRegisters>,
    pub reply_event: RawSymbol<FnReplyEvent>,
    pub pop_event: RawSymbol<FnPopEvent>,
    pub wait_event: RawSymbol<FnWaitEvent>,
    pub set_log_cb: RawSymbol<FnSetLogCb>,
    pub get_maximum_gfn: RawSymbol<FnGetMaximumGFN>,
}

impl Libkvmi {
    pub unsafe fn new() -> Result<Self, Error> {
        info!("Loading {}", LIBKVMI_FILENAME);
        let lib = Library::new(LIBKVMI_FILENAME)?;
        // load symbols
        let init_vsock_sym: Symbol<FnInitVSock> = lib.get(b"kvmi_init_vsock\0")?;
        let init_vsock = init_vsock_sym.into_raw();

        let init_unix_socket_sym: Symbol<FnInitUnixSocket> = lib.get(b"kvmi_init_unix_socket\0")?;
        let init_unix_socket = init_unix_socket_sym.into_raw();

        let uninit_sym: Symbol<FnUninit> = lib.get(b"kvmi_uninit\0")?;
        let uninit = uninit_sym.into_raw();

        let close_sym: Symbol<FnClose> = lib.get(b"kvmi_close\0")?;
        let close = close_sym.into_raw();

        let domain_close_sym: Symbol<FnDomainClose> = lib.get(b"kvmi_close\0")?;
        let domain_close = domain_close_sym.into_raw();

        let domain_is_connected_sym: Symbol<FnDomainIsConnected> =
            lib.get(b"kvmi_domain_is_connected\0")?;
        let domain_is_connected = domain_is_connected_sym.into_raw();

        let domain_name_sym: Symbol<FnDomainName> = lib.get(b"kvmi_domain_name\0")?;
        let domain_name = domain_name_sym.into_raw();

        let connection_fd_sym: Symbol<FnConnectionFd> = lib.get(b"kvmi_connection_fd\0")?;
        let connection_fd = connection_fd_sym.into_raw();

        let get_version_sym: Symbol<FnGetVersion> = lib.get(b"kvmi_get_version\0")?;
        let get_version = get_version_sym.into_raw();

        let control_events_sym: Symbol<FnControlEvents> = lib.get(b"kvmi_control_events\0")?;
        let control_events = control_events_sym.into_raw();

        let control_cr_sym: Symbol<FnControlCr> = lib.get(b"kvmi_control_cr\0")?;
        let control_cr = control_cr_sym.into_raw();

        let control_msr_sym: Symbol<FnControlMsr> = lib.get(b"kvmi_control_msr\0")?;
        let control_msr = control_msr_sym.into_raw();

        let pause_all_vcpus_sym: Symbol<FnPauseAllVCPUs> = lib.get(b"kvmi_pause_all_vcpus\0")?;
        let pause_all_vcpus = pause_all_vcpus_sym.into_raw();

        let get_vcpu_count_sym: Symbol<FnGetVCPUCount> = lib.get(b"kvmi_get_vcpu_count\0")?;
        let get_vcpu_count = get_vcpu_count_sym.into_raw();

        let read_physical_sym: Symbol<FnReadPhysical> = lib.get(b"kvmi_read_physical\0")?;
        let read_physical = read_physical_sym.into_raw();

        let write_physical_sym: Symbol<FnWritePhysical> = lib.get(b"kvmi_write_physical\0")?;
        let write_physical = write_physical_sym.into_raw();

        let set_page_access_sym: Symbol<FnSetPageAccess> = lib.get(b"kvmi_set_page_access\0")?;
        let set_page_access = set_page_access_sym.into_raw();

        let get_registers_sym: Symbol<FnGetRegisters> = lib.get(b"kvmi_get_registers\0")?;
        let get_registers = get_registers_sym.into_raw();

        let set_registers_sym: Symbol<FnSetRegisters> = lib.get(b"kvmi_set_registers\0")?;
        let set_registers = set_registers_sym.into_raw();

        let reply_event_sym: Symbol<FnReplyEvent> = lib.get(b"kvmi_reply_event\0")?;
        let reply_event = reply_event_sym.into_raw();

        let pop_event_sym: Symbol<FnPopEvent> = lib.get(b"kvmi_pop_event\0")?;
        let pop_event = pop_event_sym.into_raw();

        let wait_event_sym: Symbol<FnWaitEvent> = lib.get(b"kvmi_wait_event\0")?;
        let wait_event = wait_event_sym.into_raw();

        let set_log_cb_sym: Symbol<FnSetLogCb> = lib.get(b"kvmi_set_log_cb\0")?;
        let set_log_cb = set_log_cb_sym.into_raw();

        let get_maximum_gfn_sym: Symbol<FnGetMaximumGFN> = lib.get(b"kvmi_get_maximum_gfn\0")?;
        let get_maximum_gfn = get_maximum_gfn_sym.into_raw();

        Ok(Libkvmi {
            lib,
            init_vsock,
            init_unix_socket,
            uninit,
            close,
            domain_close,
            domain_is_connected,
            domain_name,
            connection_fd,
            get_version,
            control_events,
            control_cr,
            control_msr,
            pause_all_vcpus,
            get_vcpu_count,
            read_physical,
            write_physical,
            set_page_access,
            get_registers,
            set_registers,
            reply_event,
            pop_event,
            wait_event,
            set_log_cb,
            get_maximum_gfn,
        })
    }
}
