use crate::KVMiEventType;
use libloading;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KVMiError {
    /// When waiting for the next Pause event timeouts while resuming the VM
    #[error("no pause events are available")]
    NoPauseEventAvailable,
    /// When expecting a Pause event while resuming the VM and receiving another event
    #[error("unexpected event {0:?} while resuming")]
    UnexpectedEventWhileResuming(KVMiEventType),
    #[error("Failed to load libkvmi.so")]
    LibloadingError(#[from] libloading::Error),
    /// Catch-all for underlying IO errors
    #[error("IO error")]
    IOError(#[from] io::Error),
}
