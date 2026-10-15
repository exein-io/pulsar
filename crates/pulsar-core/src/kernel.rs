pub mod file {

    pub mod flags {
        pub use linux_raw_sys::general::{
            O_ACCMODE, O_APPEND, O_CREAT, O_DIRECTORY, O_EXCL, O_LARGEFILE, O_NOCTTY, O_NONBLOCK,
            O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
        };
    }
}
