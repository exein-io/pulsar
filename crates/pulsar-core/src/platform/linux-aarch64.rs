pub mod file {

    /// O_* macros for fcntl/open are architecture-specific
    pub mod flags {
        pub const O_RDONLY: u32 = 0;
        pub const O_WRONLY: u32 = 1;
        pub const O_RDWR: u32 = 2;
        pub const O_CREAT: u32 = 0x40;
        pub const O_EXCL: u32 = 0x80;
        pub const O_NOCTTY: u32 = 0x100;
        pub const O_TRUNC: u32 = 0x200;
        pub const O_APPEND: u32 = 0x400;
        pub const O_NONBLOCK: u32 = 0x800;
        pub const O_DIRECTORY: u32 = 0x4000;
        pub const O_LARGEFILE: u32 = 0x20000;
    }
}
