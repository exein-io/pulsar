pub mod file {

    /// O_* macros for fcntl/open are architecture-specific
    pub mod flags {
        pub const O_RDONLY: i32 = 0;
        pub const O_WRONLY: i32 = 1;
        pub const O_RDWR: i32 = 2;
        pub const O_CREAT: i32 = 0x40;
        pub const O_EXCL: i32 = 0x80;
        pub const O_NOCTTY: i32 = 0x100;
        pub const O_TRUNC: i32 = 0x200;
        pub const O_APPEND: i32 = 0x400;
        pub const O_NONBLOCK: i32 = 0x800;
        pub const O_LARGEFILE: i32 = 0x8000;
        pub const O_DIRECTORY: i32 = 0x10000;
    }
}
