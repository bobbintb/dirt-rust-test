#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub mnt_userns_ptr: u64,
    pub dir_inode_ptr: u64,
    pub dentry_ptr: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnlinkEvent {}
