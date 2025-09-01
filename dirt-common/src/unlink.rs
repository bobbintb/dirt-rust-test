#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkEvent {
    pub file_path: [u8; 30],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnlinkEvent {}
