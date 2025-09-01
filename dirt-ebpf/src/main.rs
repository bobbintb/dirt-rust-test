#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_str_bytes,
    macros::{fentry, map},
    maps::PerfEventArray,
    programs::FEntryContext,
};
use dirt_common::unlink::UnlinkEvent;

#[map]
static mut EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[fentry(function = "vfs_unlink")]
pub fn dirt(ctx: FEntryContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: FEntryContext) -> Result<u32, u32> {
    let dentry = unsafe { ctx.arg::<*const u8>(2) };
    if dentry.is_null() {
        return Err(1);
    }
    let mut file_path_bytes = [0u8; 30];
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(dentry, &mut file_path_bytes) }
        .map_err(|_| 1u32)?;
    let unlink_event = UnlinkEvent {
        file_path: file_path_bytes,
    };
    unsafe {
        EVENTS.output(&ctx, &unlink_event, 0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
