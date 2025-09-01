#![no_std]
#![no_main]

use aya_ebpf::{macros::fexit, programs::FExitContext};
use aya_log_ebpf::info;

#[fexit(function = "vfs_unlink")]
pub fn dirt(ctx: FExitContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function vfs_unlink called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
