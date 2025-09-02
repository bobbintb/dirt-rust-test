#![no_std]
#![no_main]

// Include vmlinux types directly since the file exists in the repo
#[path = "vmlinux.rs"]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel},
    macros::{fexit, map},
    maps::{Array, PerfEventArray},
    programs::FExitContext,
};
use aya_log_ebpf::info;
use dirt_common::{Settings, UnlinkEvent};
use vmlinux::{dentry, inode, mnt_idmap, super_block};

#[map]
static EVENTS: PerfEventArray<UnlinkEvent> = PerfEventArray::new(0);

#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

#[fexit(function = "vfs_unlink")]
pub fn dirt(ctx: FExitContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: FExitContext) -> Result<u32, u32> {
    // Read settings
    let settings = if let Some(settings) = SETTINGS.get(0) {
        settings
    } else {
        return Ok(0); // Should not happen
    };

    // Get the function arguments directly
    // vfs_unlink signature: int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    // Note: We skip the 4th argument (delegated_inode) as it's a pointer to pointer which the verifier rejects
    let mnt_idmap: *const mnt_idmap = unsafe { ctx.arg(0) };
    let dir_inode: *const inode = unsafe { ctx.arg(1) };
    let dentry: *const dentry = unsafe { ctx.arg(2) };

    // Get device id from inode
    let i_sb: *const super_block =
        unsafe { bpf_probe_read_kernel(&(*dir_inode).i_sb).map_err(|e| e as u32)? };
    let dev: u32 = unsafe { bpf_probe_read_kernel(&(*i_sb).s_dev).map_err(|e| e as u32)? };

    // Filter by device id
    if settings.mnt_dev != dev as u64 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let event = UnlinkEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: (uid_gid & 0xFFFFFFFF) as u32,
        gid: (uid_gid >> 32) as u32,
        mnt_userns_ptr: mnt_idmap as u64,
        dir_inode_ptr: dir_inode as u64,
        dentry_ptr: dentry as u64,
    };

    info!(&ctx, "vfs_unlink called: pid={}", event.pid);

    // Send event to userspace
    EVENTS.output(&ctx, &event, 0);

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
