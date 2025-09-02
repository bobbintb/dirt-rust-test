use std::os::unix::fs::MetadataExt;

use anyhow::Context as _;
use aya::{
    maps::{perf::AsyncPerfEventArray, Array},
    programs::FExit,
    util::online_cpus,
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use dirt_common::{Settings, UnlinkEvent};
use log::{debug, warn};
use serde::Serialize;
use tokio::{signal, task};

#[derive(Serialize)]
struct UnlinkEventJson {
    pid: u32,
    uid: u32,
    gid: u32,
    mnt_userns_ptr: u64,
    dir_inode_ptr: u64,
    dentry_ptr: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;

    // Get the device ID of /mnt/user
    let metadata = std::fs::metadata("/mnt/user")?;
    let dev_id = metadata.dev();

    // Get the SETTINGS map
    let mut settings: Array<_, Settings> =
        Array::try_from(ebpf.take_map("SETTINGS").unwrap())?;

    // Write the device ID to the map
    let settings_data = Settings { mnt_dev: dev_id };
    settings.set(0, settings_data, 0)?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    let program: &mut FExit = ebpf.program_mut("dirt").unwrap().try_into()?;
    program.load("vfs_unlink", &btf)?;
    program.attach()?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?;

    println!("eBPF program loaded. Press Ctrl+C to exit.");

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers: Vec<BytesMut> = (0..10).map(|_| BytesMut::with_capacity(1024)).collect();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    if let Some(buf) = buffers.get(i) {
                        if buf.len() >= std::mem::size_of::<UnlinkEvent>() {
                            let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const UnlinkEvent) };
                            let json = UnlinkEventJson {
                                pid: event.pid,
                                uid: event.uid,
                                gid: event.gid,
                                mnt_userns_ptr: event.mnt_userns_ptr,
                                dir_inode_ptr: event.dir_inode_ptr,
                                dentry_ptr: event.dentry_ptr,
                            };
                            println!("{}", serde_json::to_string(&json).unwrap());
                        }
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
