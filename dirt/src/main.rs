use anyhow::Context as _;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::FEntry,
    util::online_cpus,
    Btf,
};
use bytes::Bytes;
use dirt_common::unlink::UnlinkEvent;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    let program: &mut FEntry = ebpf.program_mut("dirt").unwrap().try_into()?;
    program.load("vfs_unlink", &btf)?;
    program.attach()?;
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| Bytes::with_capacity(4096))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const UnlinkEvent;
                    let unlink_event = unsafe { ptr.read_unaligned() };
                    println!(
                        "{}",
                        String::from_utf8_lossy(&unlink_event.file_path[..])
                    );
                }
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
