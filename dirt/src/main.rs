use anyhow::Context as _;
use aya::{
    maps::PerfEventArray,
    programs::FExit,
    util::online_cpus,
    Btf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use dirt_common::UnlinkEvent;
use log::{debug, warn};
use tokio::{signal, task};

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

    // Load the eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Load BTF information
    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;

    // Load and attach the program
    let program: &mut FExit = ebpf.program_mut("dirt").unwrap().try_into()?;
    program.load("vfs_unlink", &btf)?;
    program.attach()?;

    // Get the perf event array for receiving events
    let mut perf_array = PerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    println!("eBPF program loaded and attached. Monitoring vfs_unlink calls...");
    println!("Press Ctrl+C to exit.\n");

    // Create event handlers for each CPU
    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?;
    let num_cpus = cpus.len();
    
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        
        task::spawn(async move {
            let mut buffers: Vec<BytesMut> = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(1024))
                .collect();

            loop {
                let events = match buf.read_events(&mut buffers) {
                    Ok(events) => events,
                    Err(e) => {
                        eprintln!("Error reading events: {}", e);
                        continue;
                    }
                };

                // events.read is the number of events read
                // The actual event data is in the buffers that had events
                for i in 0..events.read {
                    if let Some(buf) = buffers.get(i) {
                        if buf.len() >= std::mem::size_of::<UnlinkEvent>() {
                            let event = unsafe { 
                                std::ptr::read_unaligned(buf.as_ptr() as *const UnlinkEvent) 
                            };
                            
                            println!("=== vfs_unlink arguments ===");
                            println!("  PID: {}", event.pid);
                            println!("  UID: {}", event.uid);
                            println!("  GID: {}", event.gid);
                            println!("  mnt_userns pointer: 0x{:x}", event.mnt_userns_ptr);
                            println!("  dir inode pointer: 0x{:x}", event.dir_inode_ptr);
                            println!("  dentry pointer: 0x{:x}", event.dentry_ptr);
                            println!();
                        }
                    }
                }
            }
        });
    }

    // Wait for Ctrl-C
    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
