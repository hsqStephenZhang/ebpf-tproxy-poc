use std::os::fd::FromRawFd;
use std::str::FromStr;

use anyhow::Context;
use aya::programs::{tc, SchedClassifier};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use nix::sys::socket::sockopt::ReusePort;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;

use nix::sys::socket::{
    bind, listen, setsockopt, socket,
    sockopt::{IpTransparent, ReuseAddr},
    AddressFamily, SockFlag, SockType, SockaddrIn,
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
    #[clap(short, long, default_value = "wlo1")]
    wan_iface: String,
    #[clap(short, long, default_value = "127.0.0.1")]
    addr: String,
    #[clap(short, long, default_value = "9999")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf_tproxy"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf_tproxy"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.

    // ingress & egress for lan
    let _ = tc::qdisc_add_clsact(&opt.iface);
    {
        let program: &mut SchedClassifier = bpf.program_mut("lan_ingress").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.iface, tc::TcAttachType::Ingress)?;
    }

    {
        let program: &mut SchedClassifier = bpf.program_mut("lan_egress").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.iface, tc::TcAttachType::Egress)?;
    }

    // ingress & egress for wan
    let _ = tc::qdisc_add_clsact(&opt.wan_iface);
    {
        let program: &mut SchedClassifier = bpf.program_mut("wan_ingress").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.wan_iface, tc::TcAttachType::Ingress)?;
    }

    {
        let program: &mut SchedClassifier = bpf.program_mut("wan_egress").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.wan_iface, tc::TcAttachType::Egress)?;
    }

    tproxy_listen(&opt.addr, opt.port).await?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    info!("Exiting...");

    Ok(())
}

fn handle_client(client: TcpStream) -> anyhow::Result<()> {
    let local_addr = client.local_addr().context("Failed to get local addr")?;
    let peer_addr = client.peer_addr().context("Failed to get peer addr")?;

    println!("New connection:");
    println!("\tlocal: {}", local_addr);
    println!("\tpeer: {}", peer_addr);
    println!();

    Ok(())
}

async fn tproxy_listen(addr: &str, port: u16) -> anyhow::Result<()> {
    // Create listener socket
    let fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .context("Failed to create listener socket")?;

    // Set some sockopts
    setsockopt(fd, ReusePort, &true).context("Failed to set SO_REUSEADDR")?;
    setsockopt(fd, ReuseAddr, &true).context("Failed to set SO_REUSEADDR")?;
    setsockopt(fd, IpTransparent, &true).context("Failed to set IP_TRANSPARENT")?;

    // Bind to addr
    let addr = format!("{}:{}", addr, port);
    let addr = SockaddrIn::from_str(&addr).context("Failed to parse socketaddr")?;
    bind(fd, &addr).context("Failed to bind listener")?;

    // Start listening
    listen(fd, 128).context("Failed to listen")?;
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    let _ = listener.set_nonblocking(true);
    let listener =
        TcpListener::from_std(listener).context("fail to convert listener from std to tokio")?;

    // let mut sock_map = SockMap::try_from(bpf.map_mut("REDIR").unwrap())?;
    // sock_map.set(0, &listener, 0)?;

    while let Ok((stream, _addr)) = listener.accept().await {
        let _ = handle_client(stream).context("Failed to handle client");
    }

    Ok(())
}
