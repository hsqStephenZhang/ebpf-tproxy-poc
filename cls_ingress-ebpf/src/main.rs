#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::*,
    helpers::{bpf_redirect, bpf_sk_assign, bpf_sk_release, bpf_skc_lookup_tcp},
    macros::classifier,
    programs::TcContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TC_ACT_OK);
    }

    Ok((start + offset) as *const T)
}

fn assign(ctx: &TcContext, sk: *mut bpf_sock) {
    unsafe {
        bpf_sk_assign(ctx.as_ptr() as *mut _, sk as *mut _, 0);
        bpf_sk_release(sk as *mut _);
    }
}

// assign the sk to tproxy socket, so inet_lookup will steal the sock and hand it to
// the tproxy progress
#[classifier]
pub fn cls_ingress(ctx: TcContext) -> i32 {
    match try_cls_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// redirect the egress traffic to `lo`
#[classifier]
pub fn cls_egress(ctx: TcContext) -> i32 {
    match try_cls_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_cls_ingress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_OK),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let proto = unsafe { (*ipv4hdr).proto };
    let (sport, dport) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(TC_ACT_OK),
    };

    // custom this condition with your own logic
    if dport == 80 && proto == IpProto::Tcp {
        info!(&ctx, "[ingress] {:i}:{} => {:i}:{}", src, sport, dst, dport);

        let ipv4 = bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
            saddr: src.to_be(),
            daddr: dst.to_be(),
            sport: sport.to_be(),
            dport: dport.to_be(),
        };
        let inner = bpf_sock_tuple__bindgen_ty_1 { ipv4: ipv4 };
        let mut tuple = bpf_sock_tuple {
            __bindgen_anon_1: inner,
        };
        let sk = unsafe {
            bpf_skc_lookup_tcp(
                ctx.as_ptr() as *mut _,
                &mut tuple as *mut _,
                core::mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as _,
                BPF_F_CURRENT_NETNS as _,
                0,
            )
        };

        unsafe {
            if !sk.is_null() {
                let sk = &mut *sk;
                /* Reuse existing connection if it exists */
                if sk.state != BPF_TCP_LISTEN {
                    info!(&ctx, "found reusable sk for tproxy");
                    assign(&ctx, sk);
                    return Ok(TC_ACT_OK);
                } else {
                    bpf_sk_release(sk as *mut bpf_sock as *mut _);
                }
            } else {
                info!(&ctx, "no reusable sk for tproxy");
            }
        }

        let proxy_dst = 0x7f000001_u32;
        let proxy_port = 9999_u16;
        let server = bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
            saddr: src.to_be(),
            daddr: proxy_dst.to_be(),
            sport: sport.to_be(),
            dport: proxy_port.to_be(),
        };
        let inner = bpf_sock_tuple__bindgen_ty_1 { ipv4: server };
        let mut tuple = bpf_sock_tuple {
            __bindgen_anon_1: inner,
        };
        let sk = unsafe {
            bpf_skc_lookup_tcp(
                ctx.as_ptr() as *mut _,
                &mut tuple as *mut _,
                core::mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as _,
                BPF_F_CURRENT_NETNS as _,
                0,
            )
        };
        if sk.is_null() {
            error!(&ctx, "failed to find sk for tproxy");
            return Err(TC_ACT_SHOT);
        }
        info!(&ctx, "found sk for tproxy");
        unsafe {
            let sk = &mut *sk;
            if sk.state != BPF_TCP_LISTEN {
                bpf_sk_release(sk as *mut bpf_sock as *mut _);
                return Err(TC_ACT_SHOT);
            } else {
                assign(&ctx, sk);
            }
        }
    }

    Ok(TC_ACT_OK)
}

fn try_cls_egress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_OK),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let proto = unsafe { (*ipv4hdr).proto };
    let (sport, dport) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(TC_ACT_OK),
    };

    if dport == 80 && proto == IpProto::Tcp {
        let skb = &unsafe { *ctx.skb.skb };
        let mark = skb.mark;
        info!(&ctx, "[egress] {:i}:{} => {:i}:{}, mark: {}", src, sport, dst, dport, mark);

        // redirect to lo
        unsafe {
            return Ok(bpf_redirect(1, 0) as _);
        }
    }

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
