#![no_std]
#![no_main]

use core::mem::{self, offset_of};

use aya_ebpf::{
    bindings::*,
    helpers::{
        bpf_fib_lookup as bpf_fib_lookup_fn, bpf_redirect, bpf_sk_assign, bpf_sk_release,
        bpf_skb_change_type, bpf_skc_lookup_tcp,
    },
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

fn get_tcp_v4_tuple(ctx: &TcContext) -> Option<bpf_sock_tuple> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).ok()?;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return None;
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).ok()?;
    let proto = unsafe { (*ipv4hdr).proto };
    let (sport, dport) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok()?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        _ => return None,
    };

    let src = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let ipv4 = bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
        saddr: src.to_be(),
        daddr: dst.to_be(),
        sport: sport.to_be(),
        dport: dport.to_be(),
    };
    let inner = bpf_sock_tuple__bindgen_ty_1 { ipv4: ipv4 };
    let tuple = bpf_sock_tuple {
        __bindgen_anon_1: inner,
    };

    Some(tuple)
}

fn rewrite_ip(ctx: &TcContext, new_ip: u32, is_dst: bool) -> Result<i32, i32> {
    Ok(0)
}

fn assign(ctx: &TcContext, sk: *mut bpf_sock) {
    unsafe {
        bpf_sk_assign(ctx.as_ptr() as *mut _, sk as *mut _, 0);
        bpf_sk_release(sk as *mut _);
    }
}

fn get_common(ctx: &TcContext) -> (u32, u32) {
    let ctx = &unsafe { *(ctx.as_ptr() as *const __sk_buff) };
    (ctx.mark, ctx.pkt_type)
}

// assign the sk to tproxy socket, so inet_lookup will steal the sock and hand it to
// the tproxy progress
#[classifier]
pub fn lan_ingress(ctx: TcContext) -> i32 {
    match try_lan_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn lan_egress(ctx: TcContext) -> i32 {
    let tuple = match get_tcp_v4_tuple(&ctx) {
        Some(tuple) => tuple,
        None => return TC_ACT_OK,
    };

    unsafe {
        let src = u32::from_be(tuple.__bindgen_anon_1.ipv4.saddr);
        let dst = u32::from_be(tuple.__bindgen_anon_1.ipv4.daddr);
        let sport = u16::from_be(tuple.__bindgen_anon_1.ipv4.sport);
        let dport = u16::from_be(tuple.__bindgen_anon_1.ipv4.dport);

        if sport == 80 || dport == 80 {
            info!(
                &ctx,
                "[lan egress] {:i}:{} => {:i}:{}", src, sport, dst, dport
            );

            if sport == 80 {
                // redirect to `wlo1`, ingress
                return bpf_redirect(3, 1) as _;
            }
        }
    }

    TC_ACT_OK
}

fn try_lan_ingress(mut ctx: TcContext) -> Result<i32, i32> {
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
    if (dport == 80 || sport == 80) && proto == IpProto::Tcp {
        ctx.set_mark(1);
        // set pkt type to PACKET_HOST, so it won't get dropped
        unsafe {
            bpf_skb_change_type(ctx.as_ptr() as *mut _, 0);
        }

        let (mark, pkt_type) = get_common(&ctx);
        info!(
            &ctx,
            "[lan ingress] {:i}:{} => {:i}:{}, mark: {}, pkt_type: {}",
            src,
            sport,
            dst,
            dport,
            mark,
            pkt_type
        );

        // {
        //     let smac = unsafe { (*ethhdr).src_addr };
        //     let dmac = unsafe { (*ethhdr).dst_addr };

        //     // info!(&ctx, "smac: {:mac}, dmac: {:mac}", smac, dmac);
        //     let lo_mac = [0; 6];
        //     if ctx.store(offset_of!(EthHdr, dst_addr), &lo_mac, 0).is_err() {
        //         error!(&ctx, "failed to set dst mac");
        //         return Err(TC_ACT_SHOT);
        //     }
        //     if ctx.store(offset_of!(EthHdr, src_addr), &lo_mac, 0).is_err() {
        //         error!(&ctx, "failed to set dst mac");
        //         return Err(TC_ACT_SHOT);
        //     }
        // }

        // {
        // {
        //     const IP_DST_OFF: usize = mem::size_of::<EthHdr>() + offset_of!(Ipv4Hdr, dst_addr);
        //     const IP_SRC_OFF: usize = mem::size_of::<EthHdr>() + offset_of!(Ipv4Hdr, src_addr);
        //     const IP_CSUM_OFF: usize = mem::size_of::<EthHdr>() + offset_of!(Ipv4Hdr, check);
        //     const TCP_CSUM_OFF: usize =
        //         mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>() + offset_of!(TcpHdr, check);
        //     const IS_PSEUDO: u64 = 0x10;
        //     const LO: u32 = u32::from_be(0x7f000001_u32);

        //     let dst1: u32 = match ctx.load(IP_DST_OFF) {
        //         Ok(dst) => dst,
        //         Err(_) => return Err(TC_ACT_SHOT),
        //     };

        //     if ctx.store(IP_DST_OFF, &LO, 0).is_err() {
        //         error!(&ctx, "failed to set dst ip");
        //         return Err(TC_ACT_SHOT);
        //     }

        //     // flags & 0xf is the size of replaced data, it can be 0/2/4
        //     if ctx
        //         .l4_csum_replace(
        //             TCP_CSUM_OFF,
        //             dst1 as _,
        //             LO as _,
        //             mem::size_of::<u32>() as u64,
        //         )
        //         .is_err()
        //     {
        //         error!(&ctx, "failed to replace l4 csum");
        //         return Err(TC_ACT_SHOT);
        //     }
        //     if ctx
        //         .l3_csum_replace(
        //             IP_CSUM_OFF,
        //             dst1 as _,
        //             LO as _,
        //             mem::size_of::<u32>() as u64,
        //         )
        //         .is_err()
        //     {
        //         error!(&ctx, "failed to replace l3 csum");
        //         return Err(TC_ACT_SHOT);
        //     }
        //     // return Ok(TC_ACT_OK);
        // }

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
                    info!(&ctx, "[lan ingress] found reusable sk for tproxy");
                    assign(&ctx, sk);
                    return Ok(TC_ACT_OK);
                } else {
                    bpf_sk_release(sk as *mut bpf_sock as *mut _);
                }
            } else {
                info!(&ctx, "[lan ingress] no reusable sk for tproxy");
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
            error!(&ctx, "[lan ingress] failed to find sk for tproxy");
            return Err(TC_ACT_SHOT);
        }
        info!(&ctx, "[lan ingress] found sk for tproxy");
        unsafe {
            let sk = &mut *sk;
            if sk.state != BPF_TCP_LISTEN {
                bpf_sk_release(sk as *mut bpf_sock as *mut _);
                return Err(TC_ACT_SHOT);
            } else {
                assign(&ctx, sk);
            }
        }
        // let pesudo_dst = u32::from_be(0x01010101);
        // if dst == pesudo_dst {
        //     info!(&ctx, "[lan ingress] dst is pesudo dst");
        //     let params = [0u8; mem::size_of::<bpf_fib_lookup>()];
        //     let params = unsafe { core::mem::transmute::<_, *mut bpf_fib_lookup>(&params) };
        //     let params = &mut unsafe { *params };
        //     params.l4_protocol = 6;
        //     params.family = 2;
        //     params.sport = sport.to_be();
        //     params.dport = dport.to_be();
        //     params.__bindgen_anon_3.ipv4_src = src.to_be();
        //     params.__bindgen_anon_4.ipv4_dst = dst.to_be();
        //     unsafe {
        //         let res = bpf_fib_lookup_fn(
        //             ctx.as_ptr() as *mut _,
        //             params as *mut _,
        //             mem::size_of::<bpf_fib_lookup>() as _,
        //             0,
        //         );
        //     }
        // }
    }

    Ok(TC_ACT_OK)
}

#[classifier]
pub fn wan_ingress(ctx: TcContext) -> i32 {
    match try_wan_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn try_wan_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    let tuple = match get_tcp_v4_tuple(&ctx) {
        Some(tuple) => tuple,
        None => return Ok(TC_ACT_OK),
    };

    unsafe {
        let src = u32::from_be(tuple.__bindgen_anon_1.ipv4.saddr);
        let dst = u32::from_be(tuple.__bindgen_anon_1.ipv4.daddr);
        let sport = u16::from_be(tuple.__bindgen_anon_1.ipv4.sport);
        let dport = u16::from_be(tuple.__bindgen_anon_1.ipv4.dport);

        if sport == 80 || dport == 80 {
            info!(
                &ctx,
                "[wan ingress] {:i}:{} => {:i}:{}", src, sport, dst, dport
            );

            ctx.set_mark(1);

            let (mark, pkt_type) = get_common(&ctx);
            info!(
                &ctx,
                "[wan ingress] {:i}:{} => {:i}:{}, mark: {}, pkt_type: {}",
                src,
                sport,
                dst,
                dport,
                mark,
                pkt_type
            );

            unsafe {
                bpf_skb_change_type(ctx.as_ptr() as *mut _, 0);
            }

            // {
            //     const IP_DST_OFF: usize = mem::size_of::<EthHdr>() + offset_of!(Ipv4Hdr, dst_addr);
            //     const IP_SRC_OFF: usize = mem::size_of::<EthHdr>() + offset_of!(Ipv4Hdr, src_addr);
            //     const IP_CSUM_OFF: usize = mem::size_of::<EthHdr>() + offset_of!(Ipv4Hdr, check);
            //     const TCP_CSUM_OFF: usize = mem::size_of::<EthHdr>()
            //         + mem::size_of::<Ipv4Hdr>()
            //         + offset_of!(TcpHdr, check);
            //     const IS_PSEUDO: u64 = 0x10;
            //     const LO: u32 = u32::from_be(0x7f000001_u32);

            //     let dst1: u32 = match ctx.load(IP_DST_OFF) {
            //         Ok(dst) => dst,
            //         Err(_) => return Err(TC_ACT_SHOT),
            //     };

            //     if ctx.store(IP_DST_OFF, &LO, 0).is_err() {
            //         error!(&ctx, "failed to set dst ip");
            //         return Err(TC_ACT_SHOT);
            //     }

            //     // flags & 0xf is the size of replaced data, it can be 0/2/4
            //     if ctx
            //         .l4_csum_replace(
            //             TCP_CSUM_OFF,
            //             dst1 as _,
            //             LO as _,
            //             mem::size_of::<u32>() as u64,
            //         )
            //         .is_err()
            //     {
            //         error!(&ctx, "failed to replace l4 csum");
            //         return Err(TC_ACT_SHOT);
            //     }
            //     if ctx
            //         .l3_csum_replace(
            //             IP_CSUM_OFF,
            //             dst1 as _,
            //             LO as _,
            //             mem::size_of::<u32>() as u64,
            //         )
            //         .is_err()
            //     {
            //         error!(&ctx, "failed to replace l3 csum");
            //         return Err(TC_ACT_SHOT);
            //     }
            //     return Ok(TC_ACT_OK);
            // }

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
                        info!(&ctx, "[wan ingress] found reusable sk for tproxy");
                        assign(&ctx, sk);
                        return Ok(TC_ACT_OK);
                    } else {
                        bpf_sk_release(sk as *mut bpf_sock as *mut _);
                    }
                } else {
                    info!(&ctx, "[wan ingress] no reusable sk for tproxy");
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
                error!(&ctx, "[wan ingress] failed to find sk for tproxy");
                return Err(TC_ACT_SHOT);
            }
            info!(&ctx, "[wan ingress] found sk for tproxy");
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
    }

    Ok(TC_ACT_OK)
}

// redirect the egress traffic to `lo`
#[classifier]
pub fn wan_egress(ctx: TcContext) -> i32 {
    match try_wan_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_wan_egress(mut ctx: TcContext) -> Result<i32, i32> {
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

    if proto == IpProto::Tcp {
        if (dport == 80 || sport == 80) {
            info!(
                &ctx,
                "[wan egress] {:i}:{} => {:i}:{}", src, sport, dst, dport
            );
        }

        // redirect to `lo`
        if dport == 80 {
            unsafe {
                // set the mark to 1, so we can use it to route the packet
                // ip rule add fwmark 1 lookup 100
                // ip route add local default dev lo table 100
                ctx.set_mark(1);
                // change skb type here won't work
                // bpf_skb_change_type(ctx.as_ptr() as *mut _, 0);
                // let (mark, pkt_type) = get_common(&ctx);
                // info!(&ctx, "[wan egress] mark: {}, pkt_type: {}", mark, pkt_type);
                return Ok(bpf_redirect(1, 1) as _);
            }
        } else if sport == 80 {
            unsafe{
                let (mark, pkt_type) = get_common(&ctx);
                info!(
                    &ctx,
                    "[wan egress] {:i}:{} => {:i}:{}, mark: {}, pkt_type: {}",
                    src,
                    sport,
                    dst,
                    dport,
                    mark,
                    pkt_type
                );
                // bpf_skb_change_type(ctx.as_ptr() as *mut _, 0);
            }
        }
    }

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
