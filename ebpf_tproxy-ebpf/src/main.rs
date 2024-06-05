#![no_std]
#![no_main]

use core::mem::{self};

use aya_ebpf::{
    bindings::*,
    helpers::{
        bpf_redirect, bpf_sk_assign, bpf_sk_release, bpf_skb_change_type, bpf_skc_lookup_tcp,
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
};

mod utils {
    use super::*;

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

    pub(crate) fn get_tcp_v4_tuple(ctx: &TcContext) -> Option<bpf_sock_tuple> {
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

    // SAFETY: the tuple is a ipv4 one
    pub(crate) unsafe fn unpack_bpf_sock_tuple_v4(tuple: bpf_sock_tuple) -> (u32, u32, u16, u16) {
        let src = u32::from_be(tuple.__bindgen_anon_1.ipv4.saddr);
        let dst = u32::from_be(tuple.__bindgen_anon_1.ipv4.daddr);
        let sport = u16::from_be(tuple.__bindgen_anon_1.ipv4.sport);
        let dport = u16::from_be(tuple.__bindgen_anon_1.ipv4.dport);
        (src, dst, sport, dport)
    }

    // SAFETU: the sk is valid
    pub(crate) unsafe fn assign(ctx: &TcContext, sk: *mut bpf_sock) {
        unsafe {
            bpf_sk_assign(ctx.as_ptr() as *mut _, sk as *mut _, 0);
            bpf_sk_release(sk as *mut _);
        }
    }

    // get details about the skb, which are important for routing
    pub(crate) fn get_skb_details(ctx: &TcContext) -> (u32, u32) {
        let ctx = &unsafe { *(ctx.as_ptr() as *const __sk_buff) };
        (ctx.mark, ctx.pkt_type)
    }
}

use utils::*;

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

    let (src, dst, sport, dport) = unsafe { unpack_bpf_sock_tuple_v4(tuple) };

    if sport == 80 || dport == 80 {
        info!(
            &ctx,
            "[lan egress] {:i}:{} => {:i}:{}", src, sport, dst, dport
        );

        if sport == 80 {
            // redirect to `wlo1`, ingress
            return unsafe { bpf_redirect(3, 1) as _ };
        }
    }

    TC_ACT_OK
}

#[classifier]
pub fn wan_ingress(ctx: TcContext) -> i32 {
    match try_wan_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// redirect the egress traffic to `lo`
#[classifier]
pub fn wan_egress(ctx: TcContext) -> i32 {
    match try_wan_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_lan_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    let tuple = match get_tcp_v4_tuple(&ctx) {
        Some(tuple) => tuple,
        None => return Ok(TC_ACT_OK),
    };
    let (src, dst, sport, dport) = unsafe { unpack_bpf_sock_tuple_v4(tuple) };

    // custom this condition with your own logic
    if dport == 80 || sport == 80 {
        ctx.set_mark(1);
        // set pkt type to PACKET_HOST, so it won't get dropped
        unsafe {
            bpf_skb_change_type(ctx.as_ptr() as *mut _, 0);
        }

        let (mark, pkt_type) = get_skb_details(&ctx);
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
    }

    Ok(TC_ACT_OK)
}

pub fn try_wan_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    let tuple = match get_tcp_v4_tuple(&ctx) {
        Some(tuple) => tuple,
        None => return Ok(TC_ACT_OK),
    };

    let (src, dst, sport, dport) = unsafe { unpack_bpf_sock_tuple_v4(tuple) };

    if sport == 80 || dport == 80 {
        info!(
            &ctx,
            "[wan ingress] {:i}:{} => {:i}:{}", src, sport, dst, dport
        );

        ctx.set_mark(1);

        let (mark, pkt_type) = get_skb_details(&ctx);
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

    Ok(TC_ACT_OK)
}

fn try_wan_egress(mut ctx: TcContext) -> Result<i32, i32> {
    let tuple = match get_tcp_v4_tuple(&ctx) {
        Some(tuple) => tuple,
        None => return Ok(TC_ACT_OK),
    };
    let (src, dst, sport, dport) = unsafe { unpack_bpf_sock_tuple_v4(tuple) };
    let (mark, pkt_type) = get_skb_details(&ctx);

    if dport == 80 || sport == 80 {
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
    }

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
