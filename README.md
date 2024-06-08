# ebpf_tproxy

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run


```bash
RUST_LOG=info cargo xtask run
```


to make the wan redirect logic work, you have to

```bash
sysctl -w net.ipv4.conf.lo.accept_local=1 # so the fib validate src will success
ip rule add fwmark 0x1/0x1 lookup 100
ip route add local default dev lo table 100
```

192.168.10.23 is the address of wan interface(e.g. wlo1), then run `curl --interface wlo1 1.1.1.1`.

the connection will be intercepted by the tproxy socket

and don't forget to run the cleanup command, or the attached bpf program will not be detached: 
```bash
tc qdisc del dev lo clsact && tc qdisc del dev wlo1 clsact # replace wlo1 with your interface in the args 
```


## How it works

### common

what we mainly do is to redirect the egress traffic of an interface, let's say wlo1, to an ingress of interface, let's say lo. So the traffic will go through the kernel's routing system `again`. And we can perform 2 hacks on this path:
1. mark the packet, so it will hit our defined `ip rule`, and pass it to the local process
2. assign the `skb->sk` with the tproxy's listnening sk.

with these two hacks, the kernel will know that the skb is handled by the tproxy listening socket, the very special one.

the first hacks can be done via setting the `mark` field of skb in the TC's bpf program, and the second can also be done there, with the magic of `bpf_sk_assign`.

The returning traffic from device lo should also be hacked, but it's quite the reversed path: the egress traffic of lo should be redirected to the ingress of wlo1.

### fastpath

So far, so good. But we can actually perform another optimization here: boost the sendmsg/recvmsg path.

The idea is that, the traffic between the proxied program and our tproxy program doesn't have to go through the entire network stack, it's more like a `IPC` mechanism, but in the form of socket's API. Luckily, kernel's developers provide a fastpath in such situations: `BPF_PROG_TYPE_SK_MSG` type of bpf programs.

the `SK_MSG` bpf program works with `BPF_MAP_TYPE_SOCKHASH`: when we insert a sk into the sock_map, `sock_map_link` is invoked in kernel, and the the tcp/udp's callbacks in its ops(`inet_stream_ops`) will be replaced by `tcp_bpf_update_proto`, e.g. the `tcp_sendmsg` will be replaced by `tcp_bpf_sendmsg`, the `tcp_recvmsg` will be replaced by `tcp_bpf_recvmsg` etc.

the question is, how do we know which sk to insert into the map? to do that, we can utilize another type of bpf programs: `BPF_PROG_TYPE_SOCK_OPS`. 

This type of bpf programs will be invoked whenever a socket's state is changed, for example, during the establishment of tcp connection, the active establishment(syn packet) and passive establishment(syn&ack packet) of the connection will trigger their events accordingly, and kernel will pass the event's op code and skb to the `SOCK_OPS` bpf program, in the program, what we do is to simply match the skb, record it into the `BPF_MAP_TYPE_SOCKHASH` that is shared between the `sk_ops` and `sk_msg` programs(so the proto will be updated, and the fastpath will be enabled)

back to the `SK_MSG` programs, we just need to reverse the 5-tuple, find the other side of the connection, and pass the skb to it via `bpf_msg_redirect_hash` helper function. the kernel will do the rest of the job in `tcp_bpf_sendmsg` and `tcp_bpf_recvmsg`.

```txt
Tips:
    skb: the kernel structure that represents the data that is transfered.
    sk: the kernel structure that links skb and process(task_struct).
    route: for egress, the routing is to find the outbound interface, for ingress, the routing is to forward the traffic, or to pass the skb to the sk that it belongs to.
```

## TODOS

you must notice that, we hardcode the traffic to be intercepted: 
1. from one specific interface.
2. redirect to lo interface
3. the destination must be `1.1.1.1`

let's call the step to choose the redirected interface and the matching traffic `reroute`, since it's different with linux routing system, but is very similar.

we actually can do better, there are a few improvements that can be done easily: 

1. iterate a list of rules similar to iptables, each has a type like `match the dst`, `match the sport` etc.
2. pre-compile the rules into a much compat structure and perform a rule search of O(1) time complexity. but we must notice that, the constant of O(1) may be very large, according to the num of rules, unless u are quite sure about its advantage, don't use it. the details algorithm can be found [here](https://mbertrone.github.io/documents/21-Securing_Linux_with_a_Faster_and_Scalable_Iptables.pdf)
3. attach each rule with the action of either DROP the packet, or redirect it to one interface.
