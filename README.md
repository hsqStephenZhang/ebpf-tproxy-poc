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

### common redirect

TC(traffic control) provide both ingress and egress hooks, and the skb can be redirected to any other interface with both directions.

So we just redirect the egress traffic on wlo1 to the ingress path of loopback device, so it will traverse the network stack again. Since we have a tproxy socket listening on a specific port, we can also assign this listening socket to the redirected skb, thus when the real `inet_lookup` is performed, kernel will use the already set socket instead of looking up the listening sockets and established sockets(this would endup failure). this step is called `steal the sock` in kernel's source code.

### redirection fastpath

when a socket is put into the map of `BPF_MAP_TYPE_SOCKHASH`, it will rebuild the tcp protocol's callbacks, e.g. the `tcp_sendmsg` will be turned into `tcp_bpf_sendmsg` and `tcp_recvmsg` will be turned into `tcp_bpf_recvmsg`, and the fast redirection work will be done in `tcp_bpf_send_verdict`, after the verdict decision of `REDIRECT` is settled by our bpf programs, `tcp_bpf_sendmsg_redir` will be called to put the skb into a buffer instead of put it down to the network stack and into the ringbuf of network interface