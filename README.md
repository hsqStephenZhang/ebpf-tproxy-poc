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
```

192.168.10.23 is the address of wan interface(e.g. wlo1), then run `curl --interface wlo1 1.1.1.1`.

the connection will be intercepted by the tproxy socket

and don't forget to run the cleanup command, or the attached bpf program will not be detached: 
```bash
tc qdisc del dev lo clsact && tc qdisc del dev wlo1 clsact # replace wlo1 with your interface in the args 
```