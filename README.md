# cls_ingress

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
ip route add local 1.1.1.1/32 dev lo src 192.168.10.23 # this will lookup the 
```

192.168.10.23 is the address of wan interface(e.g. wlo1), then run `curl --interface wlo1 1.1.1.1`.

the connection will be intercepted by the tproxy socket
