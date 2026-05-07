# BPF headers

No `vmlinux.h` required. `bpf/filter.c` uses stock Linux uapi headers
(`linux/if_ether.h`, `linux/ip.h`, `linux/udp.h`, `linux/bpf.h`,
`linux/pkt_cls.h`) plus libbpf's `bpf/bpf_helpers.h` and `bpf/bpf_endian.h`.

These ship with:
- Debian/Ubuntu: `linux-libc-dev` + `libbpf-dev`
- Alpine: `linux-headers` + `libbpf-dev`

Any clang supporting `-target bpf` works. The Dockerfile in the repo root
installs these from Debian bookworm.
