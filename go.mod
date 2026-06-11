module github.com/HuJK/gvisor-vswitch

go 1.26.3

require (
	github.com/cilium/ebpf v0.16.0
	github.com/cloudflare/slirpnetstack v0.0.0-00010101000000-000000000000
	github.com/insomniacslk/dhcp v0.0.0-20260603135910-a415979eb11e
	github.com/mdlayher/vsock v1.3.0
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.45.0
	gvisor.dev/gvisor v0.0.0-20260609190117-5b5430a559c4
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/higebu/netfd v0.0.0-20171006072739-15573c3bed1f // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/moby/sys/capability v0.4.0 // indirect
	github.com/mohae/deepcopy v0.0.0-20170308212314-bb9b5e7adda9 // indirect
	github.com/opencontainers/runc v1.2.3 // indirect
	github.com/opencontainers/runtime-spec v1.2.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/netaddr.v1 v1.5.1 // indirect
)

replace github.com/cloudflare/slirpnetstack => ./slirpnetstack
