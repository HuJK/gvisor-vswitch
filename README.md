# gvisor-vswitch

純 user-space 的虛擬 L2 交換機 + per-VLAN 虛擬網關（NAT / port-forward /
DHCPv4 / DHCPv6 / SLAAC），給 QEMU 等 VM 當網路後端，全部透過 REST API
動態控制。網關基於 [slirpnetstack](https://github.com/KusakabeShi/slirpnetstack)
（gVisor netstack）。

```
VM(qemu) ──tcp/udp/unix/unixgram/vsock/tap──┐
VM(qemu) ──────────────────────────────────┤   gvswitch (userspace)
                                            ├──► L2 switch ── MAC learning / VLAN /
control: REST API (tcp/unix socket) ────────┘        │         isolation / port-security
                                                     └──► per-VLAN gateway (gVisor netstack)
                                                              NAT / port-forward / DHCP / RA
```

## 建置

```sh
./sync-slirpnetstack.sh   # 同步 slirpnetstack 並轉成 library（首次與升級時）
make build                # 或 go build ./cmd/gvswitch
```

### Android（pKVM host）

```sh
make build-android        # CGO_ENABLED=0 GOOS=linux GOARCH=arm64，產出靜態 binary
```

全依賴鏈為純 Go（gvisor/netlink/ebpf/dhcp/vsock 都無 cgo），`CGO_ENABLED=0`
下產出完全靜態的 binary — 不連 glibc 也不連 bionic，Android kernel 即 Linux
kernel，adb push 後可直接執行。Makefile 的 `check-static` 會驗證沒有動態連結。
注意事項：

- **不要用預設 CGO**：`CGO_ENABLED=1`（Go 預設）時 stdlib `net`/`os/user`
  會連 libc 變成動態 binary；Makefile 已固定 `CGO_ENABLED=0`。
- 執行權限：tap/netlink 需 CAP_NET_ADMIN、af_xdp 另需 bpf()（Android SELinux
  對非特權 domain 通常擋 bpf，建議在 root/system context 跑）；vsock 對
  pKVM/crosvm guest 是天然路徑（AF_VSOCK）。
- crosvm（AVF/pKVM 的 VMM）沒有 QEMU 式 socket netdev：實際接法是 `tap`
  （gvswitch 建 tap 後把裝置交給 crosvm）或 vsock（guest 內 agent 走
  `vsock` transport）。

`sync-slirpnetstack.sh` 會 `git reset --hard && git pull` slirpnetstack/，把
`package main` 改名為 `package slirpnetstack`，再把 `_overlay/` 內的 glue 檔
複製進去（透過編譯驗證 upstream 相容性）。

## 啟動

```sh
./gvswitch -listen /run/gvswitch.sock          # unix socket
./gvswitch -listen 127.0.0.1:8080              # tcp4
./gvswitch -listen [::1]:8080                  # tcp6
./gvswitch -listen ... -config config.json     # 啟動時重放設定
./gvswitch -listen ... -auth-token s3cret      # API 驗證（亦可用 $GVSWITCH_AUTH_TOKEN）
```

## API 驗證

設定 `-auth-token`（或環境變數 `GVSWITCH_AUTH_TOKEN`）後，所有 API 請求
必須帶 `Authorization: Bearer <token>`，否則回 401（constant-time 比較）。
不設定則不驗證 — unix socket 建議直接用檔案權限控管。

```sh
curl -H "Authorization: Bearer s3cret" --unix-socket /run/gvswitch.sock http://x/api/v1/ports
```

## REST API（`/api/v1`）

### Switch ports

```sh
# server mode：listen unix socket 等 QEMU 連入（QEMU 4-byte 長度前綴 framing）
curl --unix-socket /run/gvswitch.sock http://x/api/v1/ports -d '{
  "identifier": "vm1",
  "vlan": 100,
  "mode": "server",
  "transport": "unix",
  "local": "/run/vm1.sock",
  "replacing_mode": "replace"
}'

# client mode：主動連線對方（VM 端 listen）
curl ... /api/v1/ports -d '{
  "identifier": "vm2", "vlan": 100,
  "mode": "client", "transport": "tcp", "remote": "127.0.0.1:7000"
}'

# tap / tapbr（需要 CAP_NET_ADMIN）
curl ... /api/v1/ports -d '{
  "identifier": "uplink",
  "mode": "client", "transport": "tapbr", "tap_name": "gvsw0", "bridge": "br0"
}'

# af_xdp：用 AF_XDP 直接接管實體/虛擬網卡（需要 root；自動開 promisc、
# 掛 XDP redirect 程式，先試 driver-native 失敗則退 generic mode）
curl ... /api/v1/ports -d '{
  "identifier": "nic0",
  "mode": "client", "transport": "af_xdp", "interface": "eth1", "queue_id": 0
}'

# vhost-user：gvswitch 作為 virtio-net device backend，VM 效能最高路徑
# （共享記憶體 virtqueue，資料面零 syscall，eventfd 通知）
curl ... /api/v1/ports -d '{
  "identifier": "vm9", "vlan": 100,
  "mode": "server", "transport": "vhost-user", "local": "/run/vm9-vu.sock"
}'

curl ... GET    /api/v1/ports          # 列表（含 online/peer/connections/stats）
curl ... GET    /api/v1/ports/vm1      # 含 rx/tx frames/bytes/dropped 計數器
curl -X PATCH   /api/v1/ports/vm1 -d '{"vlan": 4095, "port_security": "52:54:00:00:00:01"}'
curl -X PATCH   /api/v1/ports/vm1 -d '{"enabled": false}'   # administrative shutdown
curl -X DELETE  /api/v1/ports/vm1      # 回收（VM 關機）
```

### 轉發表（FDB）管理

```sh
curl ... GET 'http://x/api/v1/fdb?vlan=100&port=vm1&mac=...'   # 查詢（過濾條件皆可選；vlan=0 查 untagged domain）
curl -X DELETE  /api/v1/fdb/100/02:00:00:00:00:01              # 刪除單條動態 entry
curl -X POST    /api/v1/fdb/flush -d '{"port":"vm1"}'          # flush（{} = 全部、可按 port/vlan）→ {"flushed": n}

# 靜態轉發表：不老化、learning 不會覆蓋、flush/port 下線不影響
curl -X PUT     /api/v1/fdb/static -d '{"vlan":100,"mac":"02:00:00:00:00:01","port":"vm1"}'
curl ... GET    /api/v1/fdb/static
curl -X DELETE  /api/v1/fdb/static/100/02:00:00:00:00:01       # vlan 0 = untagged domain

# aging 時間（動態 entry，預設 300 秒）
curl ... GET    /api/v1/fdb/config
curl -X PUT     /api/v1/fdb/config -d '{"aging_seconds":120}'
```

Port 屬性：

| 欄位 | 含義 |
|---|---|
| `vlan` | `0`=只收送 untagged（untagged domain）；`1-4094`=access；`4095`=trunk（tagged 原樣通過，untagged 歸 untagged domain）。未填預設 `4095` |
| `isolated` | isolated port 之間不互通，只能和非 isolated port 通訊 |
| `port_security` | `null`=不驗證；MAC 字串=只允許該 src MAC |
| `identifier` | 唯一字串（`[A-Za-z0-9._-]+`），DHCP static binding 可用它當條件。只是中繼資料：轉發引擎走指針（見下） |
| `auto_remove` | 預設 `true`：transport 不可恢復時（有狀態連線被對方關閉、tap 裝置被刪、af_xdp 網卡消失）自動移除整個 port，等同 DELETE。`false` = 保留 port 等重連（server listener 續聽）。dgram 類無斷線訊號，不觸發 |

Server `replacing_mode`：

- `replace`（預設）：新連線踢掉舊的（stream 關閉舊連線；dgram 更新 peer）
- `occupy`：有連線時拒絕新連線（stream 直接關閉；dgram 不更新 peer）
- `multiplex`：多連線，每條變成獨立 subport `id@ip:port` / `id@cid:port` /
  `id@anonymous-N`（unix 取不到 peer 時，N=最小可用）。僅 stream。

Transport：`tcp` `unix` `vsock`（stream，4-byte BE 長度前綴）；`udp`
`unixgram` `vsock-dgram`（一個 datagram = 一個 frame）；`tap` `tapbr`
`af_xdp`（client mode 專用）；`vhost-user`（client/server 皆可）。vsock
位址格式 `cid:port`（listen 可省略 cid）。注意：mainline virtio-vsock 不
支援 SOCK_DGRAM，`vsock-dgram` 視 kernel transport 而定。

`vhost-user` 細節：純 Go 實作 vhost-user-net backend（device 側），協議
角色固定為 device、socket 方向對應 mode（server=gvswitch listen 等 VMM
連入、client=連 VMM 的 `server=on` socket）。協商 `VIRTIO_F_VERSION_1` +
`MRG_RXBUF` + REPLY_ACK，split ring，guest 記憶體經 SET_MEM_TABLE 的
memfd mmap 直接讀寫 — 每幀單向 1 次複製、零 syscall（eventfd kick）。
replacing_mode 支援 replace/occupy（一 port 一 VM session）。VM 必須用
共享記憶體：`-object memory-backend-memfd,share=on,size=<與 -m 相同> 
-machine memory-backend=mem0`。QEMU 範例：

```sh
qemu-system-x86_64 -m 1024 \
  -object memory-backend-memfd,id=mem0,share=on,size=1024M -machine memory-backend=mem0 \
  -chardev socket,id=c0,path=/run/vm9-vu.sock \
  -netdev vhost-user,id=n0,chardev=c0 -device virtio-net-pci,netdev=n0
```

`af_xdp` 細節：XDP 程式以 cilium/ebpf 在程序內組譯（不需外部 .o），把綁定
queue 的所有 ingress frame redirect 到 AF_XDP socket，其餘 queue XDP_PASS
回 kernel；`queue_id` 預設 0，多 queue 網卡建議先 `ethtool -L <dev>
combined 1`。frame 上限約 3584 bytes（UMEM 4096 - headroom），刪除 port
時自動卸載 XDP 程式並還原 promisc。網卡消失（hotplug 拔除、qemu 關機帶走
tap 等）以 netlink RTM_DELLINK 事件即時偵測（訂閱失敗時退回每 ~2 秒輪詢，
POLLERR 亦作備援觸發）：port 離線、觸發 port-down 事件（連動釋放 DHCP
租約），依 `auto_remove`（預設 true）自動移除。僅支援 linux amd64/arm64。

### Gateways（一個 VLAN 一個，以 vlan id 定址；0 = untagged domain、1-4094 = access vlan）

```sh
curl ... /api/v1/gateways -d '{
  "vlan": 100,
  "ipv4": {"address": "10.0.100.2", "prefix_len": 24},
  "ipv6": {"address": "fd00:100::2", "prefix_len": 64},
  "enable_internet_routing": true
}'
curl ... GET/DELETE /api/v1/gateways/100
```

VM 把預設閘道指向 gateway IP 即可出網（NAT：guest 連線被 netstack 終結，
轉成 host syscall）。`allow`/`deny`（`ip/cidr` 或 `ip/cidr:portmin-portmax`）
與 `enable_host_routing` 控制可達範圍。

#### Port forwards（動態增刪）

```sh
# local：host 上 listen，轉給 guest
curl ... /api/v1/gateways/100/forwards -d '{
  "type": "local", "network": "tcp", "bind": "0.0.0.0:8022", "host": "10.0.100.50:22"}'
# remote：guest 連 gateway 的某 port，轉給 host 側位址
curl ... /api/v1/gateways/100/forwards -d '{
  "type": "remote", "network": "tcp", "bind": "10.0.100.2:25", "host": "127.0.0.1:1025"}'
curl ... GET /api/v1/gateways/100/forwards
curl -X DELETE .../forwards/fwd-1
```

#### DHCPv4 / DHCPv6

```sh
curl -X PUT .../gateways/100/dhcp4 -d '{
  "enabled": true, "pool_start": "10.0.100.100", "pool_end": "10.0.100.199",
  "lease_seconds": 3600, "dns": ["10.0.100.2"]}'

# static binding（條件 AND；nil=wildcard；至少一項；全部非 wildcard 條件須匹配；
# 匹配條件數多者優先；平手取 order 大者）
curl -X PUT .../gateways/100/dhcp4/static/web1 -d '{
  "order": 10, "port_identifier": "vm1", "mac": "52:54:00:00:00:01",
  "ip": "10.0.100.10"}'
curl ... GET .../dhcp4/static
curl -X DELETE .../dhcp4/static/web1

curl ... GET .../dhcp4/leases            # 活動租約（含 port_identifier）
curl -X DELETE .../dhcp4/leases/10.0.100.100   # 強制回收
```

`/dhcp6` 同構（`client_id` 欄位放 DUID 的 hex）。租約與 switchport 連動：
port 離線（連線斷開或被刪除）時自動釋放該 port 的租約。

#### SLAAC（Router Advertisement）

```sh
curl -X PUT .../gateways/100/slaac -d '{
  "enabled": true, "interval_seconds": 200, "managed": false, "other": true,
  "prefixes": [{"prefix": "fd00:100::/64", "on_link": true, "autonomous": true}]}'
```

週期廣播至 `ff02::1`，並回應 Router Solicitation。

## QEMU 範例

```sh
# gvswitch 端
curl ... /api/v1/ports -d '{"identifier":"vm1","vlan":100,"mode":"server",
  "transport":"unix","local":"/run/vm1.sock"}'

# QEMU 端（stream framing 相容）
qemu-system-x86_64 ... \
  -netdev stream,id=n1,server=off,addr.type=unix,addr.path=/run/vm1.sock \
  -device virtio-net-pci,netdev=n1

# 或 dgram（unixgram，雙向都要 bind）
curl ... -d '{"identifier":"vm2","vlan":100,"mode":"client","transport":"unixgram",
  "local":"/run/sw-vm2.sock","remote":"/run/vm2.sock"}'
qemu-system-x86_64 ... \
  -netdev dgram,id=n1,local.type=unix,local.path=/run/vm2.sock,remote.type=unix,remote.path=/run/sw-vm2.sock \
  -device virtio-net-pci,netdev=n1
```

VM 內 DHCP 拿 IP、`ping 10.0.100.2`、對外連線即可驗證。

## -config 格式

```json
{
  "gateways": [{
    "vlan": 100,
    "ipv4": {"address": "10.0.100.2", "prefix_len": 24},
    "enable_internet_routing": true,
    "forwards": [{"type": "local", "network": "tcp", "bind": "0.0.0.0:8022", "host": "10.0.100.10:22"}],
    "dhcp4": {"enabled": true, "pool_start": "10.0.100.100", "pool_end": "10.0.100.199"},
    "dhcp4_static": [{"id": "web1", "mac": "52:54:00:00:00:01", "ip": "10.0.100.10"}],
    "slaac": {"enabled": true, "prefixes": [{"prefix": "fd00:100::/64", "on_link": true, "autonomous": true}]}
  }],
  "ports": [
    {"identifier": "vm1", "vlan": 100, "mode": "server", "transport": "unix", "local": "/run/vm1.sock"}
  ]
}
```

## 轉發引擎

- FDB 是 `map[{vlan int32, mac [6]byte}]entry` 雜湊表 — 定長 struct key，
  無字串比對、無線性掃描。
- hot path 完全指針化：每個 port 經 `PortRef` 快取自己的 registry 指針
  （atomic，port 移除時以 gone flag 失效）；FDB 動態 entry 在 learning 時
  直接存目的 port 的指針，命中即用。`identifier` 字串只用於 API 顯示、
  DHCP static binding 條件與 port-down 事件，不在每幀路徑上。
- 唯一例外：靜態 FDB entry 可指向尚未建立的 port，命中時按 ID 解析一次。
- flood 是成員迭代（VLAN/isolation 過濾），不是搜尋。

## 開發

```sh
go vet ./internal/... ./cmd/...
go test ./internal/... -race      # 單元 + 程序內整合測試（tap/af_xdp 需 root，無權限自動 skip）
```

## 整合測試（tests/）

```sh
cd tests
./init_artifacts.sh    # 安裝 qemu/libguestfs 等套件、下載 Debian cloud image
                       # 到 artifacts/、烤入 qemu-guest-agent
./run_all.sh           # 或單跑：
./test_tap.sh          # tap port：host 從 tap 端 ping 通 gateway、FDB 驗證
./test_afxdp.sh        # af_xdp 接管 veth 一端，從另一端 ping 通 gateway
./test_vsock.sh        # vsock_loopback：tap→switchB→vsock→switchA→gateway
./test_qemu.sh         # 真 Debian VM：DHCP 拿 IP（lease 綁 switchport）、
                       # guest-agent 驗證 IP、local-forward 收到 SSH banner、
                       # 關機自動釋放租約；TRANSPORT=stream|dgram|tcp
```

各測試缺前置條件（root、/dev/vsock、image）時自動 skip。`tests/artifacts/`
內容不進 git。

已知限制：

- DHCP 租約只存在記憶體，重啟即清空。
- DHCPv6 僅實作 stateful IA_NA 最小子集（無 IA_PD / Reconfigure）。
- ICMP echo 只回應網關自身位址（與 slirpnetstack 相同）。
- `_overlay/vswitch_glue.go` 依賴 slirpnetstack 內部符號；upstream 更新後
  跑 `./sync-slirpnetstack.sh`，編譯失敗即代表需要調整 glue。
