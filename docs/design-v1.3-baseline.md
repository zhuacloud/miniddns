# miniddns — 下一版本需求与设计基线（设计规格 v1.3 草案）

> **Requirements & Design Baseline** · 低 CPU、低内存、低峰值与双轨可验证演进基线
>
> 状态：**设计基线（经交叉审查修订）** · 含 v1.3.1 勘误（现网复测回写，2026-11-27）· 基于权威规格：[`docs/design.md`](design.md) v1.2（含 1.2.1–1.2.4 修订）
>
> 版本命名空间说明（见 [`docs/RELEASE_PROCESS.md`](RELEASE_PROCESS.md) §1）：
> - **设计规格版本**：本文档定义 **v1.3** 演进基线；**每个里程碑合入时同步回写** [`docs/design.md`](design.md) 对应章节（遵循 `design §04.7`），避免规格与实现长期漂移。
> - **目标软件版本**：下一发布周期（如 `0.0.2` / `0.1.0`，由发布流程通过 `VERSION=` 注入；本地构建仍固定为 `0.0.0-dev`）。
> - **配置兼容性**：**100% 向后兼容 v1.2 配置文件**（不新增、不删除、不修改任何 INI key 与枚举值）。
> - **引用约定**：本文档内部引用写作 `本文 §x.y`；对权威规格 `docs/design.md` 的引用统一写作 `design §xx.y`，避免章节号冲突。

---

## 目录

- [01 背景与实测基线](#s1)
- [02 演进目标、非目标与新版双轨门禁](#s2)
- [03 需求清单（REQ-01 ~ REQ-08）](#s3)
- [04 对冻结规格 v1.2 的修订对照表](#s4)
- [05 详细技术方案与模块变更设计](#s5)
- [06 内存与 CPU 收益量化估算](#s6)
- [07 不可回归红线与安全约束](#s7)
- [08 测试、注入手段与验收门禁升级](#s8)
- [09 实施里程碑（CPU 优先重排）](#s9)
- [10 风险评估与缓解策略](#s10)

---

<a name="s1" id="s1"></a>

## 01 背景与实测基线

### 1.1 生产实测数据（基准：0.0.1-rc2，glibc 动态未 strip 构建）

在本机生产部署环境（Linux x86_64，systemd 托管，`/usr/local/miniddns/bin/miniddns --foreground`，连续运行 3 天 2 小时 11 分钟）采集的非敏感资源基线如下：

| 维度 | 采集来源 | 当前实测 | `design §14.5` 旧门禁 | 现状评价 |
| --- | --- | --- | --- | --- |
| 常驻内存（cgroup） | `systemctl show -p MemoryCurrent` | **976 KiB（0.95 MiB）** | ≤ 2.5 MB | 达标 |
| 峰值内存（cgroup） | `systemctl show -p MemoryPeak` | **2,496 KiB（2.44 MiB）** | ≤ 6 MB | 达标 |
| 进程常驻集 | `/proc/<pid>/status` `VmRSS` | **2,736 KiB（2.67 MiB）** | ≤ 2.5 MB | ⚠️ 略超 176 KiB（glibc 共享页） |
| ↳ 进程私有内存 | `/proc/<pid>/status` `RssAnon` | **640 KiB** | — | 有明显压缩空间 |
| ↳ 文件/共享库映射 | `/proc/<pid>/status` `RssFile` | **2,096 KiB** | — | glibc + ld-linux 占主体 |
| 进程历史峰值 | `/proc/<pid>/status` `VmHWM` | **2,736 KiB（2.67 MiB）** | ≤ 6 MB | 达标但可压低 |
| 虚拟内存峰值/稳态 | `/proc/<pid>/status` `VmPeak` / `VmSize` | **5.03 MiB / 3.18 MiB** | — | 2 MiB CA 预分配拉高尖峰 |
| 数据段 / 栈虚拟映射 | `VmData` / `VmStk` | **660 KiB / 132 KiB** | — | `VmStk` 为内核预扩虚拟大小，非物理驻留 |
| 24 h 折算 CPU | `CPUUsageNSec = 83.37 s / 74.2 h`（`utime=76.16 s` 占 91.4%） | **≈ 27.0 s / 24 h** | ≤ 2 s / 24 h | ❌ **唯一现网不达标项（超门禁 13.5×）** |
| 二进制形态 | `file` / `size` | glibc 动态、未 strip（329 KB） | musl 静态 ≤ 500 KB | 未使用 musl 静态产物 |

### 1.2 本地四组对照与 `smaps` 精准归因

使用同一二进制 `build/miniddns` 在本地 mock 环境进行 4 组配置对照与 `/proc/<pid>/smaps` 剖析（验证每一 KiB 的确切归属）：

| 配置形态 | `VmRSS` | `RssAnon` | `VmData` | `VmStk`（虚拟） | `smaps [stack] Rss` | `smaps [heap] Rss` | `smaps rw-p miniddns`（`.data+.bss`） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 最小 `pause()` C 程序 | 1,364 KiB | 104 KiB | 92 KiB | **136 KiB** | **16 KiB** | — | 4 KiB |
| `inline token + 1 CA`（旧 `soak.py`） | 2,244 KiB | **240 KiB** | 504 KiB | 140 KiB | — | — | — |
| `token_file + 1 CA` | 2,484 KiB | **488 KiB**（+248） | 504 KiB | 140 KiB | — | — | — |
| `inline token + 全量 CA` | 2,352 KiB | **388 KiB**（+148） | 504 KiB | 140 KiB | — | — | — |
| `token_file + 全量 CA` | **2,696 KiB** | **644 KiB** | **664 KiB** | **140 KiB** | **124 KiB** | **424 KiB** | **4 KiB** |

上述实测精确揭示了全部内存与 CPU 事实（纠正初版草案中的两处误判）：

1. **`RssAnon = 640 KiB` 的真实构成**（`token_file + 全量 CA` 下 mock `644 KiB` 与生产 `640 KiB` 几乎完全一致，证明 glibc NSS 影响极小）：
   - **`[heap] Rss = 424 KiB`**：包含 148 张根证书的 `ca->arena`（实测 **70.2 KiB**）、`src/provider.c:510` 读 `token_file` 时 `malloc(256 KiB) + memset(0, 256 KiB)` 触发物理页 fault 且落入 glibc `brk` 堆后滞留的 **~256 KiB**，以及启动期配置/CA 分配造成的 **~95 KiB** `ptmalloc2` 空闲堆滞留。
   - **`[stack] Rss = 124 KiB`**：`main()` 栈上直接放置 `struct app`（43.8 KiB）+ `nl_read_dump`/`mn_nl_drain` 32 KiB 缓冲 + `tls_one_request` ~39.5 KiB（`struct mn_tls` 23.3 KiB + `headers[8192]` + `extra_norm[4096]` + `tmp[4096]`），而最小程序仅需 16 KiB，存在 **~100 KiB 真实栈物理页可压降**；但必须用 `smaps [stack] Rss` 度量，而非 `VmStk`（内核 `exec` 时即预扩 `VmStk` 至 132–140 KiB）。
   - **`.data + .bss` 仅占 `4 KiB`**：Linux 对 `.bss` 按需分配零页（demand paging），`src/log.c` 的 `g_folds[16]`（17.2 KiB 虚拟地址）在零折叠稳态下**实际物理 RSS 为 0 KiB**，不属于高优先优化项。
   - **glibc 共享库映射 `RssFile ≈ 2,052 KiB`**：`libc.so.6` + `ld-linux-x86-64.so.2` 贡献 ~1.6 MiB；切换为 musl 静态产物可整体消除。
2. **CPU 超标（27.0 s / 24 h）的实测根因**：
   - **排除空转**：20 s 无 netlink 事件窗口内，`d_utime = 0 ms`、`d_vol_cs = 0`，`ppoll` 完全休眠；
   - **主根因（占比 ~92%）：IPv6 Router Advertisement 生命周期刷新风暴**。在 25.7 s 同步采样窗口的 `t = +20.64 s` 捕获到主网卡 `eno1` 收到 3 条 `RTM_NEWADDR`（`AF_INET6`、`scope=0`、`flags=0x100/0x120`，仅刷新 `IFA_CACHEINFO` 的 `pref`/`valid`，地址本身未变），紧接着 PID `81022` 被唤醒并消耗 **`d_cpu = 22.49 ms`（`d_utime = 20 ms`）、`d_vol_cs = 8`**。路由器每 ~60–75 s 发送一次 RA，全天 ~1,200 次 × 22.5 ms ≈ **27.0 s / 24 h**，与 74.2 h 均值精准吻合；
   - **次级放大因子（单周期 ~22.5 ms）**：即使消除全部 RA 风暴，默认 `interval_fallback = 900 s`（96 次/天）× 22.5 ms = **2.16 s / 24 h** 仍逼近 2.0 s 红线，原因包括：① `src/provider.c` 在记录循环内重复调用 `mn_detect_ipv4()`；② `src/tls_http.c:1587` 用慢速 32 位 `br_rsa_i31_pkcs1_vrfy` 覆盖了 BearSSL 64 位默认的 `br_rsa_i62_pkcs1_vrfy`；③ 同 `(provider, name)` 双栈 `A+AAAA` 每轮向 `api.cloudflare.com` 发起 2 次独立 TLS 1.2 握手。

---

### 1.3 现网复测回写（0.0.1-rc3 musl 静态版，2026-11-27）

将 GitHub Release 构建的 `miniddns-0.0.1-rc3-linux-x64-musl.tar.gz` 部署到同一生产主机（systemd 257，加固单元不变，配置与 token 未改动），boot cycle 后采集 34 分钟稳态窗口：

| 维度 | rc2（glibc 动态） | rc3（musl 静态） | `design §14.5` musl 门禁 | 结论 |
| --- | --- | --- | --- | --- |
| `MemoryCurrent` | 976 KiB | **500 KiB** | ≤ 512 KiB | 达标 |
| `VmRSS` | 2,736 KiB | **520 KiB** | ≤ 768 KiB | 达标（−81%） |
| `RssAnon` | 640 KiB | **168 KiB** | ≤ 256 KiB | 达标（−74%，窗口内零增长） |
| `VmHWM` | 2,736 KiB | **520 KiB** | ≤ 1.0 MiB | 达标 |
| `VmPeak` | 5,148 KiB | **780 KiB** | ≤ 1.5 MiB | 达标（−85%） |
| `smaps [stack] Rss` | 124 KiB | **36 KiB** | ≤ 32 KiB | ⚠️ 超一页（−71%）；mock 轨仍达标 |
| cgroup `MemoryPeak` | 2,496 KiB | 2,456 KiB | ≤ 1.0 MiB | ❌ **指标口径问题**：同一加固集合下 `/bin/sleep` 的瞬态单元亦达 2,300 KiB（无沙箱 1,812 KiB），峰值来自 systemd 257 `systemd-executor` 搭建沙箱的阶段，与守护进程无关；峰值门禁以 `VmHWM` 为准 |
| 二进制（stripped） | 336,104 B（动态、未 strip） | **355,680 B** | ≤ 380 KB | 达标 |
| 24 h 折算 CPU | **≈ 27.0 s**（77.9 h 均值） | **≈ 2.7 s**（窗口外推） | ≤ 1.5 s（硬上限 2 s） | ❌ **仍超目标**，根因见下 |

CPU 的实测构成（cgroup `cpu.stat` 1 Hz 采样）：

- `timer` cycle：**11.3 / 11.5 ms** 两次（rc2 长期均值 ≈ 12.9 ms/cycle：87.5 s ÷ 约 6,800 cycle；§1.1 的 22.5 ms 为单次采样高值）。本地 mock 复现显示单次 TLS 请求的 CPU 取决于证书链：P-256 根 3.13 ms，**生产同款链（P-256 叶子/中间证书 + P-384 根 GTS Root R4）6.42 ms**——P-384 验签走 BearSSL 0.6 通用的 `ec_prime_i31`，上游任何发布版都没有 64 位或 P-384 专用实现，无安全可行的代码级优化手段。
- RA 突发：现网约 **87 次/小时（≈ 2,050 次/天**，rc2 过去 24 h 共 1,994 个 `reason=event` cycle），每个仍耗 **0.78 ms**，呈两段式：突发到达时 ~0.25 ms，`debounce_ms` 后 ~0.55 ms（layer-2 `mn_nl_rescan()`）。`/proc/<pid>/syscall` 轮询证实每个突发后精确 +1.5001 s 有一段活动。
- 外推：96 × 11.4 ms + 2,050 × 0.78 ms ≈ **2.7 s/24 h**。

**根因（layer-1 漏判）**：rtnetlink 被动监听（解析 `IFA_FLAGS` 属性）显示每个 RA 突发含 3 条 `RTM_NEWADDR`：preferred 地址刷新（`IFA_FLAGS=0x100`，命中指纹）、**deprecated 地址连续两条**——`IFA_FLAGS=0x100`（无 DEPRECATED，`ifa_prefered=0`）与 `IFA_FLAGS=0x120`。对照内核 `net/ipv6/addrconf.c`（v6.12）`addrconf_prefix_rcv_add_addr()`：

```c
if (update_lft) {
        ifp->valid_lft = valid_lft;
        ifp->prefered_lft = prefered_lft;
        WRITE_ONCE(ifp->tstamp, now);
        flags = ifp->flags;
        ifp->flags &= ~IFA_F_DEPRECATED;     /* 先清除 */
        spin_unlock_bh(&ifp->lock);
        if (!(flags&IFA_F_TENTATIVE))
                ipv6_ifa_notify(0, ifp);     /* 第 1 条：IFA_FLAGS 无 DEPRECATED */
}
...
addrconf_verify(net);                         /* age >= prefered_lft(0) → 重新置位，发第 2 条 */
```

dump 路径（`inet6_fill_ifaddr()` 原样输出 `ifa->flags`）里该地址的指纹 `crit_flags` 为 `0x20`，第 1 条消息为 `0x0`，`nl_addr_matches_fp()` 判不等 → `interesting` → debounce → layer-2 快照比对后跳过（无 TLS，正确性无损），但每个 RA 都付出一次 rescan。注意 `ip -6 addr change`（`inet6_addr_modify()`）只发一条带 DEPRECATED 的通知，**无法复现这对消息**，因此 M2 的 netns RA 压测没有发现该问题；修复与回归测试见 §5.2.1 第 4 条与 §8.2。

---

<a name="s2" id="s2"></a>

## 02 演进目标、非目标与新版双轨门禁

### 2.1 目标

1. **首要解决唯一现网超标项（CPU）**：消除 IPv6 RA 纯生命周期刷新风暴与无关接口噪声，同时压缩单周期 TLS 握手开销，将生产 24 h 累计 CPU 从 **27.0 s 降至 ≤ 1.5 s**（硬上限 2.0 s），且**绝不退化 NAT 主机链路重连场景的秒级响应**。
2. **建立可验证的“改前必红”度量体系**：修复 `scripts/soak.py` 使用 `token_file + 全量 CA + smaps [stack] Rss`，补齐 musl 静态产物的构建与无 `LD_PRELOAD` mock 验收能力。
3. **压低峰值与私有常驻内存**：消灭 2 MiB CA 整文件预分配、256 KiB `token_file` 零填充与双重读配置，压低 `[stack] Rss` 至 **≤ 32 KiB**，glibc 动态版 `RssAnon` 从 644 KiB 降至 **≤ 320 KiB**（`VmRSS ≤ 2.4 MiB`，全口径满足原 2.5 MB 红线），musl 静态版实测校准并压入极低常驻区间。
4. **低侵入与零破坏**：裁剪低收益高侵入改动（`g_folds`、`cfg` 动态化不再作为必做项），保持配置 100% 向后兼容、零写入不变量与 fail-closed 安全模型不变。

### 2.2 新版双轨资源门禁（v1.3 目标阈值）

| 指标 | musl 静态生产版（推荐）\* | glibc 动态兼容版 | `design §14.5` 旧门禁 | 采集方式与验收环境 |
| --- | --- | --- | --- | --- |
| 常驻 cgroup 内存（`MemoryCurrent`） | **≤ 512 KiB**（rc3 现网 500 KiB） | **≤ 640 KiB** | ≤ 2.5 MB | `systemctl show -p MemoryCurrent`（生产主机） |
| 进程常驻集（`VmRSS`） | **≤ 768 KiB**（rc3 现网 520 KiB） | **≤ 2,458 KiB（2.4 MiB）** | ≤ 2.5 MB | `/proc/<pid>/status` `VmRSS`（mock + 生产） |
| 进程私有内存（`RssAnon`） | **≤ 256 KiB**（rc3 现网 168 KiB） | **≤ 320 KiB**（改前 644 KiB） | 未单列 | `/proc/<pid>/status` `RssAnon`（mock + 生产） |
| 主线程栈物理驻留（`[stack] Rss`） | **≤ 32 KiB**（现网 36 KiB，超一页） | **≤ 32 KiB**（改前 124 KiB） | 未单列 | `/proc/<pid>/smaps` `[stack]` 段 `Rss`（mock / 本地） |
| 峰值内存（`MemoryPeak` / `VmHWM`） | **≤ 1.0 MiB**（rc3 现网 `VmHWM` 520 KiB；cgroup `MemoryPeak` 不适用于 systemd ≥ 254，见 §1.3） | **≤ 2.8 MiB** | ≤ 6 MB | `MemoryPeak` / `VmHWM`（mock + 生产） |
| 虚拟内存峰值（`VmPeak`） | **≤ 1.5 MiB**（rc3 现网 780 KiB） | **≤ 3.8 MiB**（改前 5.03 MiB） | 未单列 | `/proc/<pid>/status` `VmPeak`（mock + 生产） |
| 24 h 稳态累计 CPU（`CPUUsageNSec`） | **≤ 1.5 s**（硬上限 2.0 s；v1.3.1 修复后现网预算 ≈ 1.5–1.6 s，与 RA 速率线性相关，见 §1.3） | **≤ 1.5 s**（硬上限 2.0 s） | ≤ 2.0 s | `systemctl show -p CPUUsageNSec`（生产 24 h）+ mock soak |
| 24 h 稳态写请求数 | **0** | **0** | 0 | mock 集成 + 生产日志审计 |
| 二进制体积（stripped） | **≤ 380 KB**（硬上限 500 KB） | **≤ 320 KB** | ≤ 500 KB | `stat -c %s` |

> \* **musl 门禁校准原则**：因当前宿主机尚未实测 musl 静态包，M1 阶段须先以 Zig 0.13.0 构建 `0.0.1-rc2` musl 静态包并采集真实基线，再将上表带“待实测校准”的 musl 阈值锁定为实测基准值，避免拍脑袋定目标。校准已于 2026-11-27 在生产主机用 `0.0.1-rc3` 完成（见 §1.3）：阈值本身保持为 `soak.py` 门禁不变，括号内为现网实测值。

### 2.3 明确非目标（Non-goals）

- **不默认裁剪内置 CA bundle 根证书**：全量 148 张根证书解析后仅占 70.2 KiB，盲目裁剪会在根证书轮换时造成静默失效。
- **不改 BearSSL I/O 缓冲为半双工模式**：`BR_SSL_BUFSIZE_MONO = 16709 B` 与 `MN_TLS_IOBUF = 16384 B` 差距可忽略。
- **不引入跨周期长连接或 TLS session 复用**：维持 `Connection: close` 简洁性与确定性。
- **不把低收益高侵入项作为必做目标**：`g_folds`（稳态物理 RSS = 0 KiB）降为 P2 可选；`mn_cfg` 数组动态化降为 M4 实测后按需决策。
- **不新增或删除任何 INI 配置 key**，不为测试向生产二进制添加跳过校验或重定向后门。

---

<a name="s3" id="s3"></a>

## 03 需求清单（REQ-01 ~ REQ-08）

| 编号 | 优先级 | 里程碑 | 类别 | 需求摘要 | 预期核心收益 |
| --- | --- | --- | --- | --- | --- |
| `REQ-01` | P0 | M1 | 构建、部署与 musl 验证底座 | `Makefile` 分层优化（`OPT ?= -Os`、`OPT_VENDOR ?= -O2` 实测定型）+ `install`/`dist` strip；`--version` 输出 `libc=musl\|glibc`；`install.sh` 静态优先提示；引入 Zig 0.13.0 校准 musl 基线并落位无 `LD_PRELOAD` 的 musl mock soak 方案 | 建立真实可验证的 musl/glibc 双轨基线；部署切 musl 立降 **~2.0 MiB `VmRSS`** |
| `REQ-07` | P0 | M2 | CPU 治理：两级净变化去重 + NAT 保护 | ① netlink 入口拦截 IPv6 RA 纯 `IFA_CACHEINFO` 刷新、过滤排除接口与噪声标志，同时跟踪 `IFF_UP` + **`IFF_RUNNING`（carrier 翻转）** 保护 NAT 主机；② `reason=event`（非 carrier 翻转）执行本地有效地址快照比对，无变化跳过远端 TLS 且**保持退避/重试状态不变** | 24 h CPU 从 **27.0 s → ~2.1 s**（降幅 ~92%），且 NAT 主机链路重连不退化 |
| `REQ-08` | P0 | M2 | CPU 治理：单周期降耗与观测 | ① cycle 内按族缓存 `detect_ipv4`/`detect_ipv6`；② 恢复 BearSSL 默认 64 位 `i62` RSA 验签；③ 同 `(provider, name)` 双栈 `A+AAAA` 单周期 `GET ?name=...&per_page=100` 合并 discover（`total_pages > 1` 回退单查）；④ `cycle end` 追加 `reason=`/`tls=`；升级 `soak.py`（`token_file` + 全量 CA + `[stack] Rss` + RA 压测） | 生产 24 h 稳态 CPU 压至 **~0.8–1.2 s**（≤ 1.5 s 目标，≤ 2.0 s 硬上限） |
| `REQ-02` | P0 | M3 | CA 流式加载 | 抽取 `mn_checked_open()`，CA 改为 4 KiB 栈缓冲流式分块 `read()` 喂给 `br_pem_decoder_push()`，复用 `dn` 缓冲并采用 `1.5×` 扩容（彻底消灭 2 MiB 整文件 `malloc`） | `VmPeak` 降 **~2 MiB**，`MemoryPeak` 显著下降 |
| `REQ-03` | P0 | M3 | 凭据与配置精确读取 | `token_file` 改用 576 B 栈缓冲读首行（彻底消灭 256 KiB `malloc+memset`）；合并 `load_config` 与 `mn_cfg_load` 双重读取并按 `st_size + 1` 精确分配 | glibc `RssAnon` 立降 **~256 KiB**，消除大块堆阈值抬升 |
| `REQ-06` | P1 | M3 | glibc 堆归还治理 | `#if defined(__GLIBC__)` 下启动期设置 `mallopt(M_MMAP_THRESHOLD, 16384)` / `M_TRIM_THRESHOLD`，并在 boot 完成及 cycle/CA 重载后调用 `malloc_trim(0)` | 消除 `ptmalloc2` 空闲堆滞留，glibc `RssAnon` 稳定回落 |
| `REQ-04` | P1 | M4 | 主线程栈物理驻留瘦身 | `struct app`、32 KiB netlink 缓冲、`struct mn_tls` 移出栈帧（短生命周期分配并在释放前 `mn_secure_zero()`），收窄 `tls_http.c` / `prov_cloudflare.c` 局部栈缓冲 | `smaps [stack] Rss` 从 **124 KiB → ≤ 32 KiB**（净省 ~92–100 KiB 私有页） |
| `REQ-05` | P1/P2 | M4 | 常驻与请求内存精简 | **P1（必做）**：`mn_addr_set`（7.7 KiB）仅 cycle 内存活；HTTP 响应原地解析消除双倍拷贝；**P2（按实测决策）**：`mn_nl.links` / `mn_cfg` 动态化与 `g_folds` 懒分配（仅在 M4 实测未达门禁时实施） | 消除 HTTP 响应 2× 峰值并再省 ~8–12 KiB 常驻内存，同时控制侵入面 |

---

<a name="s4" id="s4"></a>

## 04 对冻结规格 v1.2 的修订对照表

下列条款在 [`docs/design.md`](design.md) v1.2 中属于“强制 / 逐条实现 / 冻结决策”。为遵守 `design §04.7`，**每个里程碑合入时必须同步回写 `docs/design.md` 对应章节并在修订记录追加条目**，不得拖延至全部完成再补：

| 对应里程碑 | `docs/design.md` 条款 | v1.2 原文约束 | v1.3 修订内容 | 兼容性与安全评估 |
| --- | --- | --- | --- | --- |
| M1 | `design §13.1` | `OPT ?= -O2` | 业务代码改为 `OPT ?= -Os`，vendor 保留 `OPT_VENDOR ?= -O2`（M1 基准验证）；`install`/`dist` 产物执行 strip | 二进制更小、常驻代码页更少；密码学性能不退化 |
| M1 | `design §14.5` | 单一 `MemoryCurrent ≤ 2.5 MB`、`MemoryPeak ≤ 6 MB` | 细化为 musl 静态 / glibc 动态双轨门禁，补充 `RssAnon`、`smaps [stack] Rss` 与 24 h CPU 目标 ≤ 1.5 s | 消除 `MemoryCurrent` vs `VmRSS` 歧义，门禁更严格 |
| M2 | `design §05.2` / `§05.3` | “收到任意事件 → 置 `pending=1`” | 改为：仅净变化地址事件，或允许接口上 `IFF_UP` / `IFF_RUNNING` 翻转（及 `if_indextoname` 失败 fail-open / `ENOBUFS`）置 `pending=1`；忽略纯 RA `IFA_CACHEINFO` 刷新与排除接口噪声 | 根治 IPv6 RA CPU 风暴，保护 NAT 主机链路重连响应 |
| M2 | `design §05.4` | “`provider_discover` 每次 cycle 必做，无例外” | 明确分层：`boot`/`timer`/`retry`/`--once`/`--dry-run` 及携带 `carrier_changed` 的 `event` **仍必做 discover，无例外**；非 carrier 的 `reason=event` 若本地有效地址快照完全未变则跳过远端请求，且不改动退避状态 | 零写入与远端真相不变量不变；定时兜底 100% 保留 |
| M2 | `design §07.3` | `discover` 为 `GET .../dns_records?type={A\|AAAA}&name={fqdn}` | 扩展：同 `(provider, name)` 同周期同时启用 `A` 与 `AAAA` 时，允许使用 `GET .../dns_records?name={fqdn}&per_page=100` 单次合并查询并仅在本周期内暂存结果；若 `total_pages > 1` 回退带 `type=` 单查 | 双栈 TLS 握手减半，不跨周期缓存，不违背零状态原则 |
| M2 | `design §08.1` | 显式注册 `br_rsa_i31_pkcs1_vrfy` / `br_ecdsa_i31_vrfy_asn1` | 改为注册 `br_rsa_pkcs1_vrfy_get_default()` / `br_ecdsa_vrfy_asn1_get_default()`（64 位自动用 `i62` 加速） | 保持防御性注册，消除 64 位性能降级与冗余代码 |
| M3 | `design §09.1` / `§09.2` | “read bundle（整文件读入）/ PEM 文件内容 malloc 一次” | 改为 4 KiB 栈缓冲流式 `read()` 分块喂给 `br_pem_decoder_push()`，保留 `total <= 2 MiB` 硬上限与两段式 arena | 消灭 2 MiB 峰值分配，安全校验完全等价 |
| M4 | `design §08.1` | “`struct mn_tls` 不 malloc（静态分配或调用方提供）” | 改为单次请求/握手期间短生命周期 `calloc(1, sizeof(struct mn_tls))`，结束时 `mn_secure_zero()` 后 `free()` | 消除 23.3 KiB 永久栈物理页驻留，且主动擦除 TLS 会话密钥 |

---

<a name="s5" id="s5"></a>

## 05 详细技术方案与模块变更设计

### 5.1 `REQ-01` 构建分层、部署提示与 musl 无 `LD_PRELOAD` 验证（M1）

1. **编译选项分层**（[`Makefile`](../Makefile)）：
   - 业务代码：`OPT ?= -Os`；
   - BearSSL：`OPT_VENDOR ?= -O2`（M1 实测 `-Os` vs `-O2` 的二进制体积与单次 TLS 握手 CPU，若 `-Os` 握手 CPU 增幅 > 10% 则维持 `OPT_VENDOR ?= -O2`）；
   - `all` 保持未 strip（便于开发调试与 `valgrind` 符号解析）；`install` 与 `dist`（无论 `LIBC=musl` 或 `LIBC=glibc`）均执行 strip。
2. **`--version` 汇报 libc**（[`src/main.c`](../src/main.c) `version_info()`）：
   - 增加 `libc=glibc`（`#ifdef __GLIBC__`）或 `libc=musl`（否则），供 `soak.py` 与运维自动识别构建轨。
3. **部署引导与 musl 基线校准**：
   - `install.sh` 检测二进制若含 `PT_INTERP`（动态链接），打印一条非阻断提示说明 musl 静态包可省 ~2 MiB `VmRSS`；
   - 使用 Zig `0.13.0`（与 `.github/workflows/ci.yml` 一致）构建 `0.0.1-rc2` musl 静态包并实测校准 `本文 §2.2` 的 musl 门禁数值。
4. **musl 静态二进制 mock 注入方案**（`scripts/soak.py` + CI）：
   - 静态 musl 不处理 `LD_PRELOAD`，**禁止**给生产二进制加测试用 `--mock-host` / 环境变量开关；
   - `scripts/soak.py` 新增 `--mock-mode preload|netns|hosts`：
     - `preload`（默认，glibc）：沿用 `tests/build/redirect.so`；
     - `netns`（本地免 root 测 musl）：通过 `unshare -rmn`（user + mount + net namespace）将临时 hosts 文件 `mount --bind` 到 `/etc/hosts`（将 `api.cloudflare.com`、`api.ipify.org` 指向 `127.0.0.1`），并在该 netns 内让 `MockServer` 监听 `127.0.0.1:443`；
     - `hosts`（CI Ubuntu runner 测 musl，当 runner 不允许 unprivileged userns 时回退）：CI 步骤中通过 `sudo` 临时写 `/etc/hosts` 并监听 `127.0.0.1:443`（测试结束清理还原）。

---

### 5.2 `REQ-07` CPU 治理：两级净变化去重 + NAT 场景保护（M2）

#### 5.2.1 第一级防线：`mn_nl_drain()` 事件预过滤 + RA 纯生命周期刷新拦截（`src/nl_addr.h` / `src/nl_addr.c`）

1. **接口表补齐 `IFF_RUNNING`**：
   - `struct mn_nl` 中 `links[]` 增加 `int running;`（`RTM_NEWLINK`/`RTM_GETLINK` 取 `(ifi.ifi_flags & IFF_RUNNING) != 0`；`RTM_DELLINK` 置 `up = 0, running = 0`）。
2. **轻量地址指纹表（纯内存，每次 `mn_nl_rescan()` 同步刷新）**：
   - 在 `struct mn_nl` 内记录最近一次 `nl_rescan()` 中已见地址的紧凑指纹：`{ uint8_t family; uint8_t scope; uint8_t valid_nonzero; uint8_t bytes[16]; unsigned ifindex; uint32_t crit_flags; }`（其中 `crit_flags = flags & (IFA_F_TEMPORARY | IFA_F_DEPRECATED | IFA_F_TENTATIVE | IFA_F_DADFAILED | IFA_F_OPTIMISTIC)`；仅保留 `RT_SCOPE_UNIVERSE` 地址，典型主机 2–8 条，占 < 256 B）。
3. **新增过滤排水接口**（保留原有 `mn_nl_drain()` 签名供旧单测兼容）：
   ```c
   int mn_nl_drain_filtered(struct mn_nl *nl, const struct mn_detect_cfg *det_cfg,
                            int *overflow, int *carrier_changed,
                            char *err, size_t errlen);
   ```
   过滤规则：

   | 事件类型 | 过滤 / 放行规则 | 正确性保障 |
   | --- | --- | --- |
   | `RTM_NEWADDR`（RA 纯生命周期刷新） | 若 `(family, ifindex, scope, bytes)` 已存在于指纹表中，且 `crit_flags` 与 `(valid_lft > 0)` 真值均完全一致，仅 `IFA_CACHEINFO` 数值刷新 → **忽略**（不置 `interesting`，不触发 debounce）。 | 新增、删除、前缀变更、`TENTATIVE→preferred`、`DEPRECATED` 置位、`valid_lft` 归零均会改变指纹，**100% 立即触发**。 |
   | `RTM_NEWADDR` / `RTM_DELADDR`（无关族/接口/标志） | 1. `AF_INET` 且 `ipv4_mode == MN_IP4_OFF`；<br>2. `AF_INET6` 且 `ipv6_mode == MN_IP6_OFF`；<br>3. `scope != RT_SCOPE_UNIVERSE`；<br>4. 接口名未通过 `mn_iface_allowed()`；<br>5. `RTM_NEWADDR` 含 `TENTATIVE` / `OPTIMISTIC` 或（`!allow_temporary_ipv6` 时的）`TEMPORARY`。 | 注意：**`ipv4_mode == MN_IP4_EXTERNAL` 或 `AUTO` 时不丢弃允许接口上的全局/私网 IPv4 变更**（DHCP 续租换 IP 仍触发）；`if_indextoname()` 失败时 **fail-open 视为 interesting**；`ENOBUFS`/`MSG_TRUNC` 无条件全量 resync。 |
   | `RTM_NEWLINK` / `RTM_DELLINK` | 先更新 `links[]`（`up` 与 `running`）；若接口通过 `mn_iface_allowed()`（或 `if_indextoname` 失败）且 **`up` 或 `running` 发生真实状态翻转（0↔1）** 或收到 `RTM_DELLINK` → 置 `interesting = 1` 且 **`*carrier_changed = 1`**。 | **保护 NAT 主机**：路由器重启/网线拔插触发 `IFF_RUNNING` 翻转必唤醒，同时屏蔽无状态变化的纯统计/bridge 噪声。 |

4. **DEPRECATED 归一化（v1.3.1 勘误，`mn_nl_decode_addr()`）**：
   - 解码 `AF_INET6` 地址时，若带 `IFA_CACHEINFO` 且 `ifa_prefered == 0`，则**无条件置 `IFA_F_DEPRECATED`**（只置位、不清除；`ifa_prefered > 0` 与 IPv4 不改写）。
   - 原因见 §1.3：内核在每次 RA 生命周期更新时先清除 `IFA_F_DEPRECATED` 并发出第一条 `RTM_NEWADDR`，随后 `addrconf_verify()` 对 `prefered_lft == 0` 的地址重新置位并发出第二条；dump 路径（`inet6_fill_ifaddr()` 原样输出 `ifa->flags`）报告的是置位后的状态。归一化后事件与 dump 描述同一有效状态，上表第一条规则的 `crit_flags` 比较对这对消息恒成立。
   - 真实转换仍触发：`preferred → deprecated`（无论内核是否带上 DEPRECATED 位，`ifa_prefered` 归零即改变指纹）与 `deprecated → preferred`（`ifa_prefered > 0` 且无 DEPRECATED 位，与指纹 `0x20` 不等）均置 `interesting`；`mn_detect_ipv6()`（`design §06.3`）经同一解码器，`preferred` 生命周期耗尽的地址一律按 deprecated 剔除。
   - 单测 `tests/unit.c` 回放现网抓取的三消息突发（同一数据报内 `0x100`/`0x100`/`0x120`），修复前 `dr=1`（改前必红），修复后 `dr=0`。

#### 5.2.2 第二级防线：`reason=event` 本地快照比对与退避语义（`src/main.c`）

1. 在 `struct app` 维护约 120 B 的纯内存快照 `last_local_snap`：`{ int valid; int has_v4_iface; char v4_iface_ip[MN_IP_STRLEN]; int has_v6; char v6_ip[MN_IP_STRLEN]; uint64_t v4_if_sig; }`（`v4_if_sig` 对所有允许且 `IFF_UP` 接口的 IPv4 地址集合做 FNV-1a 哈希，感知 NAT 侧私有 IPv4 变化）；并维护 `int pending_carrier;`（在 debounce 窗口内只要任一事件产生 `carrier_changed = 1` 即置位，cycle 触发后清零）。
2. **仅当 `reason == "event"` 且 `!pending_carrier` 时**：
   - 执行 `nl_rescan()`（~0.1 ms）+ 本地 `det_v4_iface` + `mn_detect_ipv6` + `v4_if_sig` 计算（零网络、零 TLS）；
   - 若与 `last_local_snap` 完全一致：
     - 输出 `debug` 日志 `cycle skip reason=no_local_addr_change`；
     - **退避与定时语义（显式定义）**：**直接 `continue` 返回 `ppoll` 循环，仅清除本次 `deb`，严禁修改 `backoff_idx`、`retry_active`、`retry_due`、`fallback_due`**（不重置失败退避，不取消已预约的 retry 定时器）；
   - 否则更新 `last_local_snap` 并执行完整 `mn_cycle()`。
3. **`reason == "boot" | "timer" | "retry"`、`--once`、`--dry-run` 以及 `pending_carrier == 1` 的 `event`**：**一律不跳过**，必须完整执行 `detect`（含 external echo）与 `provider_discover`，并在成功后刷新 `last_local_snap`。

---

### 5.3 `REQ-08` CPU 治理：单周期降耗与观测（M2）

1. **单周期按族缓存探测**（[`src/provider.c`](../src/provider.c) `mn_cycle()`）：
   - 在 `for (i = 0; i < n_records; ++i)` 之前初始化 `have_v4_det = 0`、`have_v6_det = 0`；
   - 首次遇到启用中的 `AF_INET` 记录时调用一次 `mn_detect_ipv4()` 并缓存 `(drc4, det4, err4)`，后续同族记录直接复用；`AF_INET6` 同理。
2. **恢复 BearSSL 64 位默认 RSA 验签**（[`src/tls_http.c`](../src/tls_http.c) `tls_setup()`）：
   - 将 `br_x509_minimal_set_rsa(&t->xc, br_rsa_i31_pkcs1_vrfy)` 改为 `br_x509_minimal_set_rsa(&t->xc, br_rsa_pkcs1_vrfy_get_default())`；
   - 将 `br_x509_minimal_set_ecdsa(&t->xc, br_ec_get_default(), br_ecdsa_i31_vrfy_asn1)` 改为 `br_x509_minimal_set_ecdsa(&t->xc, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default())`。
   - **边界（现网复测结论）**：64 位优化仅覆盖 RSA。vendored 的 BearSSL 0.6 与上游 0.6 发布版逐字节一致，其中**不存在** 64 位椭圆曲线实现（`ec_p256_m64` / `ec_c25519_m64` / `ecdsa_i62_*` 均为上游 0.6 之后未发布的代码），`br_ec_get_default()` 只能返回 `br_ec_all_m31`；`api.cloudflare.com` 使用 ECDSA 链（P-256 叶子与中间证书，根 GTS Root R4 为 P-384），因此单周期 CPU 的主体是 P-256/P-384 验签的固有成本（见 §1.3），不再追求本条原先估计的 −50%。
3. **同 `(provider, name)` 双栈 `A + AAAA` 合并 discover（唯一拍板方案）**（[`src/json_util.c`](../src/json_util.c) / [`src/prov_cloudflare.c`](../src/prov_cloudflare.c) / [`src/provider.c`](../src/provider.c)）：
   - `mn_cycle()` 在进入记录循环前，统计各 `(provider_id, name)` 是否同时有已启用的 `A` 和 `AAAA` 记录；
   - 对于同时启用 `A` 和 `AAAA` 的 `(provider, name)`，Cloudflare provider 发起**单次** `GET /client/v4/zones/{zone_id}/dns_records?name={fqdn}&per_page=100`：
     - 解析响应 JSON 中 `result[]` 数组：分别提取第一个 `type == "A"` 与第一个 `type == "AAAA"` 记录的 `(id, content)`，并统计各自匹配条数（> 1 条仍按 `design §07.3` 打 `duplicate_records` warn）；
     - 同时检查 `result_info.total_pages`（若存在且 `> 1`，说明该域名下存在大量 TXT/MX 等记录发生分页截断，自动回退为原有 `?type={A|AAAA}&name={fqdn}` 精确查询）；
     - 解析结果存入**仅限本轮 `cycle()` 存活**的栈/临时槽位，供同 `cycle` 内的另一条记录（`AAAA` 或 `A`）直接命中；`cycle()` 退出前立即清空该临时缓存，绝不跨 cycle 保留。
   - 若某 `(provider, name)` 仅启用了 `A` 或仅启用了 `AAAA`，仍直接发原有 `?type={A|AAAA}&name={fqdn}`，零额外流量。
4. **周期诊断字段**：
   - 在 `tls_http.c` 维护单线程请求/握手计数器（每次发起 TLS 连接前自增，提供 `mn_tls_cycle_counter_reset()` / `mn_tls_cycle_counter_get()`）；
   - `cycle end` 行尾兼容追加 `reason=<boot|event|timer|retry> tls=<N>`（位于 `level=info` 之前，不改变既有字段名与顺序）。

---

### 5.4 `REQ-02` & `REQ-03` & `REQ-06` 文件 I/O 峰值消灭与堆治理（M3）

1. **统一安全打开原语 `mn_checked_open()`**（[`src/util.h`](../src/util.h) / [`src/util.c`](../src/util.c)）：
   - 完整保留 `design §03` 全部策略（token `O_NOFOLLOW`、conf/CA `realpath()`、CA 白名单 `/etc/` `/usr/share/` `<root>/`、`S_ISREG`、属主 root、无 `S_IWGRP|S_IWOTH`、`st_size <= maxsize`）；
   - 返回 `fd >= 0`、`*out_size` 与可选 `*out_st`（供 `ca.c` 直接取得 `(st_mtime, st_size, st_ino)` 签名，省去重复 `realpath+stat`）；
   - 保留 `mn_checked_read()` 为薄封装兼容现有单测。
2. **CA 4 KiB 流式分块加载**（[`src/ca.c`](../src/ca.c)）：
   - `mn_ca_init()` 与 `mn_ca_refresh()` 改为调用 `mn_checked_open()` 后，使用栈上 `unsigned char chunk[4096]` 循环 `read()` 并流式喂给 `br_pem_decoder_push()`；
   - 累计读入字节数 `total > MN_LIMIT_CA_FILE` 时立即报 `E_CA_LOAD`（防 TOCTOU）；
   - `st.dn` 缓冲挂在 `struct ca_parse` 上按证书复用（消除 148 次 `malloc`/`free`），`st.blobs` 初始 16 KiB 并按 `1.5×` 扩容；
   - 保留 `mn_ca_parse_bundle()` 内存入口以兼容全部现有单元测试。
3. **Token 小缓冲读首行**（[`src/provider.c`](../src/provider.c)）：
   - `prov_resolve_token()` 改为 `mn_checked_open(..., MN_FILE_TOKEN)` + 栈上 `char raw[MN_TOKEN_MAX + 64]`（仅 576 B）循环读入直至 `\n`/`\r`/EOF，超长直接报 `token_too_long`，拷贝后 `mn_secure_zero(raw, sizeof(raw))`。彻底消除 256 KiB `malloc + memset`。
4. **配置单次精确读取**（[`src/main.c`](../src/main.c) + [`src/cfg.c`](../src/cfg.c)）：
   - 取消 `load_config()` 的重复 probe 读取；`mn_cfg_load()` 通过 `mn_checked_open()` 精确 `malloc(st_size + 1)` 读一次，并明确区分不可读错误（退出码 `2`）与语法/校验错误（按 `design §11` 返回 `1`/`2`）。
5. **glibc 堆归还治理**（[`src/main.c`](../src/main.c)）：
   - 在 `#if defined(__GLIBC__)` 下，启动入口执行 `mallopt(M_MMAP_THRESHOLD, 16 * 1024)` 与 `mallopt(M_TRIM_THRESHOLD, 32 * 1024)`；
   - 在守护进程 boot 完成进入 `ppoll` 前，以及每次 `app_cycle()` 结束后调用 `malloc_trim(0)`；musl 构建完全不编译该段。

---

### 5.5 `REQ-04` & `REQ-05` 栈物理驻留瘦身与 HTTP 原地解析（M4）

1. **主线程栈压低至 `[stack] Rss ≤ 32 KiB`**（现状实测 `124 KiB`）：
   - `main()` 中 `struct app`（43.8 KiB）改为堆分配 `calloc(1, sizeof(*a))`，退出时清理释放；
   - `src/nl_addr.c` 中 `nl_read_dump()` 与 `mn_nl_drain()` 的 32 KiB `MN_NL_BUFSZ` 缓冲改为函数内短生命周期 `malloc(MN_NL_BUFSZ)`，返回前 `free()`（在 glibc `M_MMAP_THRESHOLD = 16 KiB` 下直接 `munmap` 立即还给内核）；
   - `src/tls_http.c` 中 `tls_one_request()` 与 `mn_tls_handshake()` 的 `struct mn_tls`（23.3 KiB）改为 `calloc(1, sizeof(*t))`，返回前 `mn_secure_zero(t, sizeof(*t)); free(t);`；
   - 收窄 `tls_one_request()` 栈局部数组：`headers[2048]`、`extra_norm[1024]`、`tmp[1024]`；收窄 `prov_cloudflare.c`/`provider.c` 错误详情缓冲至 512 B 并复用转义缓冲。
2. **高收益常驻/峰值项（P1）**：
   - 将 `struct mn_addr_set`（7.7 KiB）移出 `struct app`，改为 `app_cycle()` / `do_print_ip()` 内临时分配、周期结束立即释放；
   - `src/tls_http.c` 新增内部原地解析 `tls_parse_in_place(char *resp, size_t rlen, ...)`：对 `Content-Length`/`EOF` 通过 `memmove` 原地前移并 `realloc` 收缩后直接转交 `out->body`，对 `chunked` 原地前移解码，消除响应体双倍拷贝峰值（保留只读 `mn_http_parse_raw()` 兼容单元测试）。
3. **低收益高侵入项（P2，M4 实测后决策）**：
   - 完成上述改造后先跑双轨 `soak.py` 实测 `RssAnon` 与 `[stack] Rss`；若 glibc 轨 `RssAnon` 已稳定 ≤ 240 KiB、musl 轨达标，则**不实施** `mn_cfg` 数组动态化与 `g_folds` 懒分配，避免无谓代码复杂度。

---

<a name="s6" id="s6"></a>

## 06 内存与 CPU 收益量化估算

| 指标 | 当前 glibc 生产/mock 基线 | v1.3 glibc 动态版（预计） | v1.3 musl 静态版（预计，M1 校准） | 主要贡献需求 |
| --- | --- | --- | --- | --- |
| `MemoryCurrent`（cgroup） | 976 KiB（生产） | **~320–450 KiB** | **~220–350 KiB** | `REQ-03`(-256K) + `REQ-04`(-92K) + `REQ-06` |
| `VmRSS`（`ps` 口径） | 2,736 / 2,696 KiB | **~2.1–2.3 MiB**（≤ 2.4 MiB） | **~450–650 KiB** | `REQ-01`(musl 去 libc) + `REQ-03/04/06` |
| `RssAnon`（私有内存） | 640 / 644 KiB | **~220–290 KiB**（≤ 320 KiB） | **~140–220 KiB** | `REQ-03`(-256K) + `REQ-04`(-92K) + `REQ-06` |
| `smaps [stack] Rss` | 124 KiB（mock） | **≤ 28 KiB**（≤ 32 KiB） | **≤ 24 KiB**（≤ 32 KiB） | `REQ-04`：`app`/netlink/`mn_tls` 离栈 |
| `MemoryPeak` / `VmHWM` | 2,496 / 2,736 KiB | **~2.2–2.5 MiB** | **~550–800 KiB** | `REQ-02/03/05` 消除 2 MiB CA + 256 KiB token + HTTP 双拷贝 |
| `VmPeak`（虚拟内存峰值） | 5,148 KiB | **~3.1–3.5 MiB** | **~750–1,100 KiB** | 消灭 2 MiB CA 映射与双重 256 KiB 配置读 |
| 24 h 稳态累计 CPU | **27.0 s**（生产 74 h 均值） | **~0.8–1.2 s**（≤ 1.5 s） | **~0.8–1.2 s**（≤ 1.5 s） | `REQ-07` 消除 RA 风暴(-92%) + `REQ-08` 缓存/`i62`/合并(-50%) |

**现网实测对照（rc3，见 §1.3）**：内存各项均落在或优于 musl 列的预计区间（`VmRSS` 520 KiB、`RssAnon` 168 KiB、`VmHWM` 520 KiB、`VmPeak` 780 KiB、`MemoryCurrent` 500 KiB），`[stack] Rss` 36 KiB 略高于预计；CPU 从 27.0 s 降至约 2.7 s/24 h（−90%），但高于预计的 0.8–1.2 s：单周期 11.4 ms 受 P-384 根证书验签限制，RA 速率约为设计假设的 1.7 倍，且 layer-1 漏判使每个 RA 仍耗 0.78 ms。v1.3.1 修复后的预算为 96 × 11.4 ms + 2,050 × ≤0.25 ms ≈ 1.5–1.6 s/24 h。

---

<a name="s7" id="s7"></a>

## 07 不可回归红线与安全约束

1. **零写入不变量（`design §01 / §05.4`）**：IP 未变化时写请求数恒为 0；`boot`/`timer`/`retry` 仍必做 `discover`；不写磁盘状态文件。
2. **Fail-closed 安全模型（`design §08.4 / §09`）**：证书/链/主机名/时间错误立即中止；不向生产二进制引入任何测试重定向或跳过校验后门。
3. **分级符号链接与权限策略（`design §03`）**：`mn_checked_open()` 完整保留 token `O_NOFOLLOW`、conf/CA `realpath()` 目标校验、CA 白名单目录、属主/权限检查与流式读累计上限（防 TOCTOU）。
4. **凭据与密钥擦除**：token 栈缓冲、`Authorization` 头缓冲及短生命周期 `struct mn_tls` 释放前一律 `mn_secure_zero()`。
5. **NAT 场景秒级响应不退化**：允许接口上 `IFF_UP`/`IFF_RUNNING` 翻转必须触发完整探测（不可被快照跳过）。
6. **配置、CLI、日志 100% 向后兼容**：不增删 INI key，保持退出码与 `<PRI>` 日志格式，仅在 `cycle end` 行尾（`level=` 前）追加兼容字段。

---

<a name="s8" id="s8"></a>

## 08 测试、注入手段与验收门禁升级

### 8.1 单元测试清单（`tests/unit.c`）

| 里程碑 | 新增/强化测试项 |
| --- | --- |
| M2 | **netlink 注入（利用 `socketpair` 已连接 socket，免 root）**：① IPv6 RA 纯 `IFA_CACHEINFO` 刷新返回 `0`（不触发）；② 地址新增/删除/`TENTATIVE→preferred`/`DEPRECATED`/`valid_lft→0` 返回 `1`；③ 排除接口、`fe80::`、`TEMPORARY`（关闭时）返回 `0`；④ 允许接口 `IFF_RUNNING` 翻转返回 `1` 且 `carrier_changed=1`；⑤ `if_indextoname` 失败 fail-open；⑥ `event` 跳过时 `backoff_idx`/`retry_active`/`retry_due` 保持不变。<br>**单周期效率**：⑦ 多条 `A` 记录同周期仅 1 次外部 echo；⑧ 同 `(provider, name)` 双栈 `A+AAAA` 单次 `GET ?name=...&per_page=100`（含 `duplicate_records` 告警与 `total_pages > 1` 回退带 `type=` 单查）；⑨ `br_rsa_pkcs1_vrfy_get_default()` 握手成功。 |
| M3 | **`mn_checked_open`**：token 符号链接拒绝、CA 白名单外拒绝、组/他可写拒绝、非普通文件拒绝、TOCTOU 读超限拒绝。<br>**CA 流式解析**：1 字节 / 7 字节 / 4096 字节跨 PEM 头尾边界分块解析、无尾换行、单张 DER > 16 KiB 跳过、重载失败保留旧锚点。<br>**Token 与配置**：首行超长 token 拒绝、空 token 拒绝、配置单次读区分不可读（exit 2）vs 校验错（exit 1/2）。 |
| M4 | **HTTP 原地解析**：`Content-Length` / `chunked` / `EOF` 原地解析与 `mn_http_parse_raw()` 输出逐字节一致，超限仍报 `body_too_large`；`ASan/UBSan` 与 `valgrind --leak-check=full` 全路径零泄漏。 |

### 8.2 集成、RA 压测与 `soak.py` 双轨验收

1. **`scripts/soak.py` 升级（M1 先行，确保改前必红）**：
   - 改用 `token_file` + 全量 `ca/ca-certificates.crt`（拼接 mock CA）；
   - 采集并校验 `VmRSS`、`RssAnon`、`RssFile`、`VmHWM`、`VmPeak`、`smaps [stack] Rss`、稳态 `RssAnon` 增长（≤ 32 KiB）与 `CPU`；
   - 自动识别 `--version` 的 `libc=musl|glibc` 切换双轨阈值，并支持 `--mock-mode preload|netns|hosts`。
2. **RA 刷新端到端压测（M2）**：
   - 在 `unshare -rn` 独立 netns 中创建 `dummy0` 并连续执行 `ip -6 addr change ... valid_lft ... preferred_lft ...` 模拟高频 RA（如每 1 s 刷新一次共 20 次），断言守护进程期间 `cycle` 与 TLS 握手增量 **= 0**，而执行 `ip -6 addr add`（新地址）或 `ip link set dummy0 down/up` 时在 ≤ 3 s 内准确触发。
      - **局限（v1.3.1）**：`ip -6 addr change` 走 `inet6_addr_modify()`，只发一条带 DEPRECATED 的通知，**无法复现**内核 RA 路径的“清除/重置 DEPRECATED”消息对；该场景由 `tests/unit.c` 的三消息回放单测守护（§5.2.1 第 4 条）。
3. **生产主机复测项（明确与 mock 环境解耦）**：
   - mock 环境验证内存门禁、零写入、RA 零唤醒与双栈握手减半；
   - **单周期绝对耗时（22.5 ms → 8–12 ms）**、**glibc 真实 DNS/TLS 常驻 `MemoryCurrent`** 与 **24 h 真实 `CPUUsageNSec ≤ 1.5 s`** 在生产主机复测闭环。

---

<a name="s9" id="s9"></a>

## 09 实施里程碑（CPU 优先重排）

按“**先建立有效度量 → 先解决唯一现网超标项（CPU）→ 再消灭内存峰值 → 最后精简栈驻留**”重排 4 个阶段，**每个里程碑合入时同步回写 `docs/design.md`**：

| 阶段 | 包含需求 | 核心交付物 | 阶段退出门禁（全部必须通过） |
| --- | --- | --- | --- |
| **V1.3-M1：度量与工具链底座** | `REQ-01`、`REQ-08`（soak 部分） | `scripts/soak.py` 改 `token_file + 全量 CA + smaps [stack] Rss` 与 `netns`/`hosts` musl 模式；`Makefile` `OPT ?= -Os` / `OPT_VENDOR ?= -O2` 对比与 strip；`--version` 输出 `libc=`；`install.sh` 静态提示；用 Zig 0.13.0 构建 `0.0.1-rc2` musl 校准基线；同步回写 `design §13.1/§14.5` | ① `soak.py` 对改动前 glibc 代码**稳定标红**（`RssAnon`、`VmRSS`、`[stack] Rss` 均触发失败）；② musl 静态包能构建并跑通 `netns` mock soak；③ `spec-check` / `verify-units` / `test` 全绿 |
| **V1.3-M2：CPU 治理（优先止血）** | `REQ-07`、`REQ-08` | `nl_addr` 跟踪 `IFF_UP\|IFF_RUNNING` + 地址指纹表拦截 RA 刷新 + 无关接口过滤；`main` 二级本地快照比对（`carrier_changed` 绕过、跳过保退避）；`provider` 按族缓存 detect；`tls_http` 恢复 `i62` 默认 RSA 验签；`prov_cloudflare` 双栈 `A+AAAA` 合并 discover（含 `total_pages > 1` 回退）；`cycle end` 追加 `reason=`/`tls=`；同步回写 `design §05.2/§05.3/§05.4/§07.3/§08.1` | ① `socketpair` 单测与 `unshare` RA 压测 0 次多余 TLS 握手；② NAT `IFF_RUNNING` 翻转秒级触发；③ 双栈同域名每轮仅 1 次 Cloudflare discover；④ `test` / `test-asan` / `spec-check` 全绿；⑤ 生产复测 24 h 折算 CPU ≤ 1.5 s |
| **V1.3-M3：I/O 峰值消灭与堆治理** | `REQ-02`、`REQ-03`、`REQ-06` | `mn_checked_open()`；CA 4 KiB 流式解析 + `dn` 复用 + `1.5×` 扩容；token 576 B 栈读首行；配置单次精确读取；glibc `mallopt` + `malloc_trim(0)`；同步回写 `design §09.1/§09.2` | ① `soak.py` glibc `RssAnon` 从 644 KiB 降至 ≤ 420 KiB、`VmPeak` 降幅 ≥ 1.5 MiB；② 1 B/7 B/4096 B CA 跨块与 TOCTOU 单测全绿；③ `test-asan` + `valgrind` 零泄漏 |
| **V1.3-M4：栈物理驻留瘦身与收尾** | `REQ-04`、`REQ-05` | `struct app`、32 KiB netlink 缓冲、`struct mn_tls` 离栈（清零释放）并收窄局部头缓冲；`mn_addr_set` 周期化；HTTP 原地解析；按实测决定是否做 P2 项；同步回写 `design §08.1`、执行 `make doc` 与 `CHANGELOG.md` 更新 | ① `soak.py` 双轨门禁全绿（glibc `smaps [stack] Rss ≤ 32 KiB`、`RssAnon ≤ 320 KiB`、`VmRSS ≤ 2,458 KiB`；musl 达校准门禁）；② `test` / `test-asan` / `valgrind` / `spec-check` / `verify-units` 全绿；③ 8 平台 `make dist` 通过 |
| **V1.3.1：layer-1 DEPRECATED 归一化（勘误）** | `REQ-07` | `mn_nl_decode_addr()` 对 `ifa_prefered == 0` 的 IPv6 地址置 `IFA_F_DEPRECATED`，消除内核“清除/重置 DEPRECATED”消息对造成的逐 RA 漏判（§1.3）；单测回放现网三消息突发 | ① 新增单测修复前必红、修复后全绿；② `test` / `test-asan` / `spec-check` 全绿；③ 生产复测：RA 突发后不再出现 `debounce_ms` 之后的第二段活动，24 h 折算 CPU ≤ 2.0 s |

---

<a name="s10" id="s10"></a>

## 10 风险评估与缓解策略

| 风险 | 严重度 | 缓解策略 |
| --- | --- | --- |
| NAT 主机仅发生路由器重拨/链路闪断、本地 IP 未变时被 `REQ-07` 过滤漏触发 | 高 | `nl_addr` 跟踪 `IFF_RUNNING`，允许接口的 `IFF_UP` 或 `IFF_RUNNING` 翻转必置 `carrier_changed = 1` 并强制绕过二级快照跳过；兜底 `timerfd` 作为最终保险 |
| `event` 被跳过误清退避状态，导致失败记录停止重试 | 中 | 明确跳过路径仅清 `deb`、严禁触碰 `backoff_idx` / `retry_active` / `retry_due`，并由 `tests/unit.c` 守护 |
| 同域名 `A+AAAA` 合并 discover 遇到 TXT/MX 过多分页截断 | 中 | 查询带 `per_page=100`，解析 `result_info.total_pages > 1` 时自动回退为带 `type=` 的精确单查 |
| 动态分配引入内存泄漏或 UAF（`app`/`nl`/`tls`） | 中 | 统一成对编写分配/释放路径，TLS/token 释放前 `mn_secure_zero()`；强制通过 `make test-asan` 与 `valgrind --leak-check=full` |
| 流式 CA 解析在 PEM 边界跨 4 KiB 块时解析失败 | 中 | 依赖 BearSSL 原生流式 `br_pem_decoder_push()` 状态机，新增 1 B / 7 B / 4096 B 极端分块单测覆盖 |
| `-Os` 降低 BearSSL 大数运算速度导致单次 TLS 握手 CPU 升高 | 低 | 拆出 `OPT_VENDOR ?= -O2`，M1 实测 `-Os` vs `-O2` 握手耗时与二进制大小后再定型 |
| `mallopt(M_MMAP_THRESHOLD, 16384)` 在非 glibc 平台不可编译 | 低 | 严格隔离在 `#if defined(__GLIBC__)` 内，musl 路径零依赖 |
| 独立 netns (`unshare -rmn`) 在部分受限容器/CI runner 被禁 | 低 | `soak.py` 同时提供 `--mock-mode hosts` 回退路径（CI 使用 `sudo` 临时写 `/etc/hosts` + 443 端口） |
| 内核事件通知与 dump 路径对同一地址报告的 `IFA_FLAGS` 不一致（RA 更新时先清除再重置 DEPRECATED） | 高 | 解码时按 `ifa_prefered == 0` 归一化 DEPRECATED（§5.2.1 第 4 条），并用现网抓取的三消息突发做回归单测；生产验证以 `/proc/<pid>/syscall` 时间对齐确认不再触发 debounce |
