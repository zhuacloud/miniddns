# miniddns 设计文档审查报告

> 审查对象：`docs/design.md`（v1.1，1316 行）+ `docs/archive/design-v1.1.html`（原文快照，96 KB）
> 状态：**本报告的全部 40 项已在 `docs/design.md` v1.2 中修订完毕**，逐项对照见 §6
> 审查方式：全文精读、HTML↔MD 内容比对（token 级零缺失）、与 C/netlink/BearSSL/systemd 实际语义逐条对照、关键结论本机实测
> 审查日期：2025-11（对应文档 v1.1）
> 结论：**架构与安全基线扎实，可作为实现依据；但有 10 处会导致"实现出来是错的/装不上"的硬缺陷必须先修**

---

## 0. 总体评价

### 优点（值得保留的设计决策）

| 维度 | 评价 |
| --- | --- |
| 方法论 | "先打通风险最高的 TLS/CA，再写业务逻辑"（§15）与"实现者的两条建议"是全篇最有价值的部分，正确且罕见 |
| 正确性定义 | 把"IP 不变 → 零写入"当作可验收的核心不变量（§01/§14.4/§14.5/附录 A.5），而不是口头约定 |
| 记忆体纪律 | §09.2 内存所有权表、§09.3 arena、§08.1 "不 malloc"、§14.5 RSS 门禁，四者互相闭合 |
| 加固清单 | §12.1 的 `PrivateNetwork` / `AF_NETLINK` 两条禁忌说明来自真实踩坑经验，应保留 |
| 可扩展性论证 | §07.5 用差异矩阵反证 vtable 设计（`id` 用字符串、`update()` 收 `cur`、core 不假设 GET 存在）是有效论证，不是空话 |
| 附录常量 | A.1（`RTM_*`/`RTNLGRP_*`/`IFA_*`）与 A.2（`IFA_F_*` 位值）逐条核对，**数值全部正确** |

### 问题统计

| 级别 | 含义 | 数量 |
| --- | --- | --- |
| **P0** | 照文档实现必然产生错误行为或装不上，必须改文档 | 10 |
| **P1** | 内部矛盾/规格缺口，实现者必须自行发明语义（会产生分歧） | 18 |
| **P2** | 文档质量、完备性、可维护性 | 12 |

### 结构性问题（跨章节）

1. **"唯一依据"与"自行发明"并存**：文档自称实现唯一依据，但 `struct mn_provider`、`MN_IP_STRLEN`、`mn_cfg` 三个核心类型从未定义（只在函数签名里出现），`--dry-run`/`--once` 冲突规则、重定向白名单键名、chunked 处置策略等关键语义缺失。实现者被迫自创，与"唯一依据"直接冲突。
2. **"冻结"与"矛盾"并存**：至少 6 处硬性条款互斥（下详），冻结状态需要靠"能自洽"支撑。
3. **安全条款过强导致不可用**：§03 的 `O_NOFOLLOW` + 属主 root + 拒符号链接三件套，在 RHEL/Alpine 的 CA 路径、systemd `User=` 非 root 模式、多实例软链三种正常运维形态下都会直接失败（P0-4、P1-14）。

---

## 1. P0：必须修复（否则实现即错）

### P0-1 `record_id` 预置与"IP 不变零写入"根本冲突，且伪代码会误创记录

**位置**：§04 L304、§05.4 L418-421、§07.1 L541、§14.2 L1141、§16 L1218

**问题**：
```c
remote = rec.record_id
         ? { .id = rec.record_id, .known = false }   /* found 隐式为 0 */
         : provider_discover(rec);
if (!remote.found) { if (!rec.create_if_missing) skip; create ... }
```
1. `found` 未赋值 → 0 → 伪代码走 **create** 分支。CF 侧会返回"记录已存在"错误，每轮 cycle 都报一次。
2. 更要紧的是：跳过 discover 后，进程**不知道远端 content**。而"不写状态文件"（§01）意味着它没有任何缓存手段。于是唯一可行的实现是"每轮都 PATCH"——这直接违反 §01/§14.4/A.5 的"IP 不变时写请求数为 0"。
3. §16 L1218 却把"填 `record_id`"作为缓解"CF 缓存导致重复写"的建议，方向正好相反。

**影响**：核心正确性不变量失效；soak 测试（§14.4，`interval_fallback=60`）会得到 1440 次写入而非 0。

**建议**（三选一，需在文档中明确）：
- (A) **删除 `record_id` 配置项**，discover 永远执行（最简单，且与不变量自洽）；
- (B) `record_id` 仅作为"首次 discover 失败时的兜底 id"，即仍做一次 discover 学习 content，后续用已知 id；
- (C) 允许 `record_id` + 进程内存缓存（`last_applied_ip`），并**明确承认**：重启后首轮必写 1 次、`--once` 必写 1 次，从而把不变量改写成"稳态 24 h 内写入 ≤ 1 次"。

同时修 §05.4 伪代码：`remote.found` 必须显式赋值，`known == false` 时必须定义比较语义。

---

### P0-2 `ipv6_mode` 的默认值不在允许值集合内

**位置**：§04 L269（默认 `auto`，枚举 `off | iface`）

**影响**：配置校验器（§04 要求未知值硬错误）会拒绝自己的默认值——**不写 `ipv6_mode` 的用户全部启动失败**。

**建议**：默认改 `iface`，或在枚举中加入 `auto`（并定义 `auto` 对 IPv6 的含义，例如"有 global 地址即用，无则视为 none"）。

---

### P0-3 `LoadCredential=` 让全新安装 100% 启动失败，且与"多 provider"结构性冲突

**位置**：§12.1 L862、§12.3 L929-935、§04 L289-292

**问题**：
1. 单元里写死 `LoadCredential=cloudflare.token:@CONFDIR@/cloudflare.token`。当源文件不存在时**单元启动即失败**（本机实测：`status=243/CREDENTIALS`）。而 §12.3 明确要求 `install.sh` **不得创建** token 文件、不得覆盖已有 token，§12.3 还要求"不自动 enable"——于是用户按文档操作 `systemctl enable --now` 后必然拿到 `243/CREDENTIALS`，且日志里没有任何 miniddns 输出，排障方向完全错误。
2. `[provider]` 可重复，`token_file` 名称/路径由用户自定，但单元只能列固定的 `LoadCredential` 行。多 provider 或多实例时无法表达。
3. 同理，`$CREDENTIALS_DIRECTORY` 未定义时程序"报错"（§04），使 `--check-ca` 在 systemd 之外必然失败（另见 P1-13）。

**建议**：
- 单元默认**不写** `LoadCredential`，改为注释示例 + 文档说明"若要使用凭据目录，为每个 provider 各加一行 `LoadCredential=<id>.token:/path`"；
- 或使用 `LoadCredential=cloudflare.token:-/etc/miniddns/cloudflare.token` 形式的**可选**语义（systemd v253+ 支持 `-` 前缀表示缺失不致命），并在文档中标注最低版本；
- `install.sh` 增加一步：若选择凭据模式则创建空的 0600 占位文件（与"不覆盖已有"不冲突）。

---

### P0-4 `O_NOFOLLOW` + 拒绝符号链接 会打死多数发行版的 CA 路径与常见运维形态

**位置**：§03 L216-230，与 §03 CA 查找顺序 L205-212、§12.2 方案 A L905-917、§16 多实例 L1223 冲突

**问题**（三处独立冲突）：
1. **发行版 CA 路径本身就是符号链接**：RHEL 系 `/etc/pki/tls/certs/ca-bundle.crt` → `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`；Alpine 的 `/etc/ssl/cert.pem` 与 `/etc/ssl/certs/ca-certificates.crt` 互为链接（方向因版本而异）。§03 把这两个路径列为优先级 5/6 → 在这两类系统上**必然拒绝启动**。
2. `--config` 显式路径若为符号链接也被拒（规则写的是"打开配置文件、CA bundle、token 文件之前"一律），而多实例部署的常规做法正是 `/etc/miniddns/miniddns.conf -> instances/home.conf`。
3. §12.2 方案 A 的 `/usr/local/bin/miniddns` 与 `/opt/miniddns` 都是符号链接——虽然这条走 `/proc/self/exe` 不受影响，但文档同时建立"符号链接=危险"与"符号链接=推荐部署"两种语境，缺一句边界说明会误导实现者把 `readlink` 也加上限制。

**建议**：分级而不是一刀切：
| 对象 | 策略 |
| --- | --- |
| token 文件 | 保留 `O_NOFOLLOW`（合理，凭据不该被重定向） |
| 配置文件 | 允许符号链接，但 `realpath()` 后校验目标（属主 root、非全局可写、`S_ISREG`、大小上限） |
| CA bundle | **必须**允许符号链接（否则多发行版不可用），同样校验解析后的目标 |

---

### P0-5 §08.2 的请求示例用 `POST` 做更新，与"只允许 PATCH、禁止 PUT"正面冲突

**位置**：§08.2 L648（`POST /client/v4/zones/{zone}/dns_records/{id}`）vs §07.3 L592 / §01 L50

**影响**：§08.2 是"HTTP 客户端怎么写"的唯一模板，实现者照抄会发出 `POST .../dns_records/{record_id}`——CF 无此语义（会 404/405），且破坏了"§08 是传输层、不含 provider 语义"的分层（方法被硬编码在示例里）。同时 §14.2 要求"断言只发 PATCH"，与示例矛盾。

**建议**：示例改为 `PATCH`，并明确"方法由 provider 传入，示例以 CF update 为例"。

---

### P0-6 `interval_fallback = 0`（禁用）时，失败退避定时器被算成 0 → 永不重试

**位置**：§05.5 L440：`timerfd` 重新设定为 `min(backoff, interval_fallback)`

**影响**：`interval_fallback = 0` 是文档允许的配置（§04 L253，"不推荐"但合法）。此时 `min(backoff, 0) = 0` → `timerfd_settime` 归零 → 定时器解除武装 → 一次失败后**永久不再重试**，且没有任何日志说明。这与"不推荐但支持"的定位矛盾（实际是"支持但会静默瘫痪"）。

**建议**：显式写出 `interval_fallback == 0 ? backoff : min(backoff, interval_fallback)`，并在 §04 对 `0` 补充"失败退避仍然生效"。

---

### P0-7 日志级别用单词前缀，journald 不识别（实测）；且"稳态 2 行"与逐记录日志矛盾

**位置**：§10.1 L775-781、§10.2 示例、§10.3 L800-802 vs §05.4 L428

**问题 1（实测）**：单元文件未设 `StandardError=`，默认 `inherit`，stdout/stderr 合并到同一条 journal stream，默认 `PRIORITY=6`。日志行首写 `error`/`warn` 这类**单词**，journald 不会据此设优先级——本机实测：

```
PRIORITY=6  hello-stdout
PRIORITY=6  hello-stderr      ← 写 stderr 也还是 6
PRIORITY=3  <3>hello-prefixed ← 只有内核式数字前缀生效
```

后果：`journalctl -p err -u miniddns` 永远为空，`LogLevelMax=`/`SystemMaxUse` 按级别过滤全部失效，§10 声称的"面向 journald"不成立。

**问题 2（内部矛盾）**：§10.3 说稳态每周期"只产生 2 行 info（cycle start/end）"，但 §05.4 的伪代码对**每条记录**都打 `action=unchanged`（info 级）。2 条记录 → 每 900 s 4 行，与"2 行"不符，也与"噪声控制"目标冲突。

**建议**：
- 格式改为 `<N> miniddns: ...`（`<3>` error / `<4>` warn / `<6>` info / `<7>` debug），并保留可 grep 的 `level=` 字段以便 `-g 'level=error'`；或在单元中显式 `StandardOutput=journal` + 使用 `sd_journal` 协议（不推荐，引入 libsystemd 依赖，与"零依赖"冲突）。
- `action=unchanged` 降为 `debug`，或把 §10.3 改成"每周期 2 + N 行（N = 记录的 unchanged 条数）"。

---

### P0-8 用 `IFA_LABEL` 取接口名：IPv6 根本没有这个属性

**位置**：§05.2 L389、附录 A.1 L1246

**问题**：`IFA_LABEL` 只有 IPv4 地址消息才带。IPv6 的 `RTM_NEWADDR` 通常只有 `IFA_ADDRESS`/`IFA_LOCAL`/`IFA_FLAGS`/`IFA_CACHEINFO`，要拿接口名必须 `if_indextoname(ifa_index)` 或订阅 `RTM_GETLINK` 建 index→name 表。

**影响**：照文档实现 → IPv6 的 `iface_include`/`iface_exclude` 永远拿不到名字 → 过滤静默失效 → `iface_exclude=lo,docker0,...` 在 IPv6 侧完全不生效（会把 `docker0`/`wg0` 的 IPv6 发上去）。

**建议**：解码内容改为"`ifa_index` → `if_indextoname()`；`IFA_LABEL` 仅作 IPv4 的冗余校验"，并在 §14.1 增加一条 IPv6 无 `IFA_LABEL` 的样例。

---

### P0-9 未规定"接口 down 时其地址必须被排除"

**位置**：§05.2 L388（只提到订阅 `RTNLGRP_LINK` "重新评估"）、§06.2/§06.3 过滤条件

**问题**：内核在 link down 后**不会**删除地址，`RTM_GETADDR` dump 仍然返回这些地址，且 `ifa_flags` 不含表示"接口 down"的位。若不检查 `IFF_UP`（来自 `RTM_GETLINK`/`SIOCGIFFLAGS`），`ip link set eth0 down` 之后 cycle 仍会把老地址当候选发布——与 §14.3 期望的"cycle 记 `no-ip` 并跳过"**完全相反**。

**建议**：§06.3 的候选条件增加"所在接口 `IFF_UP` 且（可选）`IFF_RUNNING`"；§05.2 说明需维护 index→flags 缓存并在 `RTM_NEWLINK` 时刷新；§14.3 增加"link down 后探测返回 none"的断言。

---

### P0-10 `Transfer-Encoding: chunked` 未定义处置，"否则读到 EOF"会静默产生垃圾 body

**位置**：§13 L88、§08.3 L665-668、§08.3 L672

**问题**：文档同时说"不需要 chunked"（设计选择）与"无 `Content-Length` 则读到 EOF"（实现要求）。二者组合的结果是：遇到 chunked 响应时，body 里混入 `1a2b\r\n...` 的块长度行，JSON 解析失败 → `E_PARSE` → 最大退避档重试 → 永远失败。CF 与其前置代理在部分响应（尤其错误页/大响应）确实会用 chunked。

**建议**：明确二者之一：
- **拒绝**：响应头出现 `Transfer-Encoding`（非 `identity`）→ 立即 `E_PARSE` 并在日志写明 `reason=chunked_unsupported`（诚实、可排障）；并建议 `Accept-Encoding: identity` 且**不发** `Accept-Encoding`（当前未实现解压，gzip 响应同样会炸）。
- **支持**：实现 20 行左右的最小 chunked 解码（只处理长度行 + CRLF + 结束块），把 §14.1 的 `http_parse` 用例补上 chunked 分块到达。

---

## 2. P1：应修复（规格缺口 / 内部矛盾）

| # | 位置 | 问题 | 建议 |
| --- | --- | --- | --- |
| P1-1 | §05.2 L383 vs L388 | 订阅组只写 `IPV4_IFADDR｜IPV6_IFADDR`，正文又要求订阅 `RTNLGRP_LINK`（且 A.1 把它列出来了）：位掩码到底含不含 LINK，两处不一致 | 位掩码明确写 `(1<<(RTNLGRP_LINK-1))｜(1<<(RTNLGRP_IPV4_IFADDR-1))｜(1<<(RTNLGRP_IPV6_IFADDR-1))` |
| P1-2 | §05.2 L386 | `SO_RCVBUF = 1 MiB` 无 `CAP_NET_ADMIN` 时受 `net.core.rmem_max` 限制（本机 212992 → 实际约 416 KiB，且内核内部翻倍），`setsockopt` 不报错 | 说明"读回 `getsockopt` 校验实际值，达不到就降级 warn `rcvbuf_actual=`"；1 MiB 仅在 sysctl 调整后成立 |
| P1-3 | §03 L169 vs §13.3 L1058-1065；L169/650/785 vs L908 | artifact 布局（`miniddns-1.0.0-...`，无 `systemd/`、`openwrt/`、`install.sh`、`SHA256SUMS`）与 dist 布局不一致；版本号 `1.0.0`/`1.1.0` 混用 | 让 §03 引用 §13.3（单一事实源），版本号统一为 `$(VERSION)` 占位 |
| P1-4 | §04 L251/261 vs §16 L1223 | `lock_file` 默认路径不含 `instance`，但 §16 声称"用 instance + lock 支持多实例"→ 第二个实例必然 flock 失败 | 默认改 `<RUNTIME_DIRECTORY>/<instance>.lock`；或删除"多实例"表述 |
| P1-5 | §12.4 L947-953 vs A.4 L1283-1285、§03 L218 | 非 root 模式要求 token `0640 root:miniddns`，但配置按 A.4 是 `0640 root:root` 且 §03 校验属主必须 root → `User=miniddns` 读不到配置；另外 §12.4 承诺的 `systemd/miniddns@user.service.d/override.conf` 在 §02 骨架、§13.3 dist 布局里都不存在 | 给非 root 模式一套完整权限表（conf/token 均 `0640 root:miniddns`），并把 override 文件纳入 §02/§13.3 |
| P1-6 | §04 L257 vs §12.1 L849 | `log_target=file` + `log_file=<任意路径>`，在 `ProtectSystem=strict` 下不可写（仅 `RuntimeDirectory`/`StateDirectory`/`LogsDirectory` 等被豁免，任意路径不豁免） | 要求 `log_file` 落在 `LogsDirectory=miniddns`（`/var/log/miniddns`）或加 `ReadWritePaths=`；并说明 `RuntimeDirectory` 已被豁免（lock 文件是安全的） |
| P1-7 | §06.1 L466-471 | 前缀表不完整：IPv4 缺 `192.0.0.0/24`、`255.255.255.255/32`；IPv6 缺 `::ffff:0:0/96`（v4-mapped）、`64:ff9b::/96`（NAT64）、`fec0::/10`（旧 site-local）、`100::/64`；"可发布=其余全局单播"与"IPv6 其余全局单播（2000::/3）"表述重叠 | 补全前缀；把 IPv6 规则写成"必须在 `2000::/3` **且**不在排除表内"，避免实现者二选一 |
| P1-8 | §06.2 L482、§08.3 L672 | "host 在白名单内"——配置里没有白名单键，白名单来源未定义；也未限制端口 | 明确白名单 = `ipv4_echo_url` 中出现过的 host 集合，且仅允许 `:443`/默认端口；3 跳后仍不合法 → `E_HTTP_STATUS` |
| P1-9 | §04 L246 | "同一 `[record]` 内 `(provider, name, type)` 必须唯一" 措辞错误：单个 section 内本来就不会重复；真正要防的是**跨所有 `[record]` 全局唯一**（否则两条配置争抢同一条远端记录，出现"A 写 1.1.1.1、B 写 2.2.2.2"来回抖） | 改为"跨全文所有 `[record]` 必须唯一，报错给两处行号" |
| P1-10 | §05.5 L444 vs §08.4 L683 vs A.3 | 错误码命名不一致：`E_HTTP_4XX`（§05.5）vs `E_HTTP_STATUS`（§08.4/A.3）；A.3 未给数值定义（`enum` 顺序会影响日志比较） | 统一为 `E_HTTP_STATUS` + 细分字段 `http_status=4xx`，A.3 补 `#define` 值 |
| P1-11 | §07.1 L532-542、§07.2 L559 | `struct mn_provider`、`struct mn_cfg`、`MN_IP_STRLEN` 均**从未定义**；`changed_by_us` 是恒 0 的死字段；`id[64]` 未说明空 id 语义（RFC2136 无 id） | 补 3 个类型定义与常量（建议 `MN_IP_STRLEN 46`、`MN_FQDN_MAX 254`）；删除 `changed_by_us`；说明 `id[0]=='\0'` 表示"厂商无 id" |
| P1-12 | §09.1/§09.2 L712-736 | BearSSL 关键细节缺失：DN 必须使用 `br_x509_decoder_get_dn()` 返回的 **BearSSL 原始编码**（32 位大端长度前缀 + DER，4 字节对齐），不是普通字节串；`append_dn` 是**分块多次回调**，需可增长缓冲；arena 用 `realloc` 扩容会让已就位的 `br_x509_trust_anchor[]` 内指针失效 | 明确"两段式布局"：先收集 `(dn_off, dn_len, key_off...)`，最后一次性定长分配并回填指针；补 `append_dn` 的分块追加语义 |
| P1-13 | §09.6 L752-768、§11 L829、§04 L289-292 | `--check-ca`/`--check-config` 在 systemd 之外运行（打包验收、`postinst`、`ExecStartPre`）时 `$CREDENTIALS_DIRECTORY` 未定义 → 按 §04 规则"报错" → 自检必然失败，而这正是它要防的场景 | 诊断子命令对 `CREDENTIALS_DIRECTORY` 缺失降级为 `warn` 并跳过 token 校验（反正本就不发带 token 的请求） |
| P1-14 | §12.1 L845-866、附录 A.5 L1291 | 单元用到 `ProtectProc=invisible`（v247+）等较新键；在 Debian 10 / Ubuntu 20.04（systemd 241）上 `systemd-analyze verify` 会告警，与 A.5"verify 无报错"的门禁冲突 | 声明最低 systemd 版本（建议 ≥ 248）与降级行为；A.5 门禁改为"在目标版本上 verify 无 error" |
| P1-15 | §13.1 L1000-1040 | Makefile 片段不可编译：只定义 `CSTD/WARN/HARDEN/OPT/INC` 而**没有 `CFLAGS`**（隐式规则不会用这些变量）；`build/%.o` 无模式规则与 `mkdir -p $(@D)`；`make static` 覆盖 `LDFLAGS` 时对象仍以 `-fPIE` 编译（静态链接应 `-fno-pie` + `-no-pie`）；§13.3 要求的 `ca-refresh` 目标、§14.1 的 `test`、§14.6 的 `test-asan` 均未定义 | 补 `CFLAGS` 汇总、`build/%.o` 规则、`mkdir -p`、`static` 的 PIE 处理，以及 `test`/`test-asan`/`ca-refresh`/`verify-units` 目标 |
| P1-16 | §11 L832-835 vs §14.3 L1168 | 诊断命令不取 flock，但 `--once` 会**真实写远端**：可与运行中的守护进程并发写同一记录 | `--once` 取 lock（失败则报错退出码 1），`--dry-run`/`--print-ip`/`--check-*` 不取 |
| P1-17 | §01 L42-46 vs §04 L253 / §05.3 L409 / §08 | "idle CPU 严格为 0 / 绝无每 N 分钟跑一次的主循环"与 `interval_fallback=900` 的周期性完整 cycle（含全量 dump + discover GET）语义矛盾；"≤3 s 发出更新"与 `debounce` 硬上限 `10×=15 s`、`http_timeout_ms=8000` 也矛盾 | 改写为"无常驻轮询；仅有低频兜底 timer（默认 15 min），且兜底周期只读不写（IP 未变）"；响应性目标限定为"事件 → 首个请求发出 ≤ 3 s，不含超时重试与 10× 兜底窗口" |
| P1-18 | §12.6 L958-962 | procd 脚本要点缺两条：OpenWrt 上 `--check-ca` 的调用时机；OpenWrt 的 CA 由 `ca-bundle` 包提供（需 `DEPENDS`），否则 §09 的 CA 探测全部落空且无可用锚点 | 补 `DEPENDS:=+ca-bundle` 与 `START=99` 之后的 `miniddns --check-ca` 建议；说明 OpenWrt 无 `systemd-analyze` 等价门禁 |

---

## 3. P2：文档质量与完备性

### P2-1 Markdown 残留 HTML 实体（4 处，渲染后可见 `&gt;`）

| 行 | 现状 |
| --- | --- |
| L496 | `` `IFA_CACHEINFO.ifa_valid` &gt; 0 `` |
| L591 | `0 条 → found=0；&gt;1 条 → log warn` |
| L748 | `最早到期 &lt; 90 天` |
| L1161 | `RSS 波动 &lt; 64 KB` |

转换脚本应把 `&gt;`/`&lt;`/`&amp;` 还原（同时在 `<br>`、`\|` 处做一次回归检查）。

### P2-2 §13.4 L1105 疑似抽取损坏

> `不要链接 alert 依赖的 libustream`

"alert 依赖"不成句，疑为原文"任何 OpenWrt 专有/别名依赖"或类似表述被 HTML 抽取破坏。参考文献应回查 `docs/archive/design-v1.1.html` 对应段落（本次 token 级比对未发现缺失，说明是原文即如此或抽取时发生了词形替换，需要人工确认）。

### P2-3 缺少顶层项目文档（当前仓库只有 `docs/`）

| 缺失文件 | 为什么必须有 |
| --- | --- |
| `README.md` | 现状：外部读者无法从仓库得知这是什么、处于什么阶段（文档自述"设计冻结，待实现"）。应含：一句话定位、状态徽章（design/spec-only）、`--print-ip` 三分钟试用路径、指向 `docs/design.md` |
| `LICENSE` | 项目自身许可未定。**且** vendor 了 BearSSL（MIT）与 jsmn（MIT），MIT 要求随分发保留版权与许可声明 |
| `THIRD_PARTY_NOTICES.md` | 同上；§13.3 的 dist 布局里**没有** licenses 目录 → 现在按文档打包会直接违反两上游的 MIT 条款 |
| `CHANGELOG.md` | 文档已有"修订记录"表，但规格变更与代码变更需分开；且 §04"未知 key 硬错误"使新增配置项成为**破坏性变更**，必须有版本兼容说明 |
| `.gitignore` | `build/`、`dist/`、`*.token`、`conf/miniddns.conf` 应默认忽略（与 §13.3 的 dist 断言呼应） |
| 表头声明 | 明确"`design.md` 为唯一权威、`design-v1.1.html` 仅作原始快照存档"，避免双份漂移（v1.2 已加） |

### P2-4 `design.html` 的溯源不可复现

表头把来源写成 `http://119.29.168.148/pub/report/miniddns-design.html`：内网明文 HTTP 地址，不可长期访问、不可校验。建议在元信息表补 **`sha256` + 抓取时间 + 抓取工具**，并把 HTML 移到 `docs/archive/`，在文件名体现版本（`design-v1.1.html`）。

### P2-5 目录锚点依赖 `<a id>`，可移植性有限

`<a id="s1"></a>` 在 GitHub/GitLab 可用，但在部分渲染器（某些 pandoc 配置、IDE 预览、静态站点生成器）会被剥掉 `id`，目录全部失效。建议改为"标题自动锚点 + 目录指向 `#01-目标与非目标` 之类"，或同时保留 `<a name>`（更老的兼容面）。

### P2-6 日志格式缺转义规则

§10.1 只说"值含空格或特殊字符时用双引号包裹"，未定义值内含 `"`、`\`、换行时的处理。而 `api_msg` 来自远端 JSON（jsmn 返回的是**含转义的原始切片**，不自动 unescape），很可能带引号。建议：值内 `"` → `\"`、`\` → `\\`、换行 → `\n`；并说明 `api_msg` 是否需要 unescape（建议原样输出 + 截断到 200 字符，避免多行日志被 journald 拆条）。

### P2-7 §11 CLI 语义缺口

- `-1` 与 `-n` 同时出现：谁优先？（建议 `--dry-run` 隐含 `--once`，同时给出 `-n` 覆盖 `-1` 的确定性规则）
- `--print-ip`/`--check-ca` 是否仍需要 `-c` 配置（前者需要 detect 配置，后者需要 provider 端点）：配置缺失时的退出码与提示未定义。
- `--version` 要打印"BearSSL 版本、jsmn、是否静态"——需说明如何获得（编译期宏注入 vs `strings`）。

### P2-8 §14 测试清单缺口

| 缺的用例 | 理由 |
| --- | --- |
| `debounce` 硬上限（连续事件 → 15 s 后强制执行） | §05.3 的核心防抖动逻辑，纯状态机，易测且易写错 |
| 日志折叠（`repeat=10`）与"周期结束时冲刷余数" | §10.3 无对应测试，折叠 bug 会吞掉真实变更 |
| `install.sh` 幂等性（已存在 conf/token 不被覆盖；重复执行不产生重复单元） | §12.3 三条硬要求零测试 |
| `make dist` 禁用文件断言（`*.token`/`miniddns.conf` 不存在）+ `SHA256SUMS` 覆盖全树 | §13.3 的强制条款应被 CI 守护，而非人工检查 |
| CA 为符号链接 / 配置为符号链接（P0-4 修复后） | 当前规则与发行版现实冲突，必须有用例锁定最终决策 |
| chunked 响应（P0-10 决断后） | 决定"拒绝"也要有断言 `reason=chunked_unsupported` |
| `interval_fallback=0` + 失败 → 仍按退避重试（P0-6） | 极容易被忘掉的边界 |
| 多记录部分失败（一条失败不影响其余，`ok=/fail=` 计数正确） | §05.4"逐条独立成败"无测试 |

### P2-9 §06.1 前缀写法风格不统一

`10/8`、`172.16/12`、`192.168/16` 与 `192.0.2/24`、`198.18/15` 混用省略写法，实现者容易误读（尤其 `172.16/12` 而非 `172.16.0.0/12`）。建议统一为完整 CIDR。

### P2-10 §13.3 的 `miniddns.service` 与 `.service.in` 双份入库存在漂移风险

修订记录说两者都算源码，但成品是"按默认 PREFIX 生成"的产物——入库产物必然与模板不一致（改模板忘重生成）。建议：成品不入库，只在 dist 阶段生成；或加 `make verify-units`（重新生成后 `diff`），并纳入 CI。

### P2-11 规格与实现的一致性回写机制缺失

文末声明"与实现冲突时以规格正文为准并回写修订"，但没有定义回写流程（谁改、何时 bump 版本、修订记录格式）。建议补一节"规格变更流程"：`PATCH` 级改动记入 CHANGELOG，破坏性改动（新增/删除配置项、错误码、日志字段）bump minor 并更新 §04 的兼容性说明。

### P2-12 文档长度与读者分层

1316 行、单文件、三种读者（决策者/实现者/运维）混排。建议拆分或加阅读路径：

| 读者 | 建议读 |
| --- | --- |
| 评审/决策 | §01、§16、附录 A.5 自查清单 |
| 实现者 | §02-§09 + §13.1 + §14.1 |
| 运维/打包 | §03、§11、§12、§13.3、§14.5 |

---

## 4. 已验证正确的部分（说明审查覆盖面）

| 项 | 核对结果 |
| --- | --- |
| A.1 `RTM_*`（NEWADDR=20 / DELADDR=21 / GETADDR=22 / NEWLINK=16 / DELLINK=17） | ✅ 与 `linux/rtnetlink.h` 一致 |
| A.1 `RTNLGRP_LINK=1`、`IPV4_IFADDR=5`、`IPV6_IFADDR=9`、`IPV6_PREFIX=11` | ✅ 一致；`1<<(n-1)` 位掩码写法正确（均 < 32，`nl_groups` 可容纳） |
| A.2 `IFA_F_*` 全部位值（0x01/0x02/0x04/0x08/0x10/0x20/0x40/0x80/0x100/0x200） | ✅ 与 `linux/if_addr.h` 完全一致 |
| §05.2 "先 bind 再 dump"、`nlmsg_seq` 区分、`ENOBUFS → 全量重扫` | ✅ 这是正确且常被写错的 netlink 用法 |
| §06.4 确定性排序、§06.5 规范化比较（禁止 `strcmp` 处理 `::`） | ✅ 逻辑正确，能真正防抖动 |
| §07.3 只 PATCH `content`、禁 PUT；`success` + HTTP 2xx 双判定 | ✅ 与 CF 语义一致 |
| §09.2 所有权表（DER 存活期、DN/pkey 深拷贝、不保留全量 DER） | ✅ 判断准确（唯一的缺口是 BearSSL 的 DN 编码格式，见 P1-12） |
| §08.1 BearSSL 算法/哈希/时间/信任锚显式注册清单 | ✅ 覆盖了 `br_x509_minimal` 的必填项（签名函数 API 名有小幅简写，不影响语义） |
| §12.1 `AF_NETLINK` 必须放行、`PrivateNetwork=yes` 禁用 | ✅ 是真实且高频的加固陷阱 |
| §05.1 `signalfd` 替代信号处理函数 | ✅ 单线程事件循环下的正确选择 |
| §13.2 体积预算（业务 60-90 KB + BearSSL 120-200 KB + jsmn 5 KB → 250-400 KB < 500 KB） | ✅ 量级合理 |

---

## 5. 建议的修复顺序

```
第一轮（阻塞实现，必须先改文档）
  P0-2  ipv6_mode 默认值          ← 1 行改动，但会让所有人装不上
  P0-1  record_id 语义            ← 需要做设计决策（A/B/C）
  P0-5  §08.2 示例改 PATCH
  P0-3  LoadCredential 可选化
  P0-4  符号链接分级策略
  P0-6  退避定时器 0 语义
第二轮（会在实现期反复踩坑）
  P0-8  if_indextoname
  P0-9  IFF_UP 过滤
  P0-10 chunked 决断
  P0-7  日志级别前缀 + 稳态行数
  P1-1..P1-6、P1-9..P1-11
第三轮（可运维性与文档）
  P1-7、P1-8、P1-12..P1-18
  P2-1..P2-12
```

修复完成后建议做一次**规格自洽性检查**（可作为 CI 的一部分）：

1. 所有 `[section].key` 的默认值必须属于该 key 的允许值集合（能自动抓出 P0-2）。
2. 所有 `§x.y` 交叉引用必须存在且标题匹配。
3. 所有出现过的类型名/常量名/错误码必须在正文或附录有定义（能自动抓出 P1-11）。
4. 配置文件与单元文件中的路径必须都是安装脚本会创建的路径（能自动抓出 P0-3）。

---

## 附录：本报告中的实测证据

环境：本机 Linux（systemd user manager，kernel 默认 `net.core.rmem_max`）。

**A. journald 日志级别（对应 P0-7）**

```bash
systemd-run --user --unit=mnddns-jtest --wait --collect \
  /bin/sh -c 'echo hello-stdout; echo hello-stderr >&2; echo "<3>hello-prefixed"'
journalctl --user -u mnddns-jtest -o json | jq -r '.PRIORITY + " " + .MESSAGE'
# 6 hello-stdout
# 6 hello-stderr
# 3 hello-prefixed
```

结论：`StandardError` 默认 `inherit`，stdout/stderr 同为 `PRIORITY=6`；只有 `<N>` 数字前缀改变优先级，单词 `info`/`error` 无效。

**B. `LoadCredential` 指向不存在的绝对路径（对应 P0-3）**

```bash
systemd-run --user --unit=mnddns-credtest --wait --collect \
  -p LoadCredential=cloudflare.token:/nonexistent/token /bin/true
# Main processes terminated with: code=exited, status=243/CREDENTIALS
```

结论：绝对路径形式的凭据缺失即启动失败（`man systemd.exec`：仅"未指定路径"或"给定有效凭据标识符"两种情形下缺失不致命）。

**C. `SO_RCVBUF` 上限（对应 P1-2）**

```bash
cat /proc/sys/net/core/rmem_max      # 212992
```

结论：请求 1 MiB 无 `CAP_NET_ADMIN`（不能用 `SO_RCVBUFFORCE`）时会被钳到约 2×212992 ≈ 416 KiB，`setsockopt` 不报错——必须读回校验。

---

*审查结论：`docs/design.md` 的设计判断整体可信，但 v1.1 尚不能作为"唯一实现依据"——P0 级 10 项中至少 4 项会让实现产物在标准环境上直接不可用（P0-2、P0-3、P0-4、P0-7）。建议按第 5 节顺序修订后发布 v1.2 并重新冻结。*

---

## 6. 修订对照表（v1.1 → v1.2）

全部 40 项均已落到 `docs/design.md` v1.2。破坏性变更的动机与影响面另见 `CHANGELOG.md`。

### P0（10 项，全部已修）

| # | 处置 | 落地位置 |
| --- | --- | --- |
| P0-1 | **删除 `[record].record_id`**；新增 `[core].write_memo_ms` 作为"减少重复写"的替代；伪代码改为每轮必 discover、显式赋值 `found`、`unchanged` 降为 debug | §04 `[record]` 强制 callout、§05.4 + 新增 §05.4.1、§07.1、§14.2、§16、附录 A.0 |
| P0-2 | `ipv6_mode` 默认改 `iface`，枚举明确去掉 `auto`；补"默认值必须属于枚举"的校验要求与测试 | §04 `[detect]`、§06.3、§14.1 `cfg`、§14.6 自洽检查 |
| P0-3 | `LoadCredential=` **默认注释**并说明失败模式（`243/CREDENTIALS`）；`token_file`/`token` 二选一并给出诊断路径降级规则；`install.sh` 增加"不创建 token 但提示"与启动前自检 | §12.1、§12.3、§04 `[provider]`、附录 A.5 自查清单 |
| P0-4 | 符号链接策略**分级**：token 禁跟随、conf 允许但校验 `realpath` 目标、CA 必须允许并限制白名单目录 | §03「文件权限与符号链接策略」、§09.4、§14.3 注入用例 |
| P0-5 | §08.2 请求模板改 `PATCH`，并规定"方法/路径/Host 由调用方传入" | §08.2 |
| P0-6 | 退避定时器公式显式区分 `interval_fallback == 0`，并禁止 delay=0 | §05.5、§14.1 `backoff` |
| P0-7 | 日志改为 `<PRI>miniddns: … level=…`，附实测证据；`action=unchanged` 降 debug，稳态行数改为可度量断言 | §10.1/§10.2/§10.3、§12.1 `StandardOutput=`、§14.4、§14.6 |
| P0-8 | 接口名一律 `if_indextoname(ifa_index)`，`IFA_LABEL` 降为"仅 IPv4、冗余校验"；补专项测试 | §05.2、§06.3、附录 A.1、§14.1 `ipv6_filter` |
| P0-9 | 候选地址强制 `IFF_UP` 过滤；启动时额外 `RTM_GETLINK` 建 ifindex 表；补注入用例 | §06.2、§06.3、§05.2、§14.1 `iface_up`、§14.3 |
| P0-10 | **必须实现最小 chunked 解码**；`Content-Encoding` 非 identity 直接 `E_PARSE reason=encoded_body`；禁发 `Accept-Encoding` | §08.3、§08.4、§14.1 `http_parse`、§14.2 mock 用例 |

### P1（18 项，全部已修）

| # | 处置 | 落地位置 |
| --- | --- | --- |
| P1-1 | 订阅组位掩码补 `RTNLGRP_LINK`，三处表述统一 | §05.2、§02 架构图、§06.3 |
| P1-2 | `SO_RCVBUF` 改为"请求 1 MiB + `getsockopt` 读回 + 低于 256 KiB 告警" | §05.2、§10.2 日志示例 |
| P1-3 | §03 产物布局改为引用 §13.3（单一事实源），版本号改 `$(VERSION)` 变量 | §03、§12.2、§13.3 |
| P1-4 | `lock_file` 默认改为 `<RUNTIME_DIRECTORY>/<instance>.lock`；多实例说明与 systemd 参数化限制一并写清 | §04 `[core]`、附录 A.4、§16 未决 |
| P1-5 | 非 root 模式补完整权限矩阵（conf/token 均 `0640 root:miniddns`）+ drop-in 文件纳入骨架与 dist | §12.4、§02 骨架、§13.1 `install`、§13.3 |
| P1-6 | `log_file` 要求落在 `LogsDirectory=` 下；补 `README` 写"`RuntimeDirectory` 被 `ProtectSystem=strict` 豁免"的依据 | §04 `[core]`、§12.1、§14.3 |
| P1-7 | 补全保留前缀（`192.0.0.0/24`、`255.255.255.255/32`、`::ffff:0:0/96`、`64:ff9b::/96`、`fec0::/10`、`100::/64`）；IPv6 明确"必须在 `2000::/3` 且不在排除表内" | §06.1、§14.1 `ipv6_classify` |
| P1-8 | 重定向白名单定义为"`ipv4_echo_url` 中出现过的 host 集合"，限 https + 443 + 精确匹配 + 3 跳 | §06.2 强制 callout、§08.3、§06.2 表 |
| P1-9 | `[record]` 唯一性改为**跨全文全局**，报错给两处行号 | §04 语法规则、§14.1 `cfg` |
| P1-10 | 统一为 `E_HTTP_STATUS` + `http_status=NNN` + `reason=`；附录给数值 | §05.5、§08.4、附录 A.3 |
| P1-11 | 补定义 `struct mn_provider`、`struct mn_cfg`、`MN_IP_STRLEN` 等常量；删除 `changed_by_us`；说明空 id 语义 | §07.1、附录 A.0 |
| P1-12 | 补 BearSSL 精确 API（`br_pem_decoder_setdest`/`_event`、`br_x509_decoder_get_dn`）、DN 的 raw 编码要求、`append_dn` 分块、**两段式 arena**（防 realloc 悬空） | §09.1、§09.2、§09.3 |
| P1-13 | 诊断命令遇 `$CREDENTIALS_DIRECTORY` 缺失降级为 warn；`--check-ca` 补无配置/退出码行为 | §04 `[provider]`、§09.6 |
| P1-14 | 单元头声明最低 systemd 248；`verify` 门禁限定目标版本 | §12.1、附录 A.5 |
| P1-15 | Makefile 重写：`CFLAGS` 汇总、`build/%.o` 模式规则 + `mkdir -p`、静态关 PIE、`test`/`test-asan`/`units`/`verify-units`/`ca-refresh`/`dist`/`clean` | §13.1、§13.3 |
| P1-16 | `--once` 取 flock，诊断命令不取；补并发用例 | §11 取 flock 列 + 说明、§05.7、§14.2 |
| P1-17 | "不做轮询"改写为"不做短周期轮询 + 低频只读兜底"；≤3 s 指标限定为"首个请求发出" | 关键约束速览、§01 目标/非目标、§05.3 |
| P1-18 | OpenWrt 补 `DEPENDS:=+ca-bundle`、`--check-ca` 时机、无 verify 门禁说明 | §12.6 |

### P2（12 项，全部已修）

| # | 处置 | 落地位置 |
| --- | --- | --- |
| P2-1 | 4 处 `&gt;`/`&lt;` 全部还原为 `>`/`<` | §06.3、§07.3、§09.5、§14.4 |
| P2-2 | "alert 依赖的 libustream" 改为明确表述（`libustream`/`libopenssl`） | §12.6、§13.4 |
| P2-3 | 新增 `README.md`、`LICENSE`、`THIRD_PARTY_NOTICES.md`、`CHANGELOG.md`、`.gitignore`；dist 增 `LICENSES/` 并加断言 | 仓库根、§13.1 `dist`、§13.3 |
| P2-4 | HTML 移入 `docs/archive/design-v1.1.html`，`docs/archive/README.md` 记录 sha256/大小/来源；表头声明 `design.md` 为唯一权威 | `docs/archive/`、§ 文档头 |
| P2-5 | 锚点改 `<a name="sN" id="sN">` 双写 | 全文 18 处 |
| P2-6 | 补日志值转义规则、单行长度上限、`api_msg` 截断与 `truncated=1`；jsmn 不解转义的说明 | §10.1、§07.3 |
| P2-7 | 补 CLI 退出码表、优先级/互斥规则、`-n` 隐含 `-1` | §11 |
| P2-8 | 测试清单补 8 类用例（debounce 硬上限、日志折叠、install 幂等、dist 断言、符号链接、chunked、退避 0、多记录部分失败） | §14.1、§14.2、§14.3、§14.4 |
| P2-9 | 前缀表统一为完整 CIDR 写法 | §06.1 |
| P2-10 | `systemd/miniddns.service` 明确定位为生成物，新增 `make units` / `make verify-units` CI 门禁 | §02 说明、§13.1 |
| P2-11 | 新增 §04.7「版本兼容与规格变更流程」（新增/删除 key、默认值变更、回写机制） | §04.7、`CHANGELOG.md` |
| P2-12 | 新增「阅读路径」表（评审/实现/打包运维/排障四种角色） | 文档头 |

### 未能 100% 消除、需要人工确认的两处

| 项 | 说明 |
| --- | --- |
| `LICENSE` 的著作权人 | 现填 `miniddns contributors`（未指定个人/组织）。如项目有明确归属方，需替换后再对外发布 |
| P2-2 原文措辞 | `docs/archive/design-v1.1.html` 该句已被修改为工程上正确的表述，但原文"alert 依赖"究竟是笔误还是抽取损坏，无法从快照确证；如后续能拿到源站原文，应回填一句溯源说明 |
