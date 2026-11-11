# Changelog

本文件记录 **规格**（`docs/design.md`）与**代码**的变更。规格变更单独成节，因为 §04 规定"未知 key = 硬错误"，任何新增/删除配置项都是破坏性变更。

格式参照 Keep a Changelog；版本号遵循语义化版本的思路：破坏性规格变更 → minor+（v1.x），澄清/勘误 → patch。

---

## [Unreleased]

### Added

- Automated release pipeline: tag creation, CI/CD build, generated changelog and GitHub Release publishing, for stable (`X.Y.Z`) and release-candidate (`X.Y.Z-rcN`) versions. See `docs/RELEASE_PROCESS.md`.
- Release artifacts now explicitly bundle the static binary, configuration examples, the install script and systemd/OpenWrt service configuration examples; the manifest is verified by `scripts/verify_release_artifacts.py`.
- Multi-platform packaging: eight Linux tarballs (x86/x64/arm32/arm64 × musl/glibc) built with Zig cross compilation; musl builds are static, glibc builds are dynamic. See `docs/RELEASE_PROCESS.md`.
- Each tarball is now a self-contained install prefix (`README.md`, `bin/`, `conf/`, `examples/`, `install.sh`, `systemd/`, `openwrt/`, `ca/`, `doc/`, `LICENSES/`, `SHA256SUMS`). Only tarballs and the aggregate `SHA256SUMS` are published as release assets; installation and configuration files are no longer uploaded loose.

<!-- generated-release-sections -->

## [0.0.1-rc1] - 2026-11-11

### Added

- feat: implement miniddns v1.2.0, an event-driven DDNS daemon (7185655)

### Fixed

- fix(ci): keep release tarballs outside the build directory (bacf8b8)
- fix(ci): expose kernel UAPI headers for musl static builds (8c207e0)

### Internal

- build: package eight Linux variants as self-contained tarballs (34521be)
- chore(release): update changelog for 0.0.1-rc1 (a73b90e)
- ci: add automated release pipeline and enforce the release artifact manifest (4ded7c5)


## [1.2.0] — 2026-11

### 代码（首次实现，M0–M5 全部完成）

- 按 `docs/design.md` v1.2 实现全部模块：`cfg/log/util/sched`（严格 INI、`<PRI>` 日志、文件权限分级校验）、`ca/tls_http`（BearSSL 0.6 + 两段式 arena + mtime 重载 + chunked/错误分类）、`nl_addr/detect`（rtnetlink 边沿触发、全量 dump、地址分类与确定性选择）、`json_util/provider/prov_cloudflare`（只发 `content` 的 PATCH、创建时带 ttl/proxied）、`main`（ppoll 事件循环、debounce/兜底 timer/退避/时钟守卫/flock/signalfd、全部 CLI）。
- 零写入不变量：每个 cycle 必做 discover；`action=unchanged|skip` 不产生写请求；write memo 仅抑制刚写成功的同一 IP。
- 打包：`systemd/miniddns.service{.in}` + 非 root drop-in、OpenWrt procd、`install.sh`（不装 `miniddns.conf`/token、不自动 enable）、`make units/verify-units/ca-refresh/dist`、`LICENSES/`、`SHA256SUMS`。
- 测试：`make test`（161 项单元 + 23 项 TLS mock 集成）、`make test-asan`（ASan/UBSan 全绿）、`make spec-check`、`make verify-units`、`systemd-analyze verify`、valgrind `--once`/`--check-ca` 零泄漏。
- 资源：musl 静态产物 350 160 B（≤500 KB），idle 常驻 RSS 468 KB / 峰值 664 KB（≤2.5/6 MB），5.5 s idle CPU 1 tick；24 h soak 未在本次交付中执行，见 `docs/DELIVERY.md`。

- Repository policy added: **all interactions with GitHub MUST be in English**, and `README.md` MUST be in English. The rule and its scope are defined in `CONTRIBUTING.md` and enforced by `make spec-check`; `README.md` was translated accordingly.

### 规格

- 1.2.1 实现回写：按 BearSSL 0.6 实际 API 修正 §08.1（调用顺序/信任锚/时间换算偏移 `719528`）、§09.1/§09.2（DN 来自 `append_dn` 回调，DER 字节串）、附录 A.5；无功能语义变更。
- 新增 `docs/DELIVERY.md`（实现与验收报告）、`CONTRIBUTING.md`（仓库语言规范）。

---

## [spec 1.2] — 2025-11

依 `docs/review-design-v1.1.md` 全量修订 40 项（P0×10 / P1×18 / P2×12）。**本节全部是规格变更，无代码变更。**

### 破坏性变更（实现者必须按新规格写，不得兼容旧版）

| 变更 | 原因 |
| --- | --- |
| **删除 `[record].record_id` 配置项** | 跳过 discover 就无法得知远端 content，与"IP 不变零写入"不变量互斥；旧伪代码还会误走 create 分支（P0-1） |
| **新增 `[core].write_memo_ms`（默认 60000）** | 用进程内"刚写成功"备忘，抑制 Cloudflare `GET` 秒级缓存导致的重复 PATCH；替代已被删除的 `record_id` 优化路径 |
| **`[detect].ipv6_mode` 默认值改为 `iface`，枚举去掉 `auto`** | 原默认值 `auto` 不在允许集合内，会拒绝自己的默认值，导致默认启动失败（P0-2） |
| **`[core].lock_file` 默认路径改为 `<RUNTIME_DIRECTORY>/<instance>.lock`** | 原路径不含实例名，与"`instance` 支持多实例"矛盾，第二个实例必然 flock 失败（P1-4） |
| **`[core].log_file` 默认改为 `$LOGS_DIRECTORY/miniddns.log`，且要求位于 `LogsDirectory=` 下** | `ProtectSystem=strict` 下任意路径不可写（P1-6） |
| **日志行格式改为 `<PRI>miniddns: <message> level=<lvl> ...`** | journald 不识别单词级别的 `info`/`error`，全部落成 PRIORITY=6（P0-7，已实测） |
| **错误码 `E_HTTP_4XX` 统一为 `E_HTTP_STATUS` + `http_status=` 字段** | §05.5 与 §08.4/附录 A.3 三处命名不一致（P1-10） |
| **必须实现最小 `Transfer-Encoding: chunked` 解码** | 原"无 Content-Length 则读到 EOF"会把块长度行吃进 body，产生必然的 `E_PARSE`（P0-10） |

### 修正的错误规格

- `[record]` 唯一性从"同一 section 内"改为"跨全文全局"（P1-9）
- 退避定时器 `min(backoff, interval_fallback)` 在 `interval_fallback=0` 时会让失败重试永久失效（P0-6）
- netlink 订阅组补上 `RTNLGRP_LINK`；接口名改由 `if_indextoname()` 取得（`IFA_LABEL` 仅 IPv4 存在）（P1-1、P0-8）
- 候选地址必须排除 `IFF_UP` 为假的接口（内核在 link down 后仍保留地址）（P0-9）
- `SO_RCVBUF` 1 MiB 在无 `CAP_NET_ADMIN` 时被 `net.core.rmem_max` 钳制，补读回校验（P1-2）
- `§08.2` 请求模板的 `POST` 改为 `PATCH`（P0-5）

### 补齐的规格缺口

- 符号链接策略分级：token 禁跟随、conf 允许但校验目标、CA 必须允许（否则 RHEL/Alpine 无法启动）（P0-4）
- `LoadCredential=` 改为可选，不再强制单 provider 单文件（P0-3）
- 定义 `struct mn_provider`、`struct mn_cfg`、`MN_IP_STRLEN` 等此前从未定义的核心类型与常量（P1-11）
- 补 BearSSL DN 的原始编码要求、`append_dn` 分块语义、arena 两段式布局（P1-12）
- `--once` 必须取 flock；`--dry-run` 隐含 `--once`；补齐 CLI 退出码与优先级（P1-16、P2-7）
- 补 `[detect]` 重定向白名单定义与端口限制（P1-8）
- 补地址前缀表遗漏项（`192.0.0.0/24`、`255.255.255.255/32`、`::ffff:0:0/96`、`64:ff9b::/96`、`fec0::/10`、`100::/64`）（P1-7）
- Makefile 补 `CFLAGS`、`build/%.o` 规则、`mkdir -p`、`-fno-pie` 静态链接，以及 `test`/`test-asan`/`ca-refresh`/`units`/`verify-units`/`dist` 目标（P1-15）
- systemd 最低版本声明（≥ 248）与非 root 模式的完整权限矩阵（P1-5、P1-14）
- OpenWrt 补 `DEPENDS:=+ca-bundle` 与 `--check-ca` 时机（P1-18）
- 测试清单补 8 类缺失用例（debounce 硬上限、日志折叠、install 幂等、dist 断言、符号链接、chunked、退避 0、多记录部分失败）（P2-8）

### 文档工程

- 修 4 处 `&gt;` / `&lt;` HTML 实体残留（P2-1）
- HTML 原件移入 `docs/archive/design-v1.1.html`，记录 sha256 与来源，并声明 `design.md` 为唯一权威（P2-4）
- 目录锚点改为 `<a name>` + `<a id>` 双写，兼容更多渲染器（P2-5）
- 补日志值转义规则、`api_msg` 原样输出与截断规则（P2-6）
- 补规格变更流程与版本兼容策略（§04.7、P2-11）
- 补读者分层阅读路径（P2-12）
- 新增顶层文档：`README.md`、`LICENSE`、`THIRD_PARTY_NOTICES.md`、`CHANGELOG.md`、`.gitignore`（P2-3）
- dist 布局新增 `LICENSES/`，否则违反 BearSSL/jsmn 的 MIT 归属条款（P2-3）

---

## [spec 1.1]

- systemd 单元纳入源码与产物分发：新增 `systemd/miniddns.service.in` 模板与成品、`install.sh`、`make install`、OpenWrt procd 脚本、两种安装布局与可迁移性方案；dist 布局新增 `systemd/`、`openwrt/`、`install.sh` 与 `SHA256SUMS`。

## [spec 1.0]

- 初版：目标/架构/配置/运行时/IP 探测/provider 抽象/TLS+HTTP/CA/日志/CLI/systemd/构建/测试/里程碑/风险。
