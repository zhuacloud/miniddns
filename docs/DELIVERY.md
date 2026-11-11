# miniddns 实现与验收报告（v1.2.0）

> 依据：`docs/design.md` v1.2（+ 1.2.1 实现回写）· 状态：**已实现并通过全部可执行的验收门禁**

## 1. 交付范围

| 里程碑 | 交付物 | 状态 |
| --- | --- | --- |
| M0 | `src/{miniddns.h,cfg.c,log.c,util.c,sched.c,main.c}`、Makefile、`--check-config` | 完成 |
| M1 | `src/{ca.c,tls_http.c}`、BearSSL 0.6 vendor、`--check-ca` | 完成（真实 `api.cloudflare.com` 握手 OK） |
| M2 | `src/{nl_addr.c,detect.c}`、`--print-ip` | 完成（真实 rtnetlink dump + external echo OK） |
| M3 | `src/{json_util.c,provider.c,prov_cloudflare.c}`、`--once` / `--dry-run` | 完成（零写入不变量有集成断言） |
| M4 | 事件循环、debounce 滑窗 + 15 s 硬上限、兜底 timerfd、退避（含 `interval_fallback=0`）、时钟守卫、flock、signalfd | 完成 |
| M5 | systemd 单元/模板/drop-in、OpenWrt procd、`install.sh`、`make dist`、CA 快照、LICENSES | 完成 |

第三方组件以源码 vendor：`third_party/bearssl/`（0.6，MIT）、`third_party/jsmn/`（MIT）；许可文本随 `make dist` 进入 `LICENSES/`。

## 2. 关键实现决策与规格回写（§04.7）

实现中发现 BearSSL 0.6 的 API 与 v1.2 正文不一致，按 §04.7 以实际行为回写规格正文并追加修订记录 1.2.1：

1. 不存在 `br_x509_minimal_set_trust_anchors()`；`br_ssl_client_init_full(&sc,&xc,anchors,n)` 内部已调用 `br_x509_minimal_init()` 设置信任锚。
2. `br_x509_minimal_set_time()` 的 `days` 是**自 0000-01-01 起**的天数，不是 Unix 天数：`days = time(NULL)/86400 + 719528`（系数取自 `src/x509/x509_minimal.t0`）。用 Unix 天数会让每张证书被判为过期。
3. 不存在 `br_x509_decoder_get_dn()`；`br_x509_trust_anchor.dn` 是 DER 编码的 X.500 name 字节串，唯一来源是 `br_x509_decoder_init()` 注册的 `append_dn` 回调（会被多次调用）。

其余语义（零写入、PATCH 只带 content、fail closed、分级符号链接策略等）未偏离规格。

## 3. 自测结果

在本机（Debian 13, gcc 14, 非 root 开发用户）执行：

| 门禁 | 命令 | 结果 |
| --- | --- | --- |
| 编译零警告 | `make -j8` | 0 warning（`-Wall -Wextra` 作用于项目代码；vendor 用 `-w`） |
| 单元测试 | `make test` → `tests/build/unit` | **161 checks, 0 failures** |
| 集成测试 | `make test` → `tests/integration.py` | **23 checks, 0 failures** |
| ASan/UBSan | `make test-asan` | 161 checks, 0 failures，无 sanitizer 报告 |
| valgrind | `--once` / `--check-ca` | `All heap blocks were freed`，0 errors |
| 规格自洽 | `make spec-check` | OK（默认值/交叉引用/符号/安装路径） |
| 单元模板一致性 | `make verify-units` | OK |
| 单元文件 | `systemd-analyze verify` | 无 error（安装到临时前缀后验证） |
| 真实 TLS | `miniddns --check-ca --allow-non-root-owner` | 4 个端点全部 `OK tls=1.2`，CA 148 锚点 |
| 真实探测 | `miniddns --print-ip --allow-non-root-owner` | 输出公网 IPv4（external echo），IPv6 按规则过滤 |
| 静态产物 | `make static STATIC_CC=<musl-gcc>` | 350 160 B，`ldd` = not a dynamic executable |
| 打包 | `make dist` | 断言通过；16 个 `SHA256SUMS` 全部校验一致 |
| install.sh | 临时前缀安装两次 | 幂等；未生成 `miniddns.conf` / token；未调用 enable --now |

集成测试使用自签名 TLS mock + `LD_PRELOAD` 重定向（`tests/redirect.c`），覆盖：信任/不信任 CA、主机名不匹配、`--check-ca` 零请求字节、零写入、PATCH body 仅 `content`、POST create、`--dry-run` 的 `would-update`、`success=false` 的 `api_code`、429 `Retry-After`、chunked、多记录部分失败 `ok=1 fail=1`、私有 IP 不发 provider、flock 竞争、token 符号链接拒绝、时钟守卫。

资源实测（musl 静态二进制，idle 5.5 s，`interval_fallback=0`）：

| 指标 | 实测 | 门禁 |
| --- | --- | --- |
| 静态二进制 | 350 160 B | ≤ 500 KB ✅ |
| 常驻 RSS | 468 KB | ≤ 2.5 MB ✅ |
| 峰值 VmHWM | 664 KB | ≤ 6 MB ✅ |
| idle CPU（5.5 s） | 1 tick（10 ms） | 无轮转 ✅ |
| SIGTERM | `exit=0`，`stop signal=15` | 干净退出 ✅ |

## 4. 目录与产物

- 源码：`src/*.c` / `src/*.h`；vendor：`third_party/`。
- 打包资产：`conf/miniddns.conf.example`、`systemd/`、`openwrt/`、`install.sh`、`ca/`（`make ca-refresh` 生成）、`doc/`（`make doc` 生成）。
- 发布产物：`dist/miniddns-1.2.0-x86_64-musl/`（含 `bin/`、`conf/`、`ca/`、`systemd/`、`openwrt/`、`doc/`、`LICENSES/`、`install.sh`、`SHA256SUMS`、`THIRD_PARTY_NOTICES.md`）。

## 5. 已知限制 / 未执行的验收

- **24 h soak（§14.4）未执行**：需要 systemd 环境与真实/mock provider 连续运行一天；本次交付以 5.5 s idle 采样 + 每 cycle 一行 discover / 零写入的集成断言替代，24 h 累计 CPU ≤ 2 s 与 `MemoryPeak` 需在目标设备上复测。
- **静态产物体积依赖 musl**：`make static` 在只有 glibc 的机器上会构建出约 1.2 MB 的静态二进制并打印 WARN；≤500 KB 的预算按规格针对 musl/OpenWrt SDK（用 `STATIC_CC=<musl-gcc>` 或 OpenWrt 工具链覆盖 `CC`）。
- **glibc 静态链接的 getaddrinfo** 会提示运行时可能需要同版本 glibc 的 NSS 共享库；musl 目标无此问题。
- **TLS 1.3 / HTTP 代理 / HTTP2 / 客户端证书 / AIA** 按 §01 明确不做；provider v1 仅 Cloudflare。
- **netlink ENOBUFS 分支** 通过代码路径与 `mn_nl_drain` 的 `*overflow` 处理实现，本机无法直接注入队列溢出；该分支未做故障注入实测。
- **`doc/design.html`** 为可选项：构建机无 pandoc 时跳过，`dist` 只携带 `doc/design.md`。
- `--check-config` / `--print-ip` / `--check-ca` 在开发机上若文件属主非 root，需要 `--allow-non-root-owner`（仅测试用，会打 warn）；生产环境按 §03/A.4 使用 root 属主、0644/0640/0600 权限。

## 6. 复现

```bash
make                              # 动态构建
make test                         # 单元 + 集成
make test-asan                    # ASan/UBSan
make spec-check && make verify-units
make static STATIC_CC=/path/to/musl-gcc   # 静态产物
make dist STATIC_CC=/path/to/musl-gcc     # 发布产物
```
