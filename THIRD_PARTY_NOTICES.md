# 第三方组件与许可声明

miniddns 以源码形式 vendor 了两个第三方组件。两者均为 MIT 许可，其条款要求**在分发时保留版权声明与许可文本**，因此：

- 本文件必须随源码仓库分发；
- `make dist` 必须把本文件与 `third_party/*/LICENSE` 打进产物（见 design.md §13.3）；
- 不得删除 vendor 目录中的 `LICENSE`/`COPYRIGHT` 文件。

## BearSSL

| 项 | 值 |
| --- | --- |
| 用途 | TLS 1.2 客户端、X.509 证书链验证（`br_ssl_client` + `br_x509_minimal`） |
| 位置 | `third_party/bearssl/`（源码 vendor，不用 git submodule） |
| 上游 | https://www.bearssl.org/ |
| 版本 | 见 `third_party/bearssl/README.txt`（vendor 时固定 commit，勿跟随上游浮动） |
| 许可 | MIT |

BearSSL 的版权声明原文见 `third_party/bearssl/LICENSE.txt`，摘要：

```
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, ... (MIT 标准条款)
```

> 注意：BearSSL 上游自 2021 年后基本冻结。这是**有意的选择**（代码稳定、零 malloc、攻击面小），不是疏忽；
> 替换路径记录在 design.md §16（TLS 已隔离在 `tls_http.c` 内，可换 mbedTLS 而不改接口）。

## jsmn

| 项 | 值 |
| --- | --- |
| 用途 | 从 Cloudflare 响应中取 `result[0].id` / `errors[0].code` / `errors[0].message` |
| 位置 | `third_party/jsmn/jsmn.h`（单头文件） |
| 上游 | https://github.com/zserge/jsmn |
| 版本 | 见文件头注释 |
| 许可 | MIT |

```
Copyright (c) 2010 Serge A. Zaitsev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, ... (MIT 标准条款)
```

> jsmn 只做词法切分，**不解转义**。`json_util` 必须自己处理 `\uXXXX` / `\"` 等，
> 且所有取出的切片都指向原始响应缓冲，生命周期不得长于该缓冲（见 design.md §07.3）。

## 其他随产物分发的第三方内容

| 内容 | 许可 | 说明 |
| --- | --- | --- |
| CA 证书 bundle（`ca/ca-certificates.crt`） | 各 CA 自有的 CPS/RPA | 由 `make ca-refresh` 从发行版复制；`ca/README` 记录来源、快照时间与 sha256。分发时不做修改，不构成再许可 |

## 更新本文件的规则

- 新增 vendor 组件 → 必须在此登记许可、来源、版本、位置，并在 §13.3 的 dist 步骤中携带其 LICENSE；
- 升级 vendor 版本 → 同步更新此文件的版本字段；
- `make dist` 的断言应能让"忘了带 LICENSE"的打包失败（见 design.md §13.3 第 6 步）。
