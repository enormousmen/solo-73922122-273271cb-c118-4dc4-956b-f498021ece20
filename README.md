# 交换机配置重载台（Flask · 双栈 HTTPS 竞速下发 · TLS 1.2 会话恢复演示）

值班员点击“重载配置”后，控制台通过**内置的本地双栈 HTTPS 样例设备**完成一次严格规则的竞速下发，并在网页展示设备回执、竞速时间线、三种判定、IPv4/IPv6 两路共用的重载计数，以及**每次实际采用的 TLS 握手方式（完整握手 / 会话恢复）**。

## 做成的功能

### TLS 1.2 会话恢复演示（维护窗口连续下发，默认关闭）

演示开关 `tls12_demo` **默认关闭**，关闭时 TLS 协议协商与握手流程与历史版本完全一致（实测默认协商为 TLS 1.3，不接触任何会话缓存）。开启后客户端与样例设备都限定 **TLS 1.2**，并启用按栈隔离的会话缓存（`app/session_store.py`）：

1. **每次尝试都新建 TCP 连接**，恢复只发生在 TLS 层；时间线每次都有 `tcp_connected` 事件。
2. **IPv4 / IPv6 各保留一份**会话，且只保存经现有内置 CA 与设备名 `switch-demo.local` 完整校验通过后产生的会话；两栈缓存互不覆盖。
3. **证书到期后停用**：`SessionStore.take()` 发还会话前检查证书 `notAfter` 与 OpenSSL 给出的 ticket 寿命，到期即摘除；同时实测验证 OpenSSL 对**过期证书即使携带有效 session 也会拒绝**（`CERTIFICATE_VERIFY_FAILED: certificate has expired`），双保险。
4. **值班员可在网页“忘记”指定入口的会话**（`POST /api/session/forget`，支持 `ipv4`/`ipv6`/`both`）。忘记会抬高该栈的“世代屏障”，使忘记时刻之前已发起、尚未结束的在途握手无法再把旧会话写回。
5. **服务端拒绝恢复**（每栈独立开关）：在该栈持久 `SSLContext` 上切换 `OP_NO_TICKET`。客户端携带缓存会话发起恢复被拒后，**在同一 TCP 连接上由 OpenSSL 自动退化为完整握手**，CA + 设备名校验通过才允许下发，并保存新会话（时间线事件 `session_resume_declined_full_handshake`）。
   - 实测的 OpenSSL 客观语义：拒绝期间不签发新票据，因此**关闭拒绝开关后的第一次连接仍是完整握手（重新签发票据），再下一次同栈连接才恢复**。这是 TLS 票据机制决定的，已在网页演示④与自测中如实体现。
6. **并发握手不排队等缓存**：缓存锁只保护字典的 O(1) 读写，任何 TLS/网络 I/O 都在锁外；12 个竞速实例并发、墙钟仅约 1.1s，无串行排队。
7. **旧握手晚到不能覆盖/清掉新会话**：每次握手发起前按栈领取单调递增的“世代号”；`save()` 拒绝更旧世代的写入，`invalidate()` 只允许清除本世代及更旧世代保存的条目。
8. 仅 **TLS 层失败**（`ssl.SSLError`，如证书过期/协议告警）才作废会话；TCP 层的 stall 超时/RST 以及协调方主动取消（winner 选出后释放另一路）**不会**作废已缓存会话。
9. Python 的 `SSLSession` 与创建它的 `SSLContext` 绑定，因此演示期间所有竞速共享一个进程级客户端 context（仅在演示开关翻转、协议版本集合改变时重建）；context 重建后旧会话因 context 身份不匹配而在取用处自动失效。

### 核心竞速规则（`app/race_client.py`）

1. **IPv6 优先**：先连接 `https://[::1]:8443/reload`。
2. **250ms 并行窗口**：从操作开始计时，IPv6 在 250ms 内没有通过 TLS 证书校验，立即在旁并行启动 IPv4（`https://127.0.0.1:8443/reload`）。
3. **提前失败立即切 IPv4**：IPv6 若在 250ms 内连接被拒/RST/证书校验失败，检测到终态后**立刻**启动 IPv4，不等满窗口。
4. **同一设备名校验两路证书**：两路 TLS 都以 `server_hostname="switch-demo.local"` 做 SNI 与 hostname 校验，信任同一张内置 CA；证书 SAN 含该设备名、`localhost`、`127.0.0.1`、`::1`。设备名不匹配时两路都会被拒（有自测覆盖）。
5. **最先通过者只发一次 POST**：证书校验通过后在同一把锁内原子选出唯一 winner，仅它在该连接上发送**一次** POST；另一路无论仍在握手还是已通过待选，都会被立即关闭释放。`parallel_delay=0` 的双路齐发用例连跑 15 次，计数始终为 1。
6. **整次操作 3 秒上限**：默认 `deadline=3.0s`，到点关闭所有残留 socket。
7. **未下发（`not_sent`）**：截止时 POST **尚未开始发送**（例如双路握手都卡住），标红“未下发”，设备计数不增加。
8. **结果未知（`unknown`）且不重发**：一旦 POST **已经开始发送**，之后任何断连/超时/回执不完整都判定为“结果未知”，**不会**换另一路重发；设备侧共用计数最多 +1，可据此核对设备是否其实已执行。
9. “是否已开始发送”与“截止/取消”在同一把锁下协调，消除“到点边界上误标状态”的竞态。会话恢复能力完全叠加在上述规则之上，不改变 250ms 窗口、3s 时限与一次 POST 的约定。

### 内置双栈样例设备（`app/device.py` + `app/state.py`）

- 同端口分别绑定 `::1`（AF_INET6）与 `127.0.0.1`（AF_INET），两个 `ThreadingHTTPServer` 独立线程服务，共用同一个 `DeviceState`。
- **每栈一个独立的持久 `SSLContext`**：`tls12_demo` 翻转时重建（协议版本集合改变），`reject_resume` 翻转时只在原 context 上切换 `OP_NO_TICKET`，普通故障模式（ok/stall/reset）切换与 TLS context 无关。
- `POST /reload`：在共用锁内递增**两路共用**的 `reload_count` 与分栈计数 `stack_count.{ipv6,ipv4}`，返回 JSON 回执（含新计数、实际服务栈、服务端视角的握手方式 `tls.handshake_kind/session_reused/tls_version`、request_id、时间）。
- 故障注入（可按栈分别设置）：
  - `ok`：正常 TLS + 回执；
  - `stall`：accept TCP 后**卡住 TLS 握手**（不回 ServerHello），用于演示“IPv6 握手卡住”；
  - `reset`：accept 后立即 RST，用于演示“IPv6 提前失败”。
- `disconnect_after_execute`：计数 +1（设备已执行）后不发完整回执、直接 RST 断连，用于演示“设备执行后断连 → 结果未知”。
- `GET /health` 设备栈探活。

### 网页控制台（`app/templates/index.html` + `app/static`）

- 大号**两路共用重载计数**，以及 IPv6/IPv4 分计数、运行时长、最近 30 条设备执行记录（新增“实际握手方式”列）。
- 重载按钮（执行中转圈并禁用）、三态结果横幅：
  - 绿色“已下发，收到设备回执”+ 格式化回执 JSON；
  - 红色“未下发”；
  - 橙色“结果未知”。
- winner 路径旁直接显示**实际握手方式（完整握手/会话恢复）与 TLS 版本**；另有总耗时、POST 是否已开始、逐毫秒**竞速时间线**（含 `full_handshake`、`session_resume_attempted`、`session_resumed`、`session_resume_declined_full_handshake`、`session_save_skipped_stale_generation`、`attempt_canceled` 等会话事件），以及每路证书 CN/SAN/校验名与错误明细。
- **TLS 1.2 会话恢复演示面板**：演示总开关、IPv6/IPv4 两张会话状态卡（TLS 版本、密码套件、是否有票据、票寿命、缓存年龄、证书剩余寿命、世代号）、每栈“忘记会话”按钮、每栈“拒绝恢复”复选框，以及四个一键演示序列：
  - ① 同栈恢复（连续两次 IPv6：完整 → 恢复）；
  - ② 换栈（IPv6 → IPv4 → IPv6，两栈各存各的会话）；
  - ③ 忘记会话后重新完整握手、再次重载恢复；
  - ④ 服务端拒绝恢复 → 同连接完整握手 → 关闭拒绝后重建票据 → 再次重载恢复。
- 演示控制面板：IPv6/IPv4 三态单选、执行后断连开关、五个一键场景按钮（双栈正常 / IPv6 卡住 / IPv6 提前失败 / 执行后断连 / 双路均不可用）、计数清零；状态每 2.5s 自动刷新。
- 纯原生 HTML/CSS/JS，无外部 CDN/字体，离线可用。

### 部署

- `Dockerfile`：`python:3.12-slim`，安装 Flask + cryptography，非 root 运行，带 healthcheck。
- `docker-compose.yml`：单服务 `reload-console`，映射 `http://localhost:8080`。
- Flask 值班台与样例设备在**同一容器网络命名空间**内经 `::1` / `127.0.0.1` 互访，因此**不需要**为 Docker daemon 开启 IPv6；只要容器内 lo 上有 `::1`（Docker 默认如此）即可。
- 证书在启动时用 `cryptography` 自动生成到 `/app/certs`（Dockerfile 已将该目录分配给非 root 用户；无需挂载卷）。想取出内置 CA 可执行 `docker compose cp reload-console:/app/certs/ca.pem ./ca.pem`。

## 目录结构

```
.
├── app/
│   ├── main.py           # 入口：生成证书 → 启动双栈设备 → 启动 Flask
│   ├── web.py            # Flask 工厂与 /api/* 路由（含 /api/session/forget）
│   ├── race_client.py    # 双栈竞速、250ms 窗口、3s 截止、三态判定、TLS 会话恢复
│   ├── session_store.py  # 按栈隔离的 TLS 会话缓存（世代守卫/到期停用/共享 SSLContext）
│   ├── device.py         # 双栈 HTTPS 样例设备、故障注入、按栈 OP_NO_TICKET 拒绝恢复
│   ├── state.py          # 两路共用计数/设置/历史/会话缓存（加锁）
│   ├── certutil.py       # 内置 CA 与 SAN 服务器证书生成
│   ├── templates/index.html
│   └── static/{style.css,app.js}
├── tests/test_selftest.py        # 原有竞速规则自测（11 个用例）
├── tests/test_session_resume.py  # TLS 会话恢复专项自测（16 个用例）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 启动方式

### Docker Compose（推荐交付方式）

```bash
docker compose up --build
# 打开 http://localhost:8080
```

停止：`docker compose down`（保留证书卷）；连证书卷一起清理：`docker compose down -v`。

### 本地直接运行（无需 Docker）

需要 Python 3.11+：

```bash
python3 -m pip install -r requirements.txt
python3 -m app.main
# http://127.0.0.1:8080
```

## 演示操作与预期现象

| 操作 | 预期结果 |
| --- | --- |
| 默认设置直接点“重载交换机配置” | 约几十 ms 内 **IPv6 证书通过并胜出**，不启动 IPv4；绿色成功，共用计数 +1（IPv6 分计数 +1） |
| 点场景“IPv6 握手卡住 → IPv4”再重载 | 时间线显示 `+250ms parallel_window_elapsed` 后启动 IPv4，IPv4 胜出并拿到回执；计数 +1（IPv4 +1，IPv6 +0） |
| 点场景“IPv6 提前失败 → 立即 IPv4” | `start_path` 的 reason 为 `ipv6_early_failure`，通常几十 ms 内即启动 IPv4，**早于 250ms** |
| 点场景“执行后断连 → 结果未知” | 橙色“结果未知”，`POST 已开始=是`，无回执；共用计数仍 +1，且等待后不出现第二次增加（无重发） |
| 点场景“双路均不可用 → 未下发（3s）” | 约 **3000ms** 后红色“未下发”，`POST 已开始=否`、无 winner，计数不变 |
| 任意时刻看顶部计数/底部记录表 | 两路共用同一 `reload_count`，并列出每次实际由哪一栈接收 |

HTTP 直调示例：

```bash
# 开启 TLS 1.2 会话恢复演示
curl -s -X POST localhost:8080/api/settings \
  -H 'Content-Type: application/json' -d '{"tls12_demo":true}'
# 连续两次下发：第一次 full，第二次 resumed
curl -s -X POST localhost:8080/api/reload -H 'Content-Type: application/json' -d '{}'
curl -s -X POST localhost:8080/api/reload -H 'Content-Type: application/json' -d '{}'
# 让 IPv6 服务端拒绝恢复
curl -s -X POST localhost:8080/api/settings \
  -H 'Content-Type: application/json' -d '{"ipv6_reject_resume":true}'
# 忘记指定入口的会话
curl -s -X POST localhost:8080/api/session/forget \
  -H 'Content-Type: application/json' -d '{"stack":"ipv6"}'
curl -s localhost:8080/api/state   # sessions 字段含两栈缓存详情
```

## 自测

自动化端到端测试会在临时目录生成证书、随机端口真实启动双栈 TLS 设备，共 **3 个测试类、27 个测试方法**（原有 11 个竞速用例 + 新增 16 个会话恢复用例）：

```bash
python3 -m unittest discover -s tests -v
```

最近一次实测结果（构建沙箱内，Python 3.11.2 / Flask 3.1.3 / cryptography 50.0.2 / OpenSSL 3.0.22）：

```
Ran 27 tests in 16.6s
OK
```

会话恢复专项（`tests/test_session_resume.py`）覆盖：

- 同栈连续重载第一次完整、第二次恢复，客户端与服务端视角一致；
- IPv4/IPv6 各存各的会话、互不覆盖，stall 切换后两栈缓存都在；
- 忘记会话后重新完整握手、再次重载恢复；
- 服务端拒绝恢复 → 同一连接完整握手；关闭拒绝后一次完整握手重建票据、再下一次恢复；
- 演示关闭时默认协商照旧（TLS 1.3）、不触碰缓存、时间线无会话事件；
- 每次尝试都新建 TCP；按栈拒绝恢复互不影响；TCP 层失败不作废缓存；
- 世代守卫：旧握手不能覆盖/清掉新会话、forget 屏障拦截在途握手、证书/ticket 到期停用、
  1600 次并发 `begin` 世代号全局唯一、6 线程持续 churn 缓存锁不卡死；
- 真实过期证书即使携带有效 session 也被 OpenSSL 拒绝。

此外已真实启动 `python -m app.main` 用 curl 验证全部 HTTP 场景，实测数据：

- 默认状态协商 TLS 1.3、`winner_handshake_kind=null`、缓存为空；
- 开启演示后第一次 `handshake=full/TLSv1.2`，第二次 `handshake=resumed/session_reused=true`；
- IPv6 stall → IPv4 full，两栈会话均 `present=true`；恢复后 IPv6 仍 `resumed`；
- 忘记 IPv6 → 下一次 full、再下一次 resumed；
- 拒绝恢复序列：full（declined）→ 关闭后 full（新票据）→ resumed，服务端历史逐条吻合；
- 双 stall 仍在 `elapsed_ms=3000` 判 `not_sent`、`post_started=false`，竞速规则无回归。

并发安全实测：12 个竞速实例（`parallel_delay=0`）共享同一 `SessionStore` 并发执行，墙钟约 1.1s，12 次全部 delivered、设备 `reload_count` 恰好 12（无重复 POST），最终两栈缓存世代号均为最高的 12。

前端用 jsdom 加载真实 `index.html` + `app.js` 并对接运行中的服务做了点击级回归：27 个被引用的元素 ID 与模板全部匹配；四个一键演示序列（同栈恢复/换栈/忘记/拒绝恢复）逐步断言握手方式与预期一致，会话面板、时间线、历史表、演示日志均正确渲染，**无任何 JS 报错**。`node --check app.js` 通过。

## 未完成项 / 已知限制（如实说明）

1. **本构建沙箱没有 docker / docker compose 可执行程序，也没有 `/var/run/docker.sock`**，因此 `docker compose up --build` 未能在交付前于本机实际跑过；已做的替代验证是：compose YAML 解析通过、Dockerfile 基于官方 `python:3.12-slim` 且依赖均有 manylinux wheel、同一 `python -m app.main` 入口在宿主机 Python 3.11 下端到端实测通过。Docker 构建/启动仍需在有 Docker 的环境执行一次确认。
2. “服务端拒绝恢复”基于 `OP_NO_TICKET`（RFC 5077 会话票据）。受 Python/OpenSSL 暴露的 API 限制，无法做到“拒绝本次恢复却仍在同一握手中签发可立即使用的新票据”；因此关闭拒绝开关后需要**一次**完整握手重建票据，下一次连接才能恢复。这是 OpenSSL 的客观行为，已在代码、测试与网页演示④中明确体现，而非缺陷掩盖。
3. 沙箱网络下载缓慢，未做成真实浏览器像素级截图核对；已用 jsdom 完成真实 DOM + 点击 + 接口的前端行为回归（无 JS 错误），外加 JS 语法检查与元素 ID 交叉核对。视觉排版未经过像素级确认。
4. Flask 使用自带开发服务器（`threaded=True`），面向单个值班员的演示/内网低频操作足够；未接 gunicorn，是为了保证“设备 + 控制台同进程、双栈端口与共用状态（含会话缓存）”只有一份。
5. 样例设备与 CA/服务器证书均为演示用途、自动生成，**不要**用于真实网络设备或生产环境；会话缓存只保存在进程内存中，进程重启即清空。
6. 3 秒总时限以协调线程的 20ms 轮询 + socket 关闭实现，实测判定时刻约在 3.00–3.02s；非硬实时。
