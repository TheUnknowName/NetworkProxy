# Windows 网络请求拦截与补丁转发工具开发方案

## 1. 文档目标

本文档用于规划一个运行在 Windows 平台上的本地网络代理工具，满足以下目标：

1. 拦截系统发出的网络请求。
2. 对请求数据进行补丁处理。
3. 将补丁后的请求发送给目标服务器。
4. 对服务器返回的数据进行补丁处理。
5. 将补丁后的响应返回给客户端程序。

开发约束：

- 开发语言：C++
- 开发环境：Visual Studio 2022
- 构建系统：CMake
- 目标平台：Windows 10/11 x64

建议将该工具定位为“本机授权流量调试与协议改写工具”，仅用于自己可控或已获授权的流量场景。

## 2. 核心结论

建议采用“三层架构”：

1. 底层流量拦截层：负责捕获系统 TCP/UDP 流量。
2. 传输层补丁层：负责对 TCP 流和 UDP 数据报进行通用字节级补丁与转发。
3. 协议适配层：负责对 HTTP/HTTPS 等已识别协议进行语义级补丁与转发。

推荐的整体实现方案如下：

- 流量拦截方案：WinDivert
- 传输层处理：Boost.Asio
- 协议层处理：Boost.Beast + OpenSSL
- 配置与规则：YAML + JSON
- 日志：spdlog
- 单元测试：GoogleTest

该组合适合 MVP 快速落地，能在 VS2022 和 CMake 环境中稳定构建，同时保留后续切换到 WFP 的扩展空间。

需要明确的一点是：

1. “覆盖所有应用程序网络通信”在工程上可以理解为覆盖所有出站 TCP/UDP 流量的捕获、转发和字节级 patch。
2. 但“对所有协议做语义级 patch”并不现实，因为未知私有协议、强加密协议、证书固定协议、QUIC、DTLS 等场景无法靠单一通用代理直接完成高层语义修改。
3. 因此本项目应设计成“通用 TCP/UDP 字节级 patch + 可插拔协议适配器”的架构，而不是只做 HTTP/HTTPS。

## 3. 需求拆解

### 3.1 功能需求

必须具备：

1. 在 Windows 上对指定范围内的网络流量进行拦截。
2. 支持 TCP 流量的捕获、重组、转发和字节级 patch。
3. 支持 UDP 数据报的捕获、转发和字节级 patch。
4. 支持 HTTP 请求头、URL、Query、Body 的修改。
5. 支持 HTTP 响应头、状态码、Body 的修改。
6. 支持对已识别协议进行语义级 patch，对未知协议至少支持字节级 patch。
7. 支持规则化配置，而不是将所有补丁逻辑硬编码。
8. 支持日志记录，能追踪原始请求、补丁结果、转发结果和错误。
9. 支持按进程、域名、端口、路径、协议进行过滤。
10. 支持启停控制和异常恢复。

建议首期支持：

1. TCP 字节流 patch
2. UDP 数据报 patch
3. HTTP/1.1
4. HTTPS 解密代理（MITM）
5. JSON Body 补丁
6. 文本替换和正则替换

建议二期支持：

1. WebSocket 透传或有限处理
2. 自定义 TCP 协议适配器
3. HTTP/2
4. 更复杂的脚本化补丁逻辑
5. GUI 管理界面
6. WFP 驱动级增强方案

### 3.2 非功能需求

1. 稳定性：代理服务异常时，能快速定位问题并安全退出。
2. 可观测性：日志完整，支持 debug/info/warn/error 分级。
3. 性能：在常见办公和开发场景下不明显拖慢网络访问。
4. 可维护性：模块解耦，补丁规则与核心逻辑分离。
5. 可扩展性：后续可增加新协议、新补丁类型、新过滤条件。

## 4. 技术路线建议

## 4.1 为什么不直接做“裸包修改”

如果直接在 IP/TCP/UDP 层改包：

1. 很难正确处理 HTTPS 加密内容。
2. 需要自己维护 TCP 重组、分片、校验和、乱序等复杂问题。
3. UDP 无连接、乱序、丢包和应用层重传语义需要单独考虑。
4. 对应用层协议语义修改极不友好。

因此，本项目更合理的路线是：

1. 使用底层组件捕获并重定向 TCP/UDP 流量。
2. 对未知协议先以传输层方式做通用转发和字节级 patch。
3. 对已识别协议再进入协议适配器做语义级 patch。

这才是实现“尽可能覆盖所有应用程序网络通信”的正确工程化路径。

## 4.2 首选实现：WinDivert + 本地 TCP/UDP 转发器 + 协议适配器

### 组件职责

1. WinDivert
   - 捕获满足条件的出站 TCP/UDP 流量。
   - 将目标流量重定向到本地处理引擎。
   - 可按进程、端口、协议等条件过滤。

2. 本地传输层核心
   - 接受被重定向的 TCP 流和 UDP 数据报。
   - 为 TCP 会话做连接管理、流重组、双向转发。
   - 为 UDP 会话做数据报路由、双向转发。
   - 对未知协议执行通用字节级 patch。

3. 协议适配器
   - 识别 HTTP/HTTPS 等协议。
   - 执行协议级请求补丁。
   - 执行协议级响应补丁。
   - 回退到通用字节级 patch 或透传。

4. 证书模块
   - 生成本地根证书。
   - 按域名签发动态叶子证书。
   - 将根证书导入 Windows 信任存储。

### 方案优点

1. 开发速度快。
2. 对 TCP/UDP 通用转发场景和 HTTP/HTTPS 场景都可操作。
3. 用户态实现为主，调试成本低于 WFP Callout Driver。
4. 适合先验证产品能力。

### 方案缺点

1. 对 QUIC/HTTP3、DTLS 等 UDP 加密协议支持较弱。
2. 对证书固定（certificate pinning）的应用可能无效。
3. 对未知二进制私有协议只能做到通用字节级 patch，不能保证语义级理解。
4. 某些系统流量或内核态流量不一定适合该模式。

## 4.3 关于“所有协议都能 patch”的实现边界

如果目标是“所有应用程序网络通信都能 patch”，需要把 patch 分成三个层级：

1. L3/L4 层 patch
   - 面向 IP/TCP/UDP 层。
   - 适合做地址、端口、方向、流量过滤和字节序列替换。
   - 不适合理解高层业务语义。

2. 通用传输层 patch
   - 对 TCP 流做双向字节流 patch。
   - 对 UDP 做单报文或会话级 patch。
   - 适用于未知私有协议，但只能做字节级改写。

3. 协议语义层 patch
   - 对 HTTP、HTTPS、WebSocket 等已识别协议做结构化修改。
   - 适合做 Header、JSON、状态码、字段级修改。

因此，正确的产品目标不是“任何协议都能自动理解并修改业务字段”，而是：

1. 对所有 TCP/UDP 流量提供统一捕获与转发能力。
2. 对所有 TCP/UDP 流量提供可配置的通用字节级 patch 能力。
3. 对已识别协议提供更强的语义级 patch 能力。

## 4.4 备选增强：WFP

当首期版本稳定后，可评估 Windows Filtering Platform：

1. 更贴近系统网络栈。
2. 过滤能力更强。
3. 更适合企业级长期方案。

但 WFP 尤其涉及内核态 Callout Driver 时，开发、签名、调试和部署复杂度明显更高，不建议作为首个版本的落地方案。

## 5. 总体架构设计

## 5.1 架构分层

建议采用如下逻辑分层：

1. Capture Layer
   - 负责 TCP/UDP 流量识别与重定向。

2. Session Layer
   - 管理 TCP 连接、UDP 会话、服务端连接和会话上下文。

3. Transport Patch Layer
   - 对 TCP 字节流和 UDP 数据报执行通用 patch。

4. Protocol Adapter Layer
   - 解析 HTTP/HTTPS 等已识别协议。

5. Patch Engine
   - 根据规则对请求、响应、字节流、数据报进行修改。

6. Forward Layer
   - 将请求或数据发送到服务器，并把结果返回给客户端。

7. Config and Control Layer
   - 加载规则、运行配置、黑白名单、监听端口。

8. Observability Layer
   - 日志、审计、性能统计、错误跟踪。

## 5.2 数据流

### HTTP 场景

1. 客户端发起 HTTP 请求。
2. 拦截层将连接导入本地代理。
3. 代理读取请求报文。
4. Patch Engine 修改请求头、路径、参数、Body。
5. 代理将修改后的请求发送到目标服务器。
6. 服务器返回响应。
7. Patch Engine 修改响应头、状态码、Body。
8. 代理将修改后的响应回传给客户端。

### HTTPS 场景

1. 客户端发起 TLS 连接。
2. 流量被导入本地代理。
3. 本地代理基于目标域名动态签发证书，与客户端建立 TLS。
4. 代理同时与真实服务器建立 TLS。
5. 代理在解密后的 HTTP 层处理请求与响应补丁。
6. 最终重新加密并发回客户端。

### 通用 TCP 场景

1. 客户端发起 TCP 连接。
2. 拦截层捕获连接并建立本地双向转发会话。
3. 客户端到服务端方向的数据先进入 TCP 流重组器。
4. Transport Patch Layer 对字节流执行匹配与 patch。
5. 如果命中已识别协议，则交给协议适配器做结构化 patch。
6. 修改后的数据发送到目标服务器。
7. 服务端返回数据后走相同流程，再返回客户端。

### 通用 UDP 场景

1. 客户端发送 UDP 数据报。
2. 拦截层捕获数据报并导入本地处理引擎。
3. Transport Patch Layer 按单报文或会话规则执行 patch。
4. 如果协议可识别，则进入协议适配器，否则按字节级规则处理。
5. 修改后的数据报发送到目标服务器。
6. 服务端返回数据报后执行相同流程，再返回客户端。

## 6. 模块设计

## 6.1 capture 模块

职责：

1. 初始化 WinDivert 过滤规则。
2. 捕获目标流量。
3. 执行重定向或交给本地代理。
4. 排除代理进程自身流量，避免回环。

输入：

- 系统出站网络流量

输出：

- 导入本地代理的连接或数据包

关键点：

1. 必须避免代理自身请求再次被代理。
2. 必须支持按进程名、PID、端口、域名、协议过滤。
3. 首期建议优先拦截 TCP 80/443。

## 6.2 proxy_core 模块

职责：

1. 管理监听端口。
2. 管理客户端连接生命周期。
3. 创建上游服务器连接。
4. 协调请求补丁和响应补丁流程。

建议类设计：

- ProxyServer
- ProxySession
- UpstreamConnection
- SessionContext

## 6.3 transport_patch 模块

职责：

1. 对 TCP 流量做流重组、方向识别和字节级 patch。
2. 对 UDP 数据报做报文级 patch。
3. 支持按方向、偏移、长度、十六进制模式、文本模式做匹配。
4. 为协议适配器提供已重组的字节流视图。

建议能力：

1. TCP stream reassembly
2. UDP datagram patch
3. 字节序列查找替换
4. 正则或文本替换
5. 基于偏移的二进制 patch
6. 基于方向的规则过滤

## 6.4 protocol_http 模块

职责：

1. 解析 HTTP/1.1 请求和响应。
2. 处理分块传输、Content-Length、压缩编码等。
3. 标准化报文数据结构，供补丁引擎处理。

建议数据结构：

- HttpRequestModel
- HttpResponseModel
- HeaderMap
- BodyBuffer

## 6.5 tls_mitm 模块

职责：

1. 创建本地 CA 根证书。
2. 动态为目标域名签发证书。
3. 管理客户端 TLS 和服务端 TLS 双向会话。

关键点：

1. 首期建议使用 OpenSSL。
2. 根证书导入建议做成单独命令或安装步骤。
3. 必须明确区分开发证书与生产使用证书。

## 6.6 patch_engine 模块

职责：

1. 将规则应用到请求。
2. 将规则应用到响应。
3. 支持不同类型的补丁策略。

建议支持的补丁类型：

1. Header 增删改
2. URL 路径改写
3. Query 参数增删改
4. JSON 字段增删改
5. 文本替换
6. 正则替换
7. 二进制字节序列替换
8. 十六进制模式匹配与替换
9. 状态码改写

规则执行顺序建议：

1. 过滤匹配
2. 协议识别
3. TCP/UDP 通用字节级规则
4. 请求头规则
5. URL 和 Query 规则
6. Body 规则
7. 转发
8. 响应头规则
9. 响应 Body 规则

## 6.7 rule_config 模块

职责：

1. 从 YAML 文件加载规则。
2. 校验规则合法性。
3. 支持热重载或重启加载。

建议配置格式：YAML

示例：

```yaml
listen:
  host: 127.0.0.1
  port: 18080

capture:
   include_protocols: [tcp, udp]
   include_ports: [80, 443, 5000, 7000]
  exclude_processes: ["NetworkProxy.exe"]

rules:
   - name: tcp-byte-patch-demo
      when:
         protocol: "tcp"
         remote_port: 7000
         direction: "outbound"
      transport:
         binary_replace:
            - find_hex: "01020304"
               replace_hex: "05060708"

   - name: udp-patch-demo
      when:
         protocol: "udp"
         remote_port: 5000
         direction: "outbound"
      transport:
         text_replace:
            - find: "ping"
               replace: "pong"

  - name: add-trace-id
    when:
         protocol: "tcp"
      host: "api.example.com"
      path_regex: "/v1/orders.*"
      method: "POST"
    request:
      headers:
        set:
          X-Trace-Id: "debug-123"
      json_patch:
        - op: add
          path: "/debug"
          value: true
    response:
      headers:
        set:
          X-Patched-By: "NetworkProxy"
      text_replace:
        - find: "old-value"
          replace: "new-value"
```

## 6.8 logging 模块

职责：

1. 记录会话生命周期。
2. 记录命中规则。
3. 记录请求与响应摘要。
4. 记录异常和性能指标。

日志建议内容：

1. 时间戳
2. 会话 ID
3. 客户端进程信息
4. 目标主机和端口
5. 目标协议和方向
6. 命中的规则名称
7. 修改前后摘要
8. 错误码和异常信息

## 7. 关键技术选型

## 7.1 推荐依赖库

1. Boost.Asio / Boost.Beast
   - 网络 IO、TCP/UDP 处理、HTTP 报文解析与生成。

2. OpenSSL
   - TLS、证书生成、MITM 支持。

3. nlohmann/json
   - JSON 解析与 JSON 补丁数据处理。

4. yaml-cpp
   - 规则配置加载。

5. spdlog
   - 高性能日志。

6. GoogleTest
   - 单元测试和集成测试。

7. WinDivert SDK
   - Windows 流量捕获和重定向。

8. 可选：Npcap
   - 用于调试抓包和对照验证，不作为主链路依赖。

## 7.2 不建议首期引入的内容

1. 复杂 GUI 框架
2. 内核驱动自研
3. HTTP/2 和 HTTP/3 全量支持
4. 全协议语义自动识别
5. 脚本引擎嵌入

首期目标应是先做一个稳定、可验证、可调试的命令行版本。

## 8. 建议项目结构

```text
NetworkProxy/
├─ CMakeLists.txt
├─ cmake/
│  ├─ dependencies.cmake
│  └─ warnings.cmake
├─ third_party/
├─ config/
│  ├─ proxy.yaml
│  └─ logging.yaml
├─ cert/
│  ├─ ca/
│  └─ cache/
├─ src/
│  ├─ main.cpp
│  ├─ app/
│  │  ├─ application.cpp
│  │  └─ application.h
│  ├─ capture/
│  │  ├─ win_divert_capture.cpp
│  │  └─ win_divert_capture.h
│  ├─ transport/
│  │  ├─ tcp_stream_session.cpp
│  │  ├─ tcp_stream_session.h
│  │  ├─ tcp_reassembly_buffer.cpp
│  │  ├─ tcp_reassembly_buffer.h
│  │  ├─ udp_datagram_session.cpp
│  │  └─ udp_datagram_session.h
│  ├─ proxy/
│  │  ├─ proxy_server.cpp
│  │  ├─ proxy_server.h
│  │  ├─ proxy_session.cpp
│  │  ├─ proxy_session.h
│  │  ├─ upstream_connection.cpp
│  │  └─ upstream_connection.h
│  ├─ protocol/
│  │  ├─ http_models.h
│  │  ├─ http_parser.cpp
│  │  ├─ http_parser.h
│  │  ├─ protocol_detector.cpp
│  │  └─ protocol_detector.h
│  ├─ tls/
│  │  ├─ certificate_manager.cpp
│  │  ├─ certificate_manager.h
│  │  ├─ tls_client.cpp
│  │  ├─ tls_server.cpp
│  │  └─ tls_context_builder.h
│  ├─ patch/
│  │  ├─ patch_engine.cpp
│  │  ├─ patch_engine.h
│  │  ├─ binary_patchers.cpp
│  │  ├─ binary_patchers.h
│  │  ├─ request_patchers.cpp
│  │  ├─ response_patchers.cpp
│  │  └─ rule_matcher.cpp
│  ├─ config/
│  │  ├─ config_loader.cpp
│  │  └─ config_loader.h
│  ├─ logging/
│  │  ├─ logger.cpp
│  │  └─ logger.h
│  └─ common/
│     ├─ error.h
│     ├─ types.h
│     └─ utils.h
├─ tests/
│  ├─ patch_engine_tests.cpp
│  ├─ rule_matcher_tests.cpp
│  ├─ http_parser_tests.cpp
│  └─ integration_proxy_tests.cpp
└─ docs/
   ├─ architecture.md
   ├─ certificate_setup.md
   └─ operations.md
```

## 9. CMake 设计建议

建议最低版本：

- CMake 3.24+

建议项目配置：

1. 使用 target-based CMake。
2. 第三方库优先使用 find_package。
3. 对 WinDivert 可通过导入库或手工指定路径集成。
4. 区分 Debug/Release 输出目录。
5. 打开 MSVC 较严格告警级别。

建议编译选项：

1. C++20
2. /W4
3. /permissive-
4. /EHsc

建议初始 CMake 目标：

1. network_proxy_core
2. network_proxy_cli
3. network_proxy_tests

## 10. MVP 范围定义

为了控制风险，首个可交付版本建议限制为以下范围：

### MVP 必做

1. 支持 TCP 双向转发和字节级 patch。
2. 支持 UDP 双向转发和数据报级 patch。
3. 支持 HTTP/1.1 明文代理。
4. 支持固定规则的请求头和响应头修改。
5. 支持 JSON Body 的简单字段改写。
6. 支持配置文件加载。
7. 支持基础日志。
8. 支持命令行启动。

### MVP+ 建议

1. 加入 HTTPS MITM。
2. 增加按 Host/Path/Method 匹配。
3. 增加二进制模式匹配与替换。
4. 增加文本替换和正则替换。
5. 增加进程过滤。

### 二期再做

1. 自定义 TCP 协议适配器
2. HTTP/2
3. WebSocket 深度处理
4. GUI
5. WFP 增强
6. 热更新复杂规则系统

## 11. 风险与难点

## 11.1 HTTPS MITM 风险

风险：

1. 需要本地受信任根证书。
2. 某些应用存在证书固定，无法被中间代理。
3. 证书管理做不好会引入安全隐患。

应对：

1. 先完成 HTTP MVP，再引入 HTTPS。
2. 将证书安装、卸载、缓存独立成模块。
3. 明确只对授权流量启用。

## 11.2 未知协议语义风险

风险：

未知私有 TCP/UDP 协议即使能够捕获和转发，也未必能够做字段级 patch。

应对：

1. 默认提供字节级 patch 能力。
2. 将协议解析做成可插拔适配器。
3. 对无法识别的协议保持透传或只做有限 patch。

## 11.3 流量回环风险

风险：

代理自身访问服务器时，可能再次被拦截，形成死循环。

应对：

1. 将代理进程加入排除列表。
2. 必要时标记 socket 或使用本地回环豁免策略。

## 11.4 UDP 与 QUIC 风险

风险：

1. UDP 是无连接协议，天然缺少 TCP 那样稳定的会话边界。
2. QUIC/HTTP3 基于 UDP 且带有加密语义，不能按普通明文 UDP 处理。
3. 某些实时协议对时延和抖动非常敏感。

应对：

1. 将 UDP patch 设计为“报文级优先，会话级可选”。
2. 对 QUIC 优先做识别、过滤、旁路，不作为首期语义 patch 对象。
3. 对实时业务提供白名单与旁路策略。

## 11.5 内容编码风险

风险：

服务器响应可能使用 gzip、deflate、chunked 编码。

应对：

1. 先支持常见编码。
2. 对 Body 修改前先解压，修改后再重新编码。
3. 正确更新 Content-Length 或改用 chunked。

## 11.6 协议兼容性风险

风险：

不同客户端对代理、中间证书、连接复用行为差异较大。

应对：

1. 测试覆盖浏览器、桌面客户端、命令行工具。
2. 首期聚焦常见开发调试场景。

## 12. 测试方案

## 12.1 单元测试

重点覆盖：

1. 规则匹配逻辑
2. TCP 字节流 patch 逻辑
3. UDP 数据报 patch 逻辑
4. JSON Patch 应用逻辑
5. Header 改写逻辑
6. HTTP 报文解析和重组
7. 配置加载与校验

## 12.2 集成测试

测试场景：

1. 本地 mock server + 代理 + 测试客户端
2. TCP 自定义协议客户端与服务端之间的字节级 patch
3. UDP 客户端与服务端之间的数据报级 patch
4. 请求改写后服务端收到预期内容
5. 响应改写后客户端收到预期内容
6. 异常请求、超时、连接中断处理

## 12.3 人工验证

建议工具：

1. curl
2. 浏览器
3. Postman
4. 自定义测试程序

重点验证：

1. 普通 HTTP
2. 通用 TCP 字节流 patch
3. 通用 UDP 数据报 patch
4. HTTPS 证书安装后代理
5. JSON Body 修改
6. 大包体响应
7. 并发连接

## 13. 日志与运维建议

建议日志文件按天滚动，最少包含：

1. proxy.log
2. patch.log
3. error.log

建议运行参数：

1. --config
2. --listen
3. --log-level
4. --install-ca
5. --uninstall-ca
6. --dry-run

dry-run 模式建议只记录将要修改的内容，但不真正改写，便于规则调试。

## 14. 安全建议

1. 仅拦截自己授权的流量。
2. 根证书私钥必须妥善保存，不应硬编码到仓库。
3. 日志中涉及敏感字段时应支持脱敏。
4. 配置文件若包含 token、cookie 等内容，应支持加密存储或最少权限管理。
5. 默认不要捕获所有流量，应从白名单策略开始。

## 15. 开发阶段划分

## 阶段 1：项目初始化

输出：

1. CMake 工程框架
2. 依赖接入
3. 基础日志
4. 基础配置加载

## 阶段 2：HTTP 代理 MVP

输出：

1. 本地 HTTP 代理
2. 请求和响应头改写
3. JSON Body 改写
4. 单元测试

## 阶段 3：流量重定向

输出：

1. WinDivert 集成
2. 指定端口流量导入代理
3. 进程排除机制

## 阶段 4：HTTPS 支持

输出：

1. CA 证书管理
2. 动态证书签发
3. HTTPS 请求与响应补丁

## 阶段 5：增强与稳定化

输出：

1. 更多规则类型
2. 更完善日志
3. 性能优化
4. 长时间运行稳定性测试

## 16. 人力与周期预估

如果由 1 名有 C++ 网络开发经验的工程师执行：

1. 项目骨架和 HTTP MVP：2 到 3 周
2. WinDivert 集成：1 到 2 周
3. HTTPS MITM：2 到 4 周
4. 测试和稳定化：1 到 2 周

总计建议预估：6 到 11 周

如果对 TLS、Windows 流量重定向、证书链处理经验不足，周期还会增加。

## 17. 最终建议

最合理的落地顺序不是“一上来做全系统所有协议的语义级改包”，而是：

1. 先做命令行 TCP/UDP 转发与通用字节级 patch MVP。
2. 再加入 HTTP 明文协议适配器。
3. 再加入规则引擎和 JSON/Text/Binary 补丁。
4. 再接入 WinDivert 做系统流量导入。
5. 最后补 HTTPS MITM 与证书管理。

这样做的原因是：

1. 风险最小。
2. 每一步都可验证。
3. 能先满足“所有 TCP/UDP 流量都可 patch”的基础目标。
4. 出问题时更容易定位是在拦截层、传输层、协议层还是补丁层。

## 18. 交付物建议

建议项目最终至少包含以下交付物：

1. 可执行程序
2. CMake 工程文件
3. 默认配置样例
4. 证书安装说明
5. 架构文档
6. 测试用例
7. 运维手册

## 19. 下一步建议

如果要继续推进实现，建议下一步直接产出以下内容：

1. TCP/UDP 转发主流程代码
2. 通用二进制 patch 规则结构
3. 协议检测器接口
4. HTTP 适配器接口
5. WinDivert 流量导入模块
