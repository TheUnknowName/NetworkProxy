# Windows 全流量捕获与 Patch 工具开发方案

## 1. 文档目标

本文档定义本项目的重构目标：

1. 在 Windows 10/11 x64 上，覆盖系统全部网络流量捕获。
2. 对捕获流量执行统一规则化 patch。
3. 对可识别协议执行语义级 patch，对未知协议至少执行字节级 patch。
4. 在可观测、可回滚、可验证前提下持续运行。

开发约束：

1. 开发语言：C++20
2. IDE：Visual Studio 2022
3. 构建系统：CMake
4. 运行环境：Windows 10/11 x64

使用边界：

1. 仅用于授权流量调试、测试与安全研究。
2. 默认开启审计日志与最小化数据留存策略。

## 2. 需求重定义

原需求：可捕获 Windows 所有网络流量，进行 patch。

工程化定义：

1. 覆盖面目标：覆盖 IPv4 和 IPv6 的出入站主机流量。
2. 协议目标：覆盖 TCP 和 UDP 全量转发路径，支持 ICMP 元数据观测。
3. patch 目标：
   - TCP：流重组后双向 patch。
   - UDP：单报文与会话级 patch。
   - HTTP/HTTPS：结构化语义 patch。
   - 其他协议：通用字节级 patch。
4. 运行目标：不中断主机网络，失败可旁路。

验收口径：

1. 捕获成功率：目标流量类型可观测率大于等于 99%。
2. 转发成功率：启用 patch 后端到端成功率大于等于 99%。
3. 稳定性：连续 24 小时运行无崩溃。

## 3. 覆盖边界说明

为满足“所有网络流量”目标，需分层定义覆盖范围。

### 3.1 必须覆盖

1. IPv4 和 IPv6 出站 TCP。
2. IPv4 和 IPv6 入站 TCP。
3. IPv4 和 IPv6 出站 UDP。
4. IPv4 和 IPv6 入站 UDP。
5. 回环流量（127.0.0.1 和 ::1）。
6. 多网卡、多路由环境。

### 3.2 可观测但默认不深度改写

1. ICMP/ICMPv6：记录、过滤、统计。
2. QUIC/HTTP3：优先做识别、限流、阻断、旁路策略。
3. DTLS：优先做识别与转发。

### 3.3 明确限制

1. 证书固定应用可能无法执行 HTTPS 语义 patch。
2. 内核保护流量和部分安全产品自保护流量可能受限。
3. 某些系统服务可能需要白名单旁路以保证稳定。

## 4. 技术路线重构

采用双引擎捕获架构：

1. WFP 引擎（主链路，生产默认）
   - 负责全量流量捕获、重定向、分层过滤。
   - 提供更完整的 IPv4/IPv6 和入站/出站控制能力。
2. WinDivert 引擎（兼容链路，开发默认）
   - 作为快速验证与回归通道。
   - 用于无驱动安装场景的快速部署。

统一数据面：

1. Capture Adapter 层输出统一 FlowEvent。
2. Session Core 管理 TCP/UDP 会话。
3. Patch Engine 执行规则。
4. Forwarder 完成转发与回写。

## 5. 目标架构

## 5.1 分层架构

1. Capture Layer
   - WFP Adapter
   - WinDivert Adapter
   - Packet to Flow normalizer

2. Session Layer
   - TcpSessionManager
   - UdpSessionManager
   - LoopbackSessionBridge

3. Patch Layer
   - TransportPatchPipeline
   - ProtocolPatchPipeline
   - RuleEngine

4. Forward Layer
   - UpstreamConnector
   - ReturnPathRouter

5. Control Layer
   - ConfigLoader
   - RuntimeSwitch
   - SafeBypassController

6. Observability Layer
   - StructuredLogger
   - MetricsExporter
   - AuditWriter

## 5.2 统一上下文模型

每个会话都携带统一上下文：

1. flow_id
2. process_id
3. process_path
4. direction
5. src_ip/src_port
6. dst_ip/dst_port
7. protocol
8. tls_sni
9. app_protocol
10. rule_hits

## 6. 数据路径

### 6.1 TCP

1. 捕获 TCP 包并归并为会话。
2. 重组字节流。
3. 执行传输层 patch。
4. 如识别为 HTTP 或 HTTPS，执行语义 patch。
5. 转发至原始目标。
6. 响应方向执行同样流程。

### 6.2 UDP

1. 捕获 UDP 报文并映射到会话窗口。
2. 执行报文级 patch。
3. 命中协议适配器则执行语义 patch。
4. 转发至原始目标并回写客户端。

### 6.3 HTTPS

1. 捕获 CONNECT 或透明 TLS。
2. 按策略决定 MITM、透传或旁路。
3. MITM 模式下做解密后 HTTP 语义 patch。
4. 透传模式仅做元数据与传输层策略处理。

### 6.4 QUIC/HTTP3

1. 默认策略为识别与旁路。
2. 支持按 SNI、端口、进程做策略化处理。
3. 后续可扩展为限流和阻断，不承诺语义 patch。

## 7. Patch 能力模型

## 7.1 传输层 patch

1. 文本替换
2. 十六进制替换
3. 正则替换
4. 偏移写入
5. 分段重组后替换

## 7.2 协议语义 patch

1. HTTP Header 增删改
2. URL 和 Query 改写
3. JSON 字段改写
4. 状态码改写
5. 响应体文本替换

## 7.3 策略动作

1. allow
2. patch
3. bypass
4. drop
5. mirror

## 8. 规则系统重构

规则 DSL 目标：一套规则覆盖捕获、patch、旁路和阻断。

核心字段：

1. protocol
2. direction
3. process
4. host/sni
5. port
6. path/method
7. payload_pattern

动作字段：

1. transport.text_replace
2. transport.hex_replace
3. http.header_set
4. http.body_patch
5. control.bypass
6. control.drop

最小示例：

```yaml
rules:
  - name: global-tcp-text-patch
    when:
      protocol: tcp
      direction: outbound
    action:
      transport:
        text_replace:
          - find: hello
            replace: patched_hello

  - name: udp-hex-patch
    when:
      protocol: udp
      remote_port: 5000
    action:
      transport:
        hex_replace:
          - find_hex: "010203"
            replace_hex: "0A0B0C"

  - name: https-bypass-pinned-app
    when:
      process: pinned_app.exe
      protocol: tcp
      remote_port: 443
    action:
      control:
        bypass: true
```

## 9. 当前代码重构方向

当前代码已具备：

1. TCP/UDP 转发与 patch 主流程。
2. WinDivert 捕获原型。
3. HTTP 结构化 patch。
4. HTTPS MITM 基础能力。
5. DSL 规则执行链路。

需要重构的关键点：

1. 从固定上游模型改为原始目标透明转发模型。
2. 捕获层扩展到 IPv6、入站、回环。
3. 抽象 CaptureAdapter，接入 WFP 主链路。
4. 引入 FlowTable，支持高并发会话一致性。
5. 引入统一旁路机制，避免系统关键流量受影响。

## 10. 分阶段实施计划

## 阶段 A：全量捕获能力重构

输出：

1. CaptureAdapter 抽象接口。
2. WinDivert Adapter 改造为统一事件流。
3. IPv6 与入站捕获支持。
4. 回环流量策略支持。

验收：

1. IPv4/IPv6 TCP/UDP 入出站均可被观测。
2. 回环流量可按策略拦截或旁路。

## 阶段 B：透明转发与会话一致性

输出：

1. 按原始目标地址透明转发。
2. TcpSessionManager 与 UdpSessionManager 重构。
3. FlowTable 与会话清理策略。

验收：

1. 不依赖固定 upstream 配置。
2. 常见客户端流量端到端可达。

## 阶段 C：Patch 统一执行管线

输出：

1. 传输层和协议层统一执行顺序。
2. 规则冲突处理与优先级。
3. patch 审计日志与回放摘要。

验收：

1. 同一会话可稳定执行多条规则。
2. 命中规则与修改摘要可审计。

## 阶段 D：WFP 主链路接入

输出：

1. WFP 用户态服务。
2. 过滤器策略与优先级管理。
3. WinDivert 作为降级链路。

验收：

1. WFP 模式覆盖目标高于 WinDivert 模式。
2. 失败可自动降级到兼容链路。

## 阶段 E：稳定性与性能

输出：

1. 24h 稳定性测试。
2. 压测与性能基准。
3. 资源泄漏检查与优化。

验收：

1. 长稳测试通过。
2. CPU 和内存在目标范围内。

## 11. 测试与验收矩阵

## 11.1 协议维度

1. TCP 明文
2. UDP 明文
3. HTTP/1.1
4. HTTPS/TLS
5. QUIC 识别旁路
6. IPv6 TCP/UDP
7. Loopback TCP/UDP

## 11.2 行为维度

1. 仅捕获
2. 捕获加 patch
3. 捕获加旁路
4. 捕获加阻断
5. 异常回退

## 11.3 质量门禁

1. 单元测试
2. 集成测试
3. packet smoke tests
4. e2e 清洁验证
5. 长稳与压测

## 12. 运维与安全

1. 默认最小权限运行。
2. 证书安装与卸载提供独立命令。
3. 根私钥不入库，使用本地受控存储。
4. 日志支持敏感字段脱敏。
5. 关键系统进程默认旁路。

## 13. 交付物

1. 可执行程序与 CMake 工程。
2. 全流量捕获配置模板。
3. 规则 DSL 文档与示例。
4. 测试报告与验收矩阵。
5. 运维手册与故障排查手册。

## 14. 里程碑定义

1. M1：IPv4/IPv6 TCP/UDP 入出站可观测。
2. M2：透明转发替代固定 upstream。
3. M3：统一 patch 管线与规则审计。
4. M4：WFP 主链路可用，WinDivert 降级可用。
5. M5：稳定性、性能与安全验收完成。

## 15. 当前状态与下一步

当前状态：

1. 已具备 WinDivert 原型、TCP/UDP patch、HTTP patch、HTTPS MITM 和 DSL。
2. 已新增基于 WinDivert 映射表的透明目标回查转发（TCP/UDP 按客户端源端口回查原始目标，减少固定 upstream 依赖）。
3. 已补充 IPv6 传输寻址与 WinDivert IPv6 TCP/UDP 重写记录能力，默认过滤器切换为双向 IP TCP/UDP 捕获。
4. 已接入 WFP Capture 第一版真实数据面入口：WFP 引擎会话 + NetEvent 订阅，可实时接收系统网络事件并输出连接元数据。
5. 已实现运行时回退策略（优先 WFP，失败自动回退 WinDivert）。
6. 尚未达到“Windows 全流量透明捕获与 patch”最终目标（WFP 重定向数据面仍需 Callout 级实现，且仍需更完备的入站/回环策略验证）。

下一步优先级：

1. 先完成透明转发重构，去除固定上游依赖。
2. 扩展捕获到 IPv6、入站与回环。
3. 再接入 WFP 主链路，完成全量覆盖目标。

## 16. 一键执行入口

为支持“读取需求后一键执行到底”，已提供总控脚本：

1. tools/one_click_run.ps1

执行内容：

1. cmake 配置
2. Debug 构建
3. CTest 全链路执行（unit_tests、smoke_tests、packet_smoke_tests、e2e_validation）
4. E2E 独立复验
5. 生成汇总报告

执行命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\one_click_run.ps1
```

输出报告：

1. reports/packet_smoke_report.md
2. reports/e2e_validation_report.md
3. reports/one_click_summary.md
